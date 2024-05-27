package kafka

import (
	"bytes"
	"fmt"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	sync.RWMutex

	kprobeHelper kprobe.Interface
	ch           chan Event
	probes       map[int]*Ebpf
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.ch = make(chan Event, 100)
	p.probes = make(map[int]*Ebpf)
	return nil
}

func (p *provider) Gather(c chan *metric.Metric) {
	ebpfProgram := GetEBPFProg()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProgram))
	if err != nil {
		panic(err)
	}

	vethes, err := p.kprobeHelper.GetVethes()
	if err != nil {
		panic(err)
	}
	for _, veth := range vethes {
		proj := NewEbpf(veth.Link.Attrs().Index, veth.Neigh.IP.String(), p.ch)
		if err := proj.Load(spec); err != nil {
			klog.Fatalf("failed to load ebpf, err: %v", err)
		}
		p.Lock()
		p.probes[veth.Link.Attrs().Index] = proj
		p.Unlock()
	}
	go p.sendMetrics(c)
	vethEvents := p.kprobeHelper.RegisterNetLinkListener()
	for {
		select {
		case event := <-vethEvents:
			switch event.Type {
			case kprobe.LinkAdd:
				klog.Infof("veth add, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
				p.Lock()
				if _, ok := p.probes[event.Link.Attrs().Index]; ok {
					p.Unlock()
					continue
				}
				proj := NewEbpf(event.Link.Attrs().Index, event.Neigh.IP.String(), p.ch)
				if err := proj.Load(spec); err != nil {
					klog.Fatalf("failed to load ebpf, err: %v", err)
				}
				p.probes[event.Link.Attrs().Index] = proj
				p.Unlock()
			case kprobe.LinkDelete:
				klog.Infof("veth delete, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
				p.Lock()
				_, ok := p.probes[event.Link.Attrs().Index]
				if ok {
					delete(p.probes, event.Link.Attrs().Index)
				}
				p.Unlock()
			default:
				klog.Infof("unknown event type: %v", event.Type)
			}
		}
	}
}

func (p *provider) convert2Metric(ev Event) metric.Metric {
	m := metric.Metric{
		Name:   "kafka",
		Tags:   map[string]string{},
		Fields: map[string]interface{}{},
	}
	m.Tags["topic_name"] = ev.TopicName
	m.Tags["request_api_key"] = fmt.Sprintf("%d", ev.RequestApiKey)
	m.Tags["request_api_version"] = fmt.Sprintf("%d", ev.RequestApiVersion)
	m.Tags["src_ip"] = net.IP(ev.SourceIP[:]).String()
	m.Tags["dst_ip"] = net.IP(ev.DestIP[:]).String()
	m.Tags["src_port"] = fmt.Sprintf("%d", ev.SourcePort)
	m.Tags["dst_port"] = fmt.Sprintf("%d", ev.DestPort)
	m.Fields["record_count"] = ev.RecordCount
	m.Fields["request_started"] = ev.RequestStarted
	return m

}

func (p *provider) sendMetrics(c chan *metric.Metric) {
	for {
		select {
		case m := <-p.ch:
			mc := p.convert2Metric(m)
			c <- &mc
			klog.Infof("kafka metric: %+v", mc)
		}
	}
}

func init() {
	servicehub.Register("kafka", &servicehub.Spec{
		Services:     []string{"kafka"},
		Description:  "ebpf for kafka",
		Dependencies: []string{"kprobe"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
