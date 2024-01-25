package rpc

import (
	"bytes"
	"log"
	"strings"

	"github.com/vishvananda/netlink"
	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	rpcebpf "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/rpc/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	ch           chan rpcebpf.Metric
	kprobeHelper kprobe.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.ch = make(chan rpcebpf.Metric, 100)
	links, err := netlink.LinkList()
	if err != nil {
		panic(err)
	}
	eBPFprogram := rpcebpf.GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		panic(err)
	}
	for _, link := range links {
		// TODO: filter veth for pods
		if !strings.HasPrefix(link.Attrs().Name, "veth") {
			continue
		}
		go func(l netlink.Link) {
			proj := rpcebpf.NewEbpf(l.Attrs().Index, p.ch)
			if err := proj.Load(spec); err != nil {
				log.Fatalf("failed to load ebpf, err: %v", err)
			}
		}(link)
	}
	for {
		select {
		case m := <-p.ch:
			p.fillMetric(&m)
			klog.Infof("rpc metric: %+v", m)
		}
	}
}

func (p *provider) fillMetric(m *rpcebpf.Metric) {
	stat, err := p.kprobeHelper.GetSysctlStat(m.Pid)
	if err != nil {
		return
	}
	pod, err := p.kprobeHelper.GetPodByUID(strings.ReplaceAll(stat.PodUID, "_", "-"))
	if err != nil {
		klog.Errorf("failed to get pod by uid, err: %v", err)
		return
	}
	m.PodName = pod.Name
	m.NodeName = pod.Status.HostIP
	m.NameSpace = pod.Namespace
	m.ServiceName = pod.Labels["DICE_APPLICATION_NAME"]
}

func init() {
	servicehub.Register("rpc", &servicehub.Spec{
		Services:     []string{"rpc"},
		Description:  "ebpf for rpc",
		Dependencies: []string{"kprobe"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
