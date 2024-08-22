package kafka

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/netfilter"
	"github.com/erda-project/erda-infra/base/servicehub"
)

var (
	measurementGroup = "application_mq"
)

type provider struct {
	sync.RWMutex

	kprobeHelper kprobe.Interface
	netNatHelper netfilter.Interface
	ch           chan Event
	probes       map[int]*Ebpf
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.netNatHelper = ctx.Service("netfilter").(netfilter.Interface)
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
					klog.Errorf("failed to load ebpf, err: %v", err)
					p.Unlock()
					continue
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

func (p *provider) convert2Metric(ev Event) *metric.Metric {
	var (
		sourceIP = net.IP(ev.SourceIP[:]).String()
		destIP   = net.IP(ev.DestIP[:]).String()
	)
	m := &metric.Metric{
		Name:        measurementGroup,
		Measurement: measurementGroup,
		Tags: map[string]string{
			"metric_source": "ebpf",
			"_meta":         "true",
			"_metric_scope": "micro_service",
			"span_kind":     "kafka",
		},
		Fields: map[string]interface{}{
			"elapsed_count": ev.RecordCount,
			"elapsed_sum":   ev.RequestStarted,
			"elapsed_avg":   float64(ev.RequestStarted) / float64(ev.RecordCount),
			"elapsed_max":   ev.RequestStarted,
			"elapsed_min":   ev.RequestStarted,
			"elapsed_mean":  ev.RequestStarted,
			"record_count":  ev.RecordCount,
		},
		Timestamp: time.Now().UnixNano(),
	}
	m.Tags["topic_name"] = ev.TopicName
	m.Tags["request_api_key"] = fmt.Sprintf("%d", ev.RequestApiKey)
	m.Tags["request_api_version"] = fmt.Sprintf("%d", ev.RequestApiVersion)
	m.Tags["src_ip"] = sourceIP
	m.Tags["dst_ip"] = destIP
	m.Tags["src_port"] = fmt.Sprintf("%d", ev.SourcePort)
	m.Tags["dst_port"] = fmt.Sprintf("%d", ev.DestPort)
	m.Tags["component"] = "kafka"
	m.Tags["message_bus_destination"] = ev.TopicName
	m.Tags["message_bus_status"] = "CONSUME_SUCCESS"
	m.Tags["peer_address"] = fmt.Sprintf("%s:%d", destIP, ev.DestPort)

	sourcePod, err := p.kprobeHelper.GetPodByUID(sourceIP)
	if err != nil {
		klog.Errorf("get pod by ip error: %v", err)
	} else {
		m.OrgName = sourcePod.Labels["DICE_ORG_NAME"]
		m.Tags["_metric_scope_id"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
		m.Tags["source_application_id"] = sourcePod.Labels["DICE_APPLICATION_ID"]
		m.Tags["source_application_name"] = sourcePod.Labels["DICE_APPLICATION_NAME"]
		m.Tags["source_org_id"] = sourcePod.Labels["DICE_ORG_ID"]
		m.Tags["org_name"] = sourcePod.Labels["DICE_ORG_NAME"]
		m.Tags["source_project_id"] = sourcePod.Labels["DICE_PROJECT_ID"]
		m.Tags["source_project_name"] = sourcePod.Labels["DICE_PROJECT_NAME"]
		m.Tags["source_runtime_id"] = sourcePod.Labels["DICE_RUNTIME_ID"]
		m.Tags["source_runtime_name"] = sourcePod.Annotations["msp.erda.cloud/runtime_name"]
		//output.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s",
		//	sourcePod.Labels["DICE_APPLICATION_ID"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Labels["DICE_SERVICE_NAME"])
		//m.Tags["source_service_id"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		m.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Annotations["msp.erda.cloud/application_id"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Annotations["msp.erda.cloud/service_name"])
		m.Tags["source_service_instance_id"] = string(sourcePod.UID)
		m.Tags["source_service_name"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		m.Tags["source_terminus_key"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
		m.Tags["source_workspace"] = sourcePod.Annotations["msp.erda.cloud/workspace"]
		m.Tags["cluster_name"] = sourcePod.Labels["DICE_CLUSTER_NAME"]
	}

	var target any
	natInfo, exist := p.netNatHelper.GetNatInfo(sourceIP, ev.SourcePort)
	if exist {
		destIP = natInfo.ReplyDstIP
		ev.DestPort = natInfo.ReplyDstPort
	}
	pod, err := p.kprobeHelper.GetPodByUID(destIP)
	if err != nil {
		svc, err := p.kprobeHelper.GetService(destIP)
		if err == nil {
			target = svc
		}
	} else {
		target = pod
	}
	if target == nil {
		klog.Errorf("source: %s/%d, target(external): %s", sourceIP, ev.SourcePort, destIP)
		return nil
	}

	switch t := target.(type) {
	case corev1.Pod:
		klog.Infof("source: %s/%d, target(pod): %s/%s", sourceIP, ev.SourcePort, t.Namespace, t.Name)
		m.Tags["cluster_name"] = t.Labels["DICE_CLUSTER_NAME"]
		m.Tags["db_host"] = fmt.Sprintf("%s:%d", destIP, ev.DestPort)
		m.Tags["peer_hostname"] = t.Spec.Hostname

		// target platform metadata
		m.Tags["target_application_id"] = t.Labels["DICE_APPLICATION_ID"]
		m.Tags["target_application_name"] = t.Labels["DICE_APPLICATION_NAME"]
		m.Tags["target_org_id"] = t.Labels["DICE_ORG_ID"]
		m.Tags["target_project_id"] = t.Labels["DICE_PROJECT_ID"]
		m.Tags["target_project_name"] = t.Labels["DICE_PROJECT_NAME"]
		m.Tags["target_runtime_id"] = t.Labels["DICE_RUNTIME_ID"]
		m.Tags["target_runtime_name"] = t.Annotations["msp.erda.cloud/runtime_name"]
		//output.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s",
		//	t.Labels["DICE_APPLICATION_ID"], t.Annotations["msp.erda.cloud/runtime_name"], t.Labels["DICE_SERVICE_NAME"])
		//m.Tags["target_service_id"] = t.Annotations["msp.erda.cloud/service_name"]
		m.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", t.Annotations["msp.erda.cloud/application_id"], t.Annotations["msp.erda.cloud/runtime_name"], t.Annotations["msp.erda.cloud/service_name"])
		m.Tags["target_service_instance_id"] = string(t.UID)
		m.Tags["target_service_name"] = t.Annotations["msp.erda.cloud/service_name"]
		m.Tags["target_terminus_key"] = t.Annotations["msp.erda.cloud/terminus_key"]
		m.Tags["target_workspace"] = t.Annotations["msp.erda.cloud/workspace"]
	}
	return m

}

func (p *provider) sendMetrics(c chan *metric.Metric) {
	for {
		select {
		case m := <-p.ch:
			mc := p.convert2Metric(m)
			c <- mc
			//klog.Infof("kafka metric: %+v", mc)
		}
	}
}

func init() {
	servicehub.Register("kafka", &servicehub.Spec{
		Services:     []string{"kafka"},
		Description:  "ebpf for kafka",
		Dependencies: []string{"kprobe", "netfilter"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
