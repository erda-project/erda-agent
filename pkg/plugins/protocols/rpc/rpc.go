package rpc

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/erda-project/erda-agent/metric"
	"github.com/erda-project/erda-agent/pkg/plugins/kprobe"
	"github.com/erda-project/erda-agent/pkg/plugins/netfilter"
	rpcebpf "github.com/erda-project/erda-agent/pkg/plugins/protocols/rpc/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
	"k8s.io/klog/v2"
)

const (
	rpcMeasurementGroup      = "application_rpc"
	rpcErrorMeasurementGroup = rpcMeasurementGroup + "_error"
	dbMeasurementGroup       = "application_db"
	redisMeasurementGroup    = "application_cache"
	dbErrorMeasurementGroup  = dbMeasurementGroup + "_error"
)

var (
	pathRegexp = regexp.MustCompile(`(.*)!([a-zA-Z.]+)([0-9.]+)([a-zA-Z/;]+)`)
)

type provider struct {
	sync.RWMutex
	ch           chan rpcebpf.Metric
	kprobeHelper kprobe.Interface
	netNatHelper netfilter.Interface
	rpcProbes    map[int]*rpcebpf.Ebpf
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.netNatHelper = ctx.Service("netfilter").(netfilter.Interface)
	p.rpcProbes = make(map[int]*rpcebpf.Ebpf)
	return nil
}

func (p *provider) Gather(c chan *metric.Metric) {
	p.ch = make(chan rpcebpf.Metric, 100)
	eBPFprogram := rpcebpf.GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		panic(err)
	}
	vethes, err := p.kprobeHelper.GetVethes()
	if err != nil {
		panic(err)
	}
	for _, veth := range vethes {
		proj := rpcebpf.NewEbpf(veth.Link.Attrs().Index, veth.Neigh.IP.String(), p.ch)
		if err := proj.Load(spec); err != nil {
			klog.Errorf("failed to load ebpf, err: %v", err)
			continue
		}
		p.Lock()
		p.rpcProbes[veth.Link.Attrs().Index] = proj
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
				if _, ok := p.rpcProbes[event.Link.Attrs().Index]; ok {
					p.Unlock()
					continue
				}
				proj := rpcebpf.NewEbpf(event.Link.Attrs().Index, event.Neigh.IP.String(), p.ch)
				if err := proj.Load(spec); err != nil {
					klog.Errorf("failed to load ebpf, err: %v", err)
					p.Unlock()
					continue
				}
				p.rpcProbes[event.Link.Attrs().Index] = proj
				p.Unlock()
			case kprobe.LinkDelete:
				klog.Infof("veth delete, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
				p.Lock()
				proj, ok := p.rpcProbes[event.Link.Attrs().Index]
				if ok {
					proj.Close()
					delete(p.rpcProbes, event.Link.Attrs().Index)
				}
				p.Unlock()
			default:
				klog.Infof("unknown event type: %v", event.Type)
			}
		}
	}
}

func (p *provider) sendMetrics(c chan *metric.Metric) {
	for {
		select {
		case m := <-p.ch:
			if len(m.Status) == 0 || len(m.Path) == 0 {
				if m.RpcType == rpcebpf.RPC_TYPE_GRPC {
					m.Path = "Unknown"
				} else {
					continue
				}
			}
			mc := p.convertRpc2Metric(&m)
			// ignore redis ping
			if mc.Name == redisMeasurementGroup && strings.ToLower(mc.Tags["redis_command"]) == "ping" {
				continue
			}
			c <- &mc
			//klog.Infof("rpc metric: %+v", mc)
		}
	}
}

func (p *provider) convertRpc2Metric(m *rpcebpf.Metric) metric.Metric {
	res := metric.Metric{
		Timestamp: time.Now().UnixNano(),
		Tags:      map[string]string{},
		Fields: map[string]interface{}{
			"elapsed_count": 1,
			"elapsed_sum":   m.Duration,
			"elapsed_max":   m.Duration,
			"elapsed_min":   m.Duration,
			"elapsed_mean":  m.Duration,
		},
	}
	switch m.RpcType {
	case rpcebpf.RPC_TYPE_DUBBO, rpcebpf.RPC_TYPE_GRPC:
		res.Name, res.Measurement = rpcMeasurementGroup, rpcMeasurementGroup
	case rpcebpf.RPC_TYPE_MYSQL:
		res.Name, res.Measurement = dbMeasurementGroup, dbMeasurementGroup
		res.Tags["db_statement"] = m.Path
	case rpcebpf.RPC_TYPE_REDIS:
		res.Name, res.Measurement = redisMeasurementGroup, redisMeasurementGroup
	default:

	}
	if m.RpcType == rpcebpf.RPC_TYPE_MYSQL {
		res.Tags["db_statement"] = m.Path
		if m.Status != "200" {
			res.Name = dbErrorMeasurementGroup
			res.Measurement = dbErrorMeasurementGroup
			res.Tags["db_error"] = m.MysqlErr
		}
	}
	res.Tags["metric_source"] = "ebpf"
	res.Tags["_meta"] = "true"
	res.Tags["_metric_scope"] = "micro_service"
	res.Tags["span_kind"] = "server"
	res.Tags["rpc_type"] = string(m.RpcType)
	res.Tags["peer_address"] = fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)
	if m.RpcType != rpcebpf.RPC_TYPE_REDIS {
		res.Tags["peer_service"] = m.Path
		res.Tags["method"] = m.Path
	}
	res.Tags["component"] = string(m.RpcType)
	res.Tags["db_host"] = fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)
	var rpcTarget, rpcMethod, rpcService, rpcVersion, serviceVersion string
	rpcTarget = m.Path
	parseLine := pathRegexp.FindStringSubmatch(m.Path)
	if len(parseLine) == 5 {
		rpcTarget = fmt.Sprintf("%s.%s", parseLine[2], parseLine[4])
		rpcMethod = parseLine[4]
		rpcService = parseLine[2]
		rpcVersion = parseLine[1]
		serviceVersion = parseLine[3]
	}
	if m.RpcType == rpcebpf.RPC_TYPE_REDIS {
		protocolList := strings.Split(m.Path, "\r\n")
		if len(protocolList) >= 3 {
			res.Tags["redis_command"] = protocolList[2]
		}
		if len(protocolList) >= 5 {
			res.Tags["redis_args"] = protocolList[4]
		}
		res.Tags["redis_staus"] = m.Status
		res.Tags["redis_sql"] = res.Tags["redis_command"] + " " + res.Tags["redis_args"]
		res.Tags["db_statement"] = res.Tags["redis_sql"]
	}
	res.Tags["rpc_target"] = rpcTarget
	if m.RpcType == rpcebpf.RPC_TYPE_DUBBO {
		res.Tags["dubbo_service"] = rpcService
		res.Tags["dubbo_version"] = rpcVersion
		res.Tags["dubbo_method"] = rpcMethod
		res.Tags["service_version"] = serviceVersion
		if m.Status == "20" {
			res.Tags["error"] = "false"
		} else {
			res.Name = rpcErrorMeasurementGroup
			res.Measurement = rpcErrorMeasurementGroup
			res.Tags["error"] = "true"
		}
		res.Tags["rpc_method"] = res.Tags["dubbo_method"]
		res.Tags["rpc_service"] = res.Tags["dubbo_service"]
	} else {
		if m.Status == "200" {
			res.Tags["error"] = "false"
		} else {
			res.Tags["error"] = "true"
		}
	}
	sourcePod, err := p.kprobeHelper.GetPodByUID(m.SrcIP)
	if err == nil {
		res.OrgName = sourcePod.Labels["DICE_ORG_NAME"]
		res.Tags["source_application_id"] = sourcePod.Labels["DICE_APPLICATION_ID"]
		res.Tags["source_application_name"] = sourcePod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["source_org_id"] = sourcePod.Labels["DICE_ORG_ID"]
		res.Tags["_metric_scope_id"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
		res.Tags["org_name"] = sourcePod.Labels["DICE_ORG_NAME"]
		res.Tags["cluster_name"] = sourcePod.Labels["DICE_CLUSTER_NAME"]
		res.Tags["source_project_id"] = sourcePod.Labels["DICE_PROJECT_ID"]
		res.Tags["source_project_name"] = sourcePod.Labels["DICE_PROJECT_NAME"]
		res.Tags["source_runtime_id"] = sourcePod.Labels["DICE_RUNTIME_ID"]
		res.Tags["source_runtime_name"] = sourcePod.Annotations["msp.erda.cloud/runtime_name"]
		//res.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Labels["DICE_APPLICATION_ID"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Labels["DICE_SERVICE_NAME"])
		//res.Tags["source_service_id"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Annotations["msp.erda.cloud/application_id"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Annotations["msp.erda.cloud/service_name"])
		res.Tags["source_service_name"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["source_workspace"] = sourcePod.Annotations["msp.erda.cloud/workspace"]
		res.Tags["source_terminus_key"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
	}

	dstIP := m.DstIP
	natInfo, exist := p.netNatHelper.GetNatInfo(m.SrcIP, m.SrcPort)
	if exist {
		dstIP = natInfo.ReplyDstIP
		m.DstPort = natInfo.ReplyDstPort
	}
	targetPod, err := p.kprobeHelper.GetPodByUID(dstIP)
	if err == nil {
		res.OrgName = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["cluster_name"] = targetPod.Labels["DICE_CLUSTER_NAME"]
		//res.Tags["_metric_scope_id"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		res.Tags["host_ip"] = targetPod.Status.HostIP
		res.Tags["org_name"] = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["target_application_id"] = targetPod.Labels["DICE_APPLICATION_ID"]
		res.Tags["target_application_name"] = targetPod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["target_org_id"] = targetPod.Labels["DICE_ORG_ID"]
		res.Tags["target_project_id"] = targetPod.Labels["DICE_PROJECT_ID"]
		res.Tags["target_project_name"] = targetPod.Labels["DICE_PROJECT_NAME"]
		res.Tags["target_runtime_id"] = targetPod.Labels["DICE_RUNTIME_ID"]
		res.Tags["target_runtime_name"] = targetPod.Annotations["msp.erda.cloud/runtime_name"]
		//res.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", targetPod.Labels["DICE_APPLICATION_ID"], targetPod.Annotations["msp.erda.cloud/runtime_name"], targetPod.Labels["DICE_SERVICE_NAME"])
		//res.Tags["target_service_id"] = targetPod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", targetPod.Annotations["msp.erda.cloud/application_id"], targetPod.Annotations["msp.erda.cloud/runtime_name"], targetPod.Annotations["msp.erda.cloud/service_name"])
		res.Tags["target_service_instance_id"] = string(targetPod.UID)
		res.Tags["target_service_name"] = targetPod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["target_terminus_key"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		res.Tags["target_workspace"] = targetPod.Annotations["msp.erda.cloud/workspace"]
	}
	return res
}

func init() {
	servicehub.Register("rpc", &servicehub.Spec{
		Services:     []string{"rpc"},
		Description:  "ebpf for rpc",
		Dependencies: []string{"kprobe", "netfilter"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
