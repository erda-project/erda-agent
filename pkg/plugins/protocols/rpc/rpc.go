package rpc

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"regexp"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/klog"

	"github.com/cilium/ebpf"
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	rpcebpf "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/rpc/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
)

const (
	measurementGroup = "application_rpc"
)

var (
	pathRegexp = regexp.MustCompile(`(.*)!([a-zA-Z.]+)([0-9.]+)([a-zA-Z/;]+)`)
)

type provider struct {
	ch           chan rpcebpf.Metric
	kprobeHelper kprobe.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	return nil
}

type NeighLink struct {
	Neigh netlink.Neigh
	Link  netlink.Link
}

// TODO: move this function to kprobe plugin, add some notify channel let protocol plugin listen veth link change
func getAllVethes() ([]NeighLink, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	targetLinks := make([]netlink.Link, 0)
	for _, link := range links {
		if link.Type() == "bridge" {
			targetLinks = append(targetLinks, link)
		}
		if link.Type() == "veth" {
			targetLinks = append(targetLinks, link)
		}
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ans := make([]NeighLink, 0)
	for _, l := range targetLinks {
		neighs, err := netlink.NeighList(l.Attrs().Index, unix.AF_INET)
		if err != nil {
			return nil, err
		}
		if len(neighs) == 1 && l.Type() == "veth" {
			ans = append(ans, NeighLink{
				Neigh: neighs[0],
				Link:  l,
			})
			continue
		}
		for _, neigh := range neighs {
			for _, iface := range ifs {
				link, err := netlink.LinkByName(iface.Name)
				if err != nil {
					continue
				}
				if link.Type() == "veth" {
					neighBr, errBr := netlink.NeighList(link.Attrs().Index, int(unix.AF_BRIDGE))
					if errBr != nil {
						continue
					}
					for _, neighB := range neighBr {
						if neighB.HardwareAddr.String() == neigh.HardwareAddr.String() {
							ans = append(ans, NeighLink{
								Neigh: neigh,
								Link:  link,
							})
							break
						}
					}
				}
			}
		}
	}
	return ans, nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.ch = make(chan rpcebpf.Metric, 100)
	eBPFprogram := rpcebpf.GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		panic(err)
	}
	vethLinks, err := getAllVethes()
	if err != nil {
		panic(err)
	}
	for _, link := range vethLinks {
		go func(l NeighLink) {
			proj := rpcebpf.NewEbpf(l.Link.Attrs().Index, l.Neigh.IP.String(), p.ch)
			if err := proj.Load(spec); err != nil {
				log.Fatalf("failed to load ebpf, err: %v", err)
			}
		}(link)
	}
	for {
		select {
		case m := <-p.ch:
			if len(m.Status) == 0 || len(m.Path) == 0 {
				continue
			}
			mc := p.convertRpc2Metric(&m)
			c <- mc
			klog.Infof("rpc metric: %+v", mc)
		}
	}
}

func (p *provider) convertRpc2Metric(m *rpcebpf.Metric) metric.Metric {
	res := metric.Metric{
		Name:        measurementGroup,
		Measurement: measurementGroup,
		Timestamp:   time.Now().UnixNano(),
		Tags:        map[string]string{},
		Fields: map[string]interface{}{
			"elapsed_count": 1,
			"elapsed_sum":   m.Duration,
			"elapsed_max":   m.Duration,
			"elapsed_min":   m.Duration,
			"elapsed_mean":  m.Duration,
		},
	}
	res.Tags["metric_source"] = "ebpf"
	res.Tags["_meta"] = "true"
	res.Tags["_metric_scope"] = "micro_service"
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
	res.Tags["rpc_target"] = rpcTarget
	targetPod, err := p.kprobeHelper.GetPodByUID(m.SrcIP)
	if err == nil {
		res.OrgName = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["cluster_name"] = targetPod.Labels["DICE_CLUSTER_NAME"]
		res.Tags["component"] = string(m.RpcType)
		res.Tags["db_host"] = fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)
		res.Tags["method"] = m.Path
		res.Tags["_metric_scope_id"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		if m.RpcType == rpcebpf.RPC_TYPE_DUBBO {
			res.Tags["dubbo_service"] = rpcService
			res.Tags["dubbo_version"] = rpcVersion
			res.Tags["dubbo_method"] = rpcMethod
			res.Tags["service_version"] = serviceVersion
			if m.Status == "20" {
				res.Tags["error"] = "false"
			} else {
				res.Tags["error"] = "true"
			}
		} else {
			if m.Status == "200" {
				res.Tags["error"] = "false"
			} else {
				res.Tags["error"] = "true"
			}
		}
		res.Tags["host_ip"] = targetPod.Status.HostIP
		res.Tags["org_name"] = targetPod.Labels["DICE_ORG_NAME"]
		res.Tags["peer_address"] = fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)
		res.Tags["peer_service"] = m.Path
		res.Tags["rpc_method"] = res.Tags["dubbo_method"]
		res.Tags["rpc_service"] = res.Tags["dubbo_service"]
		res.Tags["span_kind"] = "server"
		res.Tags["target_application_id"] = targetPod.Labels["DICE_APPLICATION_ID"]
		res.Tags["target_application_name"] = targetPod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["target_org_id"] = targetPod.Labels["DICE_ORG_ID"]
		res.Tags["target_project_id"] = targetPod.Labels["DICE_PROJECT_ID"]
		res.Tags["target_project_name"] = targetPod.Labels["DICE_PROJECT_NAME"]
		res.Tags["target_runtime_id"] = targetPod.Labels["DICE_RUNTIME_ID"]
		res.Tags["target_runtime_name"] = targetPod.Annotations["msp.erda.cloud/runtime_name"]
		res.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", targetPod.Labels["DICE_APPLICATION_ID"], targetPod.Annotations["msp.erda.cloud/runtime_name"], targetPod.Labels["DICE_SERVICE_NAME"])
		res.Tags["target_service_instance_id"] = string(targetPod.UID)
		res.Tags["target_service_name"] = targetPod.Annotations["msp.erda.cloud/service_name"]
		res.Tags["target_terminus_key"] = targetPod.Annotations["msp.erda.cloud/terminus_key"]
		res.Tags["target_workspace"] = targetPod.Annotations["msp.erda.cloud/workspace"]
	}
	sourcePod, err := p.kprobeHelper.GetPodByUID(m.DstIP)
	if err == nil {
		res.Tags["source_application_id"] = sourcePod.Labels["DICE_APPLICATION_ID"]
		res.Tags["source_application_name"] = sourcePod.Labels["DICE_APPLICATION_NAME"]
		res.Tags["source_org_id"] = sourcePod.Labels["DICE_ORG_ID"]
		res.Tags["source_project_id"] = sourcePod.Labels["DICE_PROJECT_ID"]
		res.Tags["source_project_name"] = sourcePod.Labels["DICE_PROJECT_NAME"]
		res.Tags["source_runtime_id"] = sourcePod.Labels["DICE_RUNTIME_ID"]
		res.Tags["source_runtime_name"] = sourcePod.Annotations["msp.erda.cloud/runtime_name"]
		res.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Labels["DICE_APPLICATION_ID"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Labels["DICE_SERVICE_NAME"])
		res.Tags["source_workspace"] = sourcePod.Annotations["msp.erda.cloud/workspace"]
	}
	return res
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
