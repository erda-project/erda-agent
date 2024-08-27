package meta

import (
	"fmt"
	"strconv"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/netfilter"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/ebpf"
	"github.com/erda-project/erda-infra/base/logs"
)

const (
	measurementGroup         = "application_http"
	measurementGroupError    = "application_http_error"
	measurementGroupDuration = "application_http_slow"
)

type Interface interface {
	Convert(metric *ebpf.Metric) *metric.Metric
}

type provider struct {
	l            logs.Logger
	kprobeHelper kprobe.Interface
	netNatHelper netfilter.Interface
}

func New(l logs.Logger, k kprobe.Interface, n netfilter.Interface) Interface {
	return &provider{
		l:            l,
		kprobeHelper: k,
		netNatHelper: n,
	}
}

func (p *provider) Convert(m *ebpf.Metric) *metric.Metric {
	p.l.Debugf("gonna to convert metrics: %+v", m)
	measurement := measurementGroup
	output := &metric.Metric{
		Timestamp: time.Now().UnixNano(),
		Tags: map[string]string{
			"metric_source":    "ebpf",
			"_meta":            "true",
			"_metric_scope":    "micro_service",
			"span_kind":        "server",
			"http_method":      m.Method,
			"http_path":        m.Path,
			"http_status_code": strconv.Itoa(int(m.StatusCode)),
			// TODO: diff with http_path?
			"http_target":  m.Path,
			"http_version": m.Version,
			// TODO: full url with query params, replace Host?
			"http_url": fmt.Sprintf("http://%s:%d%s", m.DestIP, m.DestPort, m.Path),
		},
		Fields: map[string]interface{}{
			"elapsed_count": 1,
			"elapsed_sum":   m.Duration,
			"elapsed_max":   m.Duration,
			"elapsed_min":   m.Duration,
			"elapsed_mean":  m.Duration,
		},
	}
	p.l.Debugf("ebpf metrics: %s", m.String())

	if m.StatusCode >= 400 {
		measurement = measurementGroupError
	}

	// TODO: how to define slow request?
	output.Measurement = measurement
	output.Name = measurement

	sourcePod, err := p.kprobeHelper.GetPodByUID(m.SourceIP)
	if err != nil {
		p.l.Errorf("failed to get pod by uid: %s, err: %v", m.SourceIP, err)
	} else {
		// source platform metadata
		output.OrgName = sourcePod.Labels["DICE_ORG_NAME"]
		output.Tags["_metric_scope_id"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
		output.Tags["source_application_id"] = sourcePod.Labels["DICE_APPLICATION_ID"]
		output.Tags["source_application_name"] = sourcePod.Labels["DICE_APPLICATION_NAME"]
		output.Tags["source_org_id"] = sourcePod.Labels["DICE_ORG_ID"]
		output.Tags["source_project_id"] = sourcePod.Labels["DICE_PROJECT_ID"]
		output.Tags["source_project_name"] = sourcePod.Labels["DICE_PROJECT_NAME"]
		output.Tags["source_runtime_id"] = sourcePod.Labels["DICE_RUNTIME_ID"]
		output.Tags["source_runtime_name"] = sourcePod.Annotations["msp.erda.cloud/runtime_name"]
		//output.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s",
		//	sourcePod.Labels["DICE_APPLICATION_ID"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Labels["DICE_SERVICE_NAME"])
		//output.Tags["source_service_id"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		output.Tags["source_service_id"] = fmt.Sprintf("%s_%s_%s", sourcePod.Annotations["msp.erda.cloud/application_id"], sourcePod.Annotations["msp.erda.cloud/runtime_name"], sourcePod.Annotations["msp.erda.cloud/service_name"])
		output.Tags["source_service_instance_id"] = string(sourcePod.UID)
		output.Tags["source_service_name"] = sourcePod.Annotations["msp.erda.cloud/service_name"]
		output.Tags["source_terminus_key"] = sourcePod.Annotations["msp.erda.cloud/terminus_key"]
		output.Tags["source_workspace"] = sourcePod.Annotations["msp.erda.cloud/workspace"]
	}

	var target any
	dstIP := m.DestIP
	natInfo, exist := p.netNatHelper.GetNatInfo(m.SourceIP, m.SourcePort)
	if exist {
		dstIP = natInfo.ReplyDstIP
		m.DestPort = natInfo.ReplyDstPort
	}

	pod, err := p.kprobeHelper.GetPodByUID(dstIP)
	if err != nil {
		svc, err := p.kprobeHelper.GetService(dstIP)
		if err == nil {
			target = svc
		}
	} else {
		target = pod
	}

	// external target
	if target == nil {
		p.l.Debugf("source: %s/%d, target(external): %s", m.SourceIP, m.SourcePort, m.DestIP)
		return nil
	}

	// in cluster
	switch t := target.(type) {
	case *corev1.Pod:
		p.l.Debugf("source(pod): %s/%d, target(pod): %s/%s", m.SourceIP, m.SourcePort, t.Namespace, t.Name)
		output.Tags["cluster_name"] = t.Labels["DICE_CLUSTER_NAME"]
		output.Tags["db_host"] = fmt.Sprintf("%s:%d", m.DestIP, m.DestPort)
		output.Tags["org_name"] = t.Labels["DICE_ORG_NAME"]
		// TODO: remove db_host
		output.Tags["peer_address"] = output.Tags["db_host"]
		// TODO: peer_hostname
		output.Tags["peer_hostname"] = ""
		output.OrgName = output.Tags["org_name"]

		// target platform metadata
		output.Tags["_metric_scope_id"] = t.Annotations["msp.erda.cloud/terminus_key"]
		output.Tags["target_application_id"] = t.Labels["DICE_APPLICATION_ID"]
		output.Tags["target_application_name"] = t.Labels["DICE_APPLICATION_NAME"]
		output.Tags["target_org_id"] = t.Labels["DICE_ORG_ID"]
		output.Tags["target_project_id"] = t.Labels["DICE_PROJECT_ID"]
		output.Tags["target_project_name"] = t.Labels["DICE_PROJECT_NAME"]
		output.Tags["target_runtime_id"] = t.Labels["DICE_RUNTIME_ID"]
		output.Tags["target_runtime_name"] = t.Annotations["msp.erda.cloud/runtime_name"]
		//output.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s",
		//	t.Labels["DICE_APPLICATION_ID"], t.Annotations["msp.erda.cloud/runtime_name"], t.Labels["DICE_SERVICE_NAME"])
		//output.Tags["target_service_id"] = t.Annotations["msp.erda.cloud/service_name"]
		output.Tags["target_service_id"] = fmt.Sprintf("%s_%s_%s", t.Annotations["msp.erda.cloud/application_id"], t.Annotations["msp.erda.cloud/runtime_name"], t.Annotations["msp.erda.cloud/service_name"])
		output.Tags["target_service_instance_id"] = string(t.UID)
		output.Tags["target_service_name"] = t.Annotations["msp.erda.cloud/service_name"]
		output.Tags["target_terminus_key"] = t.Annotations["msp.erda.cloud/terminus_key"]
		output.Tags["target_workspace"] = t.Annotations["msp.erda.cloud/workspace"]
	case *corev1.Service:
		// TODO: service resource
		p.l.Debugf("source(pod): %s/%d, target(service): %s/%s", m.SourceIP, m.SourcePort, t.Namespace, t.Name)
	default:
		p.l.Errorf("unknown target type: %T", target)
	}

	return output
}
