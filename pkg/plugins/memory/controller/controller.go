package controller

import (
	"log"
	"strings"
	"time"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/criruntime"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/kprobesysctl"
	oomprocesser2 "github.com/erda-project/ebpf-agent/pkg/plugins/memory/oomprocesser"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog"
)

var (
	labelKubernetesPodName      = "io.kubernetes.pod.name"
	labelKubernetesPodNamespace = "io.kubernetes.pod.namespace"
)

type Controller struct {
	stopper        chan struct{}
	clientSet      *kubernetes.Clientset
	config         *rest.Config
	runtimeFactory criruntime.Factory

	kprobeHelper kprobe.Interface
}

func NewController(helper kprobe.Interface) Controller {
	//config := k8sclient.GetRestConfig()
	//clientSet, err := kubernetes.NewForConfig(config)
	//if err != nil {
	//	log.Panic(err)
	//}
	//
	runtimeFactory, err := criruntime.NewFactory("/run/containerd")
	if err != nil {
		log.Panic(err)
	}
	return Controller{
		kprobeHelper: helper,
		//clientSet:      clientSet,
		//config:         config,
		runtimeFactory: runtimeFactory,
	}
}

func (c *Controller) Start(ch chan metric.Metric) {
	go c.watchForOoms(ch)
}

func (c *Controller) watchForOoms(ch chan metric.Metric) error {
	//outStream := make(chan *oomprocesser.OomInstance, 10)
	//oomParser, err := oomprocesser.New()
	//if err != nil {
	//	return err
	//}
	//go oomParser.StreamOoms(outStream)
	oomEventChan := make(chan *oomprocesser2.OOMEvent, 10)
	go oomprocesser2.WatchOOM(oomEventChan)

	go func() {
		for event := range oomEventChan {
			stat, err := c.kprobeHelper.GetSysctlStat(event.Pid)
			if err != nil {
				klog.Errorf("failed to get sysctl stat for oom event, err: %v", err)
				continue
			}
			klog.Infof("oom event pid: %d, stat: %v", event.Pid, stat)
			pod, err := c.kprobeHelper.GetPodByUID(strings.ReplaceAll(stat.PodUID, "_", "-"))
			if err != nil {
				klog.Errorf("failed to get pod by uid: %s, err: %v", stat.PodUID, err)
				continue
			}
			oomMetric := c.convertOomEvent2Metric(event, pod, stat)
			ch <- oomMetric
			klog.Infof("oom event: %+v", event)
		}
		//for oomInstance := range outStream {
		//	//klog.Infof("oomInstance: %+v", oomInstance)
		//	containerID := getContainerID(oomInstance.ContainerName)
		//
		//	containerRuntime := c.runtimeFactory.GetRuntimeService()
		//	contStats, err := containerRuntime.ContainerStats(containerID)
		//	if err != nil {
		//		//klog.Errorf("failed to get container stats: containerID: %s, err: %v", containerID, err)
		//		continue
		//	}
		//	if !checkIsKubernetesPod(contStats.Attributes.GetLabels()) {
		//		//klog.Warningf("container %s is not a kubernetes pod", containerID)
		//		continue
		//	}
		//	ch <- convertContainerStatsToMetric(contStats)
		//}
	}()
	return nil
}

func (c *Controller) convertOomEvent2Metric(event *oomprocesser2.OOMEvent, pod v1.Pod, stat kprobesysctl.SysctlStat) metric.Metric {
	var metric metric.Metric
	metric.Measurement = "docker_container_summary"
	metric.Name = "docker_container_summary"
	metric.Timestamp = time.Now().UnixNano()
	metric.OrgName = pod.Labels["DICE_ORG_NAME"]
	if len(pod.Status.ContainerStatuses) > 0 {
		metric.AddTags("name", strings.TrimLeft(pod.Status.ContainerStatuses[0].ContainerID, "containerd://"))
	}
	metric.AddTags("namespace", pod.Namespace)
	metric.AddTags("pod", pod.Name)
	metric.AddTags("container", pod.Spec.Containers[0].Name)
	metric.AddTags("image", pod.Spec.Containers[0].Image)
	metric.AddTags("application_id", pod.Labels["DICE_APPLICATION_ID"])
	metric.AddTags("application_name", pod.Labels["DICE_APPLICATION_NAME"])
	metric.AddTags("cluster_name", pod.Labels["DICE_CLUSTER_NAME"])
	metric.AddTags("container_id", stat.ContainerID)
	metric.AddTags("container_image", pod.Spec.Containers[0].Image)
	metric.AddTags("id", stat.ID)
	metric.AddTags("deployment_id", pod.Labels["DICE_DEPLOYMENT_ID"])
	metric.AddTags("org_id", pod.Labels["DICE_ORG_ID"])
	metric.AddTags("org_name", pod.Labels["DICE_ORG_NAME"])
	metric.AddTags("pod_ip", pod.Status.PodIP)
	metric.AddTags("pod_name", pod.Name)
	metric.AddTags("pod_namespace", pod.Namespace)
	metric.AddTags("pod_uid", string(pod.UID))
	metric.AddTags("project_id", pod.Labels["DICE_PROJECT_ID"])
	metric.AddTags("project_name", pod.Labels["DICE_PROJECT_NAME"])
	metric.AddTags("runtime_id", pod.Labels["DICE_RUNTIME_ID"])
	metric.AddTags("runtime_name", pod.Labels["DICE_RUNTIME_NAME"])
	metric.AddTags("terminus_key", pod.Annotations["msp.erda.cloud/terminus_key"])
	metric.AddTags("workspace", pod.Labels["DICE_WORKSPACE"])
	metric.AddTags("metric_source", "ebpf-agent")
	metric.AddField("oomkilled", true)
	return metric
}

func convertContainerStatsToMetric(contStats *runtimeapi.ContainerStats) metric.Metric {
	var metric metric.Metric
	contLabels := contStats.Attributes.GetLabels()
	metric.Measurement = "oom_event"
	metric.AddTags("podname", contLabels[labelKubernetesPodName])
	metric.AddTags("namespace", contLabels[labelKubernetesPodNamespace])
	metric.AddField("container_oom_events_total", 1)
	return metric
}

func checkIsKubernetesPod(labels map[string]string) bool {
	return labels[labelKubernetesPodName] != "" && labels[labelKubernetesPodNamespace] != ""
}

func getContainerID(namespacedName string) string {
	splitedNames := strings.Split(namespacedName, "/")
	return strings.TrimRight(strings.TrimLeft(splitedNames[len(splitedNames)-1], "docker-"), ".scope")
}
