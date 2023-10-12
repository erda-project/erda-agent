package controller

import (
	"log"
	"strings"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/plugins/memory/oomparser"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/pkg/criruntime"
	"github.com/erda-project/ebpf-agent/pkg/k8sclient"
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
}

func NewController() Controller {
	config := k8sclient.OutOfClusterAuth()
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}

	runtimeFactory, err := criruntime.NewFactory("/run/containerd")
	if err != nil {
		log.Panic(err)
	}
	return Controller{
		clientSet:      clientSet,
		config:         config,
		runtimeFactory: runtimeFactory,
	}
}

func (c *Controller) watchForOoms(ch chan metric.Metric) error {
	outStream := make(chan *oomparser.OomInstance, 10)
	oomParser, err := oomparser.New()
	if err != nil {
		return err
	}
	go oomParser.StreamOoms(outStream)

	go func() {
		for oomInstance := range outStream {
			klog.Infof("oomInstance: %+v", oomInstance)
			containerID := getContainerID(oomInstance.ContainerName)

			containerRuntime := c.runtimeFactory.GetRuntimeService()
			contStats, err := containerRuntime.ContainerStats(containerID)
			if err != nil {
				klog.Errorf("failed to get container stats: %v", err)
				continue
			}
			if !checkIsKubernetesPod(contStats.Attributes.GetLabels()) {
				klog.Warningf("container %s is not a kubernetes pod", containerID)
				continue
			}
			ch <- convertContainerStatsToMetric(contStats)
		}
	}()
	return nil
}

func convertContainerStatsToMetric(contStats *runtimeapi.ContainerStats) metric.Metric {
	var metric metric.Metric
	contLabels := contStats.Attributes.GetLabels()
	metric.Measurement = "oom_event"
	metric.AddTags("podname", contLabels[labelKubernetesPodName])
	metric.AddTags("namespace", contLabels[labelKubernetesPodName])
	metric.AddField("container_oom_events_total", 1)
	return metric
}

func checkIsKubernetesPod(labels map[string]string) bool {
	return labels[labelKubernetesPodName] != "" && labels[labelKubernetesPodNamespace] != ""
}

func getContainerID(namespacedName string) string {
	splitedNames := strings.Split(namespacedName, "/")
	return splitedNames[len(splitedNames)-1]
}
