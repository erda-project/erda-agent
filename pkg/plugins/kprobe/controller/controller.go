package controller

import (
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/criruntime"
	"github.com/erda-project/ebpf-agent/pkg/k8sclient"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/kprobesysctl"
)

type Controller struct {
	stopper          chan struct{}
	clientSet        *kubernetes.Clientset
	config           *rest.Config
	runtimeFactory   criruntime.Factory
	sysctlController *kprobesysctl.KprobeSysctlController
}

func NewController() Controller {
	config := k8sclient.GetRestConfig()
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Panic(err)
	}
	//
	//runtimeFactory, err := criruntime.NewFactory("/var/run")
	//if err != nil {
	//	log.Panic(err)
	//}
	sysctlControl := kprobesysctl.New(clientSet)
	return Controller{
		clientSet: clientSet,
		//config:         config,
		//runtimeFactory: runtimeFactory,
		sysctlController: sysctlControl,
	}
}

func (c *Controller) Start(ch chan *metric.Metric) {
	go c.watchKprobe(ch)
}

func (c *Controller) watchKprobe(ch chan *metric.Metric) error {
	sysctlChan := make(chan *kprobesysctl.SysctlStat, 10)
	go func() {
		for _ = range sysctlChan {
			//klog.Infof("kprobe sysctl: %v", sysctl)
		}
	}()
	if err := c.sysctlController.Start(sysctlChan); err != nil {
		return err
	}
	return nil
}

func (c *Controller) GetSysctlStat(pid uint32) (kprobesysctl.SysctlStat, error) {
	return c.sysctlController.GetSysctlStatByPID(pid)
}

func (c *Controller) GetPodByUID(podUID string) (corev1.Pod, error) {
	return c.sysctlController.GetPodByUID(podUID)
}

func (c *Controller) GetService(ip string) (corev1.Service, error) {
	return c.sysctlController.GetService(ip)
}
