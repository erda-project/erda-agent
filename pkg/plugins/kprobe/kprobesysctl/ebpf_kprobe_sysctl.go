package kprobesysctl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/btfs"
	"github.com/erda-project/ebpf-agent/pkg/envconf"
	"github.com/erda-project/ebpf-agent/pkg/exporter/collector"
	"github.com/patrickmn/go-cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	clientgoCache "k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

var (
	emptyContainerID = "                                                                "
	emptyPodUID      = "                                    "
	idCheckRegexp    = regexp.MustCompile(`^[\w+-\.]{64}$`)
)

type KprobeSysctlController struct {
	hostIP       string
	sysCtlCache  *cache.Cache
	podCache     *cache.Cache
	serviceCache *cache.Cache
	clientSet    *kubernetes.Clientset
	reportClient *collector.ReportClient
	objs         bpfObjects
}

func New(clientSet *kubernetes.Clientset) *KprobeSysctlController {
	var objs bpfObjects
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfs.BtfSpec,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	reportConfig := &collector.CollectorConfig{}
	envconf.MustLoad(reportConfig)
	return &KprobeSysctlController{
		hostIP:       os.Getenv("HOST_IP"),
		clientSet:    clientSet,
		sysCtlCache:  cache.New(time.Hour, 10*time.Minute),
		podCache:     cache.New(time.Hour, 10*time.Minute),
		serviceCache: cache.New(time.Hour, 10*time.Minute),
		reportClient: collector.CreateReportClient(reportConfig),
		objs:         objs,
	}
}

func (k *KprobeSysctlController) GetSysctlStatByPID(pid uint32) (SysctlStat, error) {
	if stat, ok := k.sysCtlCache.Get(strconv.FormatUint(uint64(pid), 10)); ok {
		return stat.(SysctlStat), nil
	}
	return SysctlStat{}, fmt.Errorf("failed to find sysctl stat for pid: %d", pid)
}

func (k *KprobeSysctlController) GetPodByUID(uid string) (corev1.Pod, error) {
	if pod, ok := k.podCache.Get(uid); ok {
		return pod.(corev1.Pod), nil
	}
	return corev1.Pod{}, fmt.Errorf("failed to find pod for uid: %s", uid)
}

func (k *KprobeSysctlController) GetService(ip string) (corev1.Service, error) {
	if svc, ok := k.serviceCache.Get(ip); ok {
		return svc.(corev1.Service), nil
	}
	return corev1.Service{}, fmt.Errorf("failed to get service from cache, ip: %s", ip)
}

func (k *KprobeSysctlController) Start(ch chan<- *SysctlStat) error {
	if err := k.refreshProcCgroupInfo(); err != nil {
		return err
	}
	if err := k.refreshPodInfo(); err != nil {
		return err
	}
	if err := k.refreshServiceInfo(nil); err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactory(k.clientSet, 0)
	// pod informer
	podInformerStopper := make(chan struct{})
	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(clientgoCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			newPod := obj.(*corev1.Pod)
			if newPod.Status.Reason == "Evicted" {
				return
			}
			k.podCache.Set(string(newPod.UID), *newPod, 30*time.Minute)
			k.podCache.Set(newPod.Status.PodIP, *newPod, 30*time.Minute)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			k.podCache.Delete(string(pod.UID))
			k.podCache.Delete(pod.Status.PodIP)
		},
		// UpdateFunc: func(oldObj interface{}, newObj interface{}) {
		// },
	})
	go podInformer.Run(podInformerStopper)

	// service informer
	serviceInformerStopper := make(chan struct{})
	serviceInformer := factory.Core().V1().Services().Informer()
	serviceInformer.AddEventHandler(clientgoCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			newSvc, ok := obj.(*corev1.Service)
			if ok {
				_ = k.refreshServiceInfo(newSvc)
			}
		},
		DeleteFunc: func(obj interface{}) {
			svc, ok := obj.(*corev1.Service)
			if ok && (svc.Spec.Type == corev1.ServiceTypeClusterIP && svc.Spec.ClusterIP != corev1.ClusterIPNone) {
				k.serviceCache.Delete(svc.Spec.ClusterIP)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldSvc, ok := oldObj.(*corev1.Service)
			if ok && (oldSvc.Spec.Type == corev1.ServiceTypeClusterIP && oldSvc.Spec.ClusterIP != corev1.ClusterIPNone) {
				k.serviceCache.Delete(oldSvc.Spec.ClusterIP)
			}
			newSvc, ok := newObj.(*corev1.Service)
			if ok {
				_ = k.refreshServiceInfo(newSvc)
			}
		},
	})

	go serviceInformer.Run(serviceInformerStopper)

	// todo: add recover and context control
	go func() {
		pidTicker := time.NewTicker(time.Hour)
		podTicker := time.NewTicker(30 * time.Minute)
		svcTicker := time.NewTicker(time.Minute)
		for {
			select {
			case <-pidTicker.C:
				if err := k.refreshProcCgroupInfo(); err != nil {
					klog.Errorf("failed to refresh cgroup infos, err: %v", err)
				}
			case <-podTicker.C:
				if err := k.refreshPodInfo(); err != nil {
					klog.Errorf("failed to refresh pod infos, err: %v", err)
				}
			case <-svcTicker.C:
				if err := k.refreshServiceInfo(nil); err != nil {
					klog.Errorf("failed to refresh service infos, err: %v", err)
				}
			}
		}
	}()
	go k.WatchKprobeSysClone(ch)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-ticker.C:
				if err := k.updateServiceNode(); err != nil {
					klog.Errorf("failed to update service node, err: %v", err)
				}
			}
		}
	}()
	return nil
}

func (k *KprobeSysctlController) WatchKprobeSysClone(ch chan<- *SysctlStat) {
	// Name of the kernel function to trace.
	fn := "sys_clone"

	kp, err := link.Kprobe(fn, k.objs.KprobeSysctlProg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	for {
		var key uint32
		var value []byte
		for k.objs.KprobeSysctlMap.Iterate().Next(&key, &value) {
			stat := DecodeMapItem(value)
			stat.Pid = key
			if err := k.objs.KprobeSysctlMap.Delete(key); err != nil {
				klog.Errorf("failed to delete map item: %v", err)
			}
			if stat.Pid != 0 && !isContainerID(stat.ContainerID) {
				podUID, containerID, podPath, err := readCgroupInfoFromPID(stat.Pid)
				if err != nil {
					//klog.Errorf("failed to get cgroups for pid %d: %v", stat.Pid, err)
					goto judge
				}
				stat.PodUID = podUID
				stat.ContainerID = containerID
				stat.ID = podPath
				if stat.PodUID != "" || stat.ContainerID != "" {
					stat.IsSystem = false
					//klog.Infof("find containerID: %s, poduid: %s for pid: %d", stat.ContainerID, stat.PodUID, stat.Pid)
				}
				//encodeStat := EncodeStat(stat)
				//if err := k.objs.KprobeSysctlMap.Update(key, encodeStat, ebpf.UpdateAny); err != nil {
				//	klog.Errorf("failed to update kprobe sysctl map, key: %d, err: %v", key, err)
				//}
			}
		judge:
			if !isContainerID(stat.ContainerID) {
				stat.IsSystem = true
			}
			k.updateStat(stat)
		}
		time.Sleep(1 * time.Second)
	}
}

func (k *KprobeSysctlController) updateStat(stat SysctlStat) {
	k.sysCtlCache.Set(strconv.FormatUint(uint64(stat.Pid), 10), stat, time.Hour)
}

func isContainerID(id string) bool {
	return idCheckRegexp.MatchString(id)
}

func DecodeMapItem(e []byte) SysctlStat {
	m := SysctlStat{}
	m.Pid = binary.LittleEndian.Uint32(e[0:4])
	m.CgroupID = binary.LittleEndian.Uint32(e[4:8])
	m.PodUID = string(e[8:44])
	m.ContainerID = string(e[44:108])
	return m
}

func EncodeStat(stat *SysctlStat) []byte {
	w := bytes.NewBuffer([]byte{})
	binary.Write(w, binary.LittleEndian, stat.Pid)
	binary.Write(w, binary.LittleEndian, stat.CgroupID)
	podUID := emptyPodUID
	if len(stat.PodUID) == 36 {
		podUID = stat.PodUID
	}
	binary.Write(w, binary.LittleEndian, []byte(podUID))
	containerID := emptyContainerID
	if len(stat.ContainerID) == 64 {
		containerID = stat.ContainerID
	}
	binary.Write(w, binary.LittleEndian, []byte(containerID))
	return w.Bytes()
}

func makeServiceNodeMetric(pod corev1.Pod) *metric.Metric {
	now := time.Now().Unix()
	return &metric.Metric{
		Measurement: "application_service_node",
		Name:        "application_service_node",
		Timestamp:   time.Now().UnixNano(),
		Tags: map[string]string{
			"_meta":               "true",
			"_metric_scope":       "micro_service",
			"_metric_scope_id":    pod.Annotations["msp.erda.cloud/terminus_key"],
			"application_id":      pod.Labels["DICE_DEPLOYMENT_ID"],
			"application_name":    pod.Labels["DICE_APPLICATION_NAME"],
			"cluster_name":        pod.Labels["DICE_CLUSTER_NAME"],
			"env_id":              pod.Annotations["msp.erda.cloud/terminus_key"],
			"host_ip":             pod.Status.HostIP,
			"host":                pod.Spec.NodeName,
			"instance_id":         string(pod.UID),
			"org_id":              pod.Labels["DICE_ORG_ID"],
			"org_name":            pod.Labels["DICE_ORG_NAME"],
			"project_id":          pod.Labels["DICE_PROJECT_ID"],
			"project_name":        pod.Labels["DICE_PROJECT_NAME"],
			"runtime_id":          pod.Labels["DICE_RUNTIME_ID"],
			"runtime_name":        pod.Annotations["msp.erda.cloud/runtime_name"],
			"service_id":          pod.Labels["DICE_SERVICE"],
			"service_instance_id": string(pod.UID),
			"service_ip":          pod.Status.PodIP,
			"service_name":        pod.Labels["DICE_SERVICE_NAME"],
			"terminus_key":        pod.Annotations["msp.erda.cloud/terminus_key"],
			"workspace":           pod.Labels["DICE_WORKSPACE"],
		},
		Fields: map[string]interface{}{
			"start_time_count": 1,
			"start_time_max":   now,
			"start_time_mean":  now,
			"start_time_min":   now,
			"start_time_sum":   now,
		},
	}
}

func (k *KprobeSysctlController) updateServiceNode() error {
	podItems := k.podCache.Items()
	serviceNodes := make([]*metric.Metric, 0)
	for _, item := range podItems {
		pod, ok := item.Object.(corev1.Pod)
		if !ok {
			continue
		}
		if pod.Status.HostIP != k.hostIP || len(pod.Labels["DICE_SERVICE"]) == 0 {
			continue
		}
		m := makeServiceNodeMetric(pod)
		serviceNodes = append(serviceNodes, m)
	}
	if len(serviceNodes) == 0 {
		return nil
	}
	return k.reportClient.Send(serviceNodes)
}
