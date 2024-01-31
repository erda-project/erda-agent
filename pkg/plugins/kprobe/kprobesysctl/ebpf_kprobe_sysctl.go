package kprobesysctl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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
	sysCtlCache *cache.Cache
	podCache    *cache.Cache
	clientSet   *kubernetes.Clientset
	objs        bpfObjects
}

func New(clientSet *kubernetes.Clientset) *KprobeSysctlController {
	var objs bpfObjects
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	return &KprobeSysctlController{
		clientSet:   clientSet,
		sysCtlCache: cache.New(time.Hour, 10*time.Minute),
		podCache:    cache.New(time.Hour, 10*time.Minute),
		objs:        objs,
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

func (k *KprobeSysctlController) Start(ch chan<- *SysctlStat) error {
	if err := k.refreshProcCgroupInfo(); err != nil {
		return err
	}
	if err := k.refreshPodInfo(); err != nil {
		return err
	}
	stopper := make(chan struct{})
	factory := informers.NewSharedInformerFactory(k.clientSet, 0)
	informer := factory.Core().V1().Pods().Informer()
	informer.AddEventHandler(clientgoCache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			newPod := obj.(*corev1.Pod)
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
	go informer.Run(stopper)
	go func() {
		pidTicker := time.NewTicker(time.Hour)
		podTicker := time.NewTicker(30 * time.Minute)
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
			}
		}
	}()
	go k.WatchKprobeSysClone(ch)
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
