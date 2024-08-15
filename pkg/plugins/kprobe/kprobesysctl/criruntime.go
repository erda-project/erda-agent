package kprobesysctl

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/procfs"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog"
)

var (
	kubepodsRegexp = regexp.MustCompile(
		"" +
			`(?:^/kubepods/[^/]+/pod([^/]+)/$)|` +
			`(?:^/kubepods\.slice/kubepods-[^/]+\.slice/kubepods-[^/]+-pod([^/]+)\.slice/$)`,
	)

	containerIDRegexp = regexp.MustCompile("^[[:xdigit:]]{64}$")
)

const (
	systemdScopeSuffix = ".scope"
)

const (
	CacheRefreshAction = iota
	CacheDeleteAction
	CacheUpdateAction
)

// Depending on the filesystem driver used for cgroup
// management, the paths in /proc/pid/cgroup will have
// one of the following formats in a Docker container:
//
//	systemd: /system.slice/docker-<container-ID>.scope
//	cgroupfs: /docker/<container-ID>
//
// In a Kubernetes pod, the cgroup path will look like:
//
//	systemd: /kubepods.slice/kubepods-<QoS-class>.slice/kubepods-<QoS-class>-pod<pod-UID>.slice/<container-iD>.scope
//	cgroupfs: /kubepods/<QoS-class>/pod<pod-UID>/<container-iD>
func readCgroupInfoFromPID(pid uint32) (string, string, string, error) {
	r, err := os.Open(fmt.Sprintf("/rootfs/proc/%d/cgroup", pid))
	if err != nil {
		return "", "", "", err
	}
	defer r.Close()

	s := bufio.NewScanner(r)
	var podUID string
	var containerID string
	var podPath string
	for s.Scan() {
		fields := strings.SplitN(s.Text(), ":", 3)
		if len(fields) != 3 {
			continue
		}
		cgroupPath := fields[2]
		dir, id := path.Split(cgroupPath)
		if strings.HasSuffix(id, systemdScopeSuffix) {
			id = id[:len(id)-len(systemdScopeSuffix)]
			if dash := strings.IndexRune(id, '-'); dash != -1 {
				id = id[dash+1:]
			}
		}
		if match := kubepodsRegexp.FindStringSubmatch(dir); match != nil {
			uid := match[1]
			if uid == "" {
				uid = match[2]
			}
			podUID = uid
			containerID = id
			podPath = cgroupPath
			break
		} else if containerIDRegexp.MatchString(id) {
			containerID = id
		}
	}
	if err := s.Err(); err != nil {
		return "", "", "", err
	}
	return podUID, containerID, podPath, nil
}

func readCgroupInfoFromProc(cgroups []procfs.Cgroup) (string, string, string) {
	var podUID string
	var containerID string
	var podPath string
	for _, cgroup := range cgroups {
		cgroupPath := cgroup.Path
		dir, id := path.Split(cgroupPath)
		if strings.HasSuffix(id, systemdScopeSuffix) {
			id = id[:len(id)-len(systemdScopeSuffix)]
			if dash := strings.IndexRune(id, '-'); dash != -1 {
				id = id[dash+1:]
			}
		}
		if match := kubepodsRegexp.FindStringSubmatch(dir); match != nil {
			uid := match[1]
			if uid == "" {
				uid = match[2]
			}
			podUID = uid
			containerID = id
			podPath = cgroupPath
			break
		} else if containerIDRegexp.MatchString(id) {
			containerID = id
		}
	}
	return podUID, containerID, podPath
}

func (k *KprobeSysctlController) refreshProcCgroupInfo() error {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return err
	}
	allProcs, err := fs.AllProcs()
	if err != nil {
		return err
	}
	for _, proc := range allProcs {
		cgroups, err := proc.Cgroups()
		if err != nil {
			klog.Errorf("failed to get cgroups for pid %d: %v", proc.PID, err)
			continue
		}
		stat := SysctlStat{
			Pid:      uint32(proc.PID),
			IsSystem: true,
		}
		podUID, containerID, podPath := readCgroupInfoFromProc(cgroups)
		stat.PodUID = podUID
		stat.ContainerID = containerID
		stat.ID = podPath
		if len(podUID) > 0 || len(containerID) > 0 {
			stat.IsSystem = false
			klog.Infof("pid %d is in pod %s container %s", proc.PID, podUID, containerID)
		}
		k.sysCtlCache.Set(strconv.FormatUint(uint64(stat.Pid), 10), stat, time.Hour)
		//if err := k.objs.KprobeSysctlMap.Update(uint32(proc.PID), EncodeStat(stat), ebpf.UpdateAny); err != nil {
		//	klog.Errorf("failed to update kprobe sysctl map, key: %d, err: %v", proc.PID, err)
		//}
	}
	return nil
}

func (k *KprobeSysctlController) refreshPodInfo() error {
	pods, err := k.podLister.List(labels.Everything())
	if err != nil {
		return err
	}

	for i := range pods {
		// ignore evicted pods
		if pods[i].Status.Reason == "Evicted" {
			continue
		}
		k.podCache.Set(string(pods[i].UID), pods[i], 30*time.Minute)
		k.podCache.Set(pods[i].Status.PodIP, pods[i], 30*time.Minute)
	}
	return nil
}

func (k *KprobeSysctlController) refreshServiceInfo(s *corev1.Service) error {
	refreshFunc := func(svc *corev1.Service) {
		// ignore not ClusterIP and headless services
		if (svc.Spec.Type != corev1.ServiceTypeClusterIP) || (svc.Spec.ClusterIP == corev1.ClusterIPNone) {
			return
		}

		k.serviceCache.Set(svc.Spec.ClusterIP, svc, time.Hour)
	}

	// load all namespace.
	if s == nil {
		services, err := k.serviceLister.List(labels.Everything())
		if err != nil {
			return err
		}

		for i := range services {
			refreshFunc(services[i])
		}
		return nil
	}

	// load specific service.
	refreshFunc(s)
	return nil
}
