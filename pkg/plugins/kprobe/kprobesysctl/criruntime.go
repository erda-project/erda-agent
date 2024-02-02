package kprobesysctl

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/procfs"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	fs, err := procfs.NewFS("/rootfs/proc")
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
	pods, err := k.clientSet.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range pods.Items {
		// ignore evicted pods
		if pods.Items[i].Status.Reason == "Evicted" {
			continue
		}
		k.podCache.Set(string(pods.Items[i].UID), pods.Items[i], 30*time.Minute)
		k.podCache.Set(pods.Items[i].Status.PodIP, pods.Items[i], 30*time.Minute)
	}
	return nil
}
