package kprobesysctl

import "testing"

func TestEncodeStat(t *testing.T) {
	stat := &SysctlStat{
		Pid:         10,
		CgroupID:    10,
		PodUID:      "2726c67e_1b11_4c6b_8446_f5c9f15622b4",
		ContainerID: "18926b6ea1c8f803ef33c3074bc14f6ef3253a08454b40b658dde6e5460d41ca",
	}
	encodedStat := EncodeStat(stat)
	decodedStat := DecodeMapItem(encodedStat)
	if decodedStat.PodUID != stat.PodUID {
		t.Errorf("PodUID not equal")
	}
}
