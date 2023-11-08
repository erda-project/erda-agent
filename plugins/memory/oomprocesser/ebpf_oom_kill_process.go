package oomprocesser

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog"
)

var (
	oomKillProcessFN = "oom_kill_process"
)

func WatchOOM(ch chan<- *OOMEvent) {
	eBPFprogram := GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		klog.Errorf("failed to load collection spec: %v", err)
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	prog := coll.DetachProgram("kprobe_oom_kill_process")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_oom_kill_process")
		log.Fatal(errors.New(msg))
	}

	kp, err := link.Kprobe(oomKillProcessFN, prog, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	oomMap := coll.DetachMap("oom_map")
	for {
		var (
			key   uint32
			event []byte
		)
		for oomMap.Iterate().Next(&key, &event) {
			oomEvent := DecodeMapItem(event)
			klog.Infof("oom event: %+v", oomEvent)
			if err := oomMap.Delete(key); err != nil {
				log.Fatalf("deleting map: %v", err)
			}
			ch <- oomEvent
		}
		time.Sleep(1 * time.Second)
	}
}

func DecodeMapItem(e []byte) *OOMEvent {
	m := new(OOMEvent)
	m.Pid = binary.LittleEndian.Uint32(e[0:4])
	m.Pages = binary.BigEndian.Uint64(e[4:12])
	m.KnID = binary.BigEndian.Uint64(e[12:20])
	m.FComm = string(e[20:36])
	m.CgroupPath = string(e[36:])
	return m
}
