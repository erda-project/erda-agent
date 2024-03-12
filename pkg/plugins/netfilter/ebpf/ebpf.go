package ebpf

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"io/ioutil"
	"k8s.io/klog"
	"log"
	"time"
)

type Ebpf struct {
	collection *ebpf.Collection

	kprobeIptDoTableProg    *ebpf.Program
	kretprobeIptDoTableProg *ebpf.Program

	kprobeIptDoTableKP    link.Link
	kretprobeIptDoTableKP link.Link
}

func NewEbpf() *Ebpf {
	return &Ebpf{}
}

func (e *Ebpf) Load(spec *ebpf.CollectionSpec) error {
	var err error
	e.collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}

	e.kprobeIptDoTableProg = e.collection.DetachProgram("kprobe_ipt_do_table")
	if e.kprobeIptDoTableProg == nil {
		return errors.New("failed to find kprobe_ipt_do_table program")
	}
	e.kretprobeIptDoTableProg = e.collection.DetachProgram("kretprobe_ipt_do_table")
	if e.kretprobeIptDoTableProg == nil {
		return errors.New("failed to find kretprobe_ipt_do_table program")
	}

	e.kprobeIptDoTableKP, err = link.Kprobe("ipt_do_table", e.kprobeIptDoTableProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe(ipt_do_table): %v", err)
	}
	e.kretprobeIptDoTableKP, err = link.Kretprobe("ipt_do_table", e.kretprobeIptDoTableProg, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kretprobe(ipt_do_table): %v", err)
	}

	go func() {
		m := e.collection.DetachMap("event_buf")
		var (
			key uint32
			val []byte
		)
		for {
			for m.Iterate().Next(&key, &val) {
				klog.Infof("key: %d, val: %s", key, val)
				if err := m.Delete(key); err != nil {
					panic(err)
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

func (e *Ebpf) Close() {
	e.kprobeIptDoTableProg.Close()
	e.kretprobeIptDoTableProg.Close()

	e.kprobeIptDoTableKP.Close()
	e.kretprobeIptDoTableKP.Close()

	e.collection.Close()
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/netfilter.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
