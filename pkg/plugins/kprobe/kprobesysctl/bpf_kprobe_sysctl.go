package kprobesysctl

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"

	"github.com/cilium/ebpf"
)

type SysctlStat struct {
	Pid         uint32 `json:"pid"`
	CgroupID    uint32 `json:"cgroupID"`
	PodUID      string `json:"podUID"`
	ContainerID string `json:"containerID"`
	IsSystem    bool   `json:"isSystem"`
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	eBPFprogram := GetEBPFProg()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfProgramSpecs struct {
	KprobeSysctlProg *ebpf.ProgramSpec `ebpf:"kprobe_sysctl_prog"`
}

type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

type bpfMapSpecs struct {
	KprobeMap *ebpf.MapSpec `ebpf:"kprobe_sysctl_map"`
}

type bpfMaps struct {
	KprobeSysctlMap *ebpf.Map `ebpf:"kprobe_sysctl_map"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.KprobeSysctlMap,
	)
}

type bpfPrograms struct {
	KprobeSysctlProg *ebpf.Program `ebpf:"kprobe_sysctl_prog"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.KprobeSysctlProg,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/kprobesysctl.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
