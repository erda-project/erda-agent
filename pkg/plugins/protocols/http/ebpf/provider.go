package ebpf

import (
	"bytes"
	"fmt"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/erda-project/erda-agent/pkg/btfs"
	"k8s.io/klog/v2"

	"github.com/erda-project/erda-agent/pkg/utils"
)

const (
	programPath = "target/http.bpf.o"
	programName = "socket__filter_package"
	mapFilter   = "filter_map"
	mapMetric   = "metrics_map"
)

type Interface interface {
	Load() error
	Close() error
}

type provider struct {
	ifIndex   int
	ipAddress string
	ch        chan Metric

	collection *ebpf.Collection
	fd         int
	sock       int
	log        klog.Logger
}

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func New(ifIndex int, ip string, ch chan Metric) Interface {
	return &provider{
		ifIndex:   ifIndex,
		ipAddress: ip,
		ch:        ch,
	}
}

func (e *provider) Load() error {
	programBytes, err := os.ReadFile(programPath)
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(programBytes))
	if err != nil {
		return err
	}
	e.collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfs.BtfSpec,
		},
	})
	if err != nil {
		return err
	}

	program := e.collection.DetachProgram(programName)
	if program == nil {
		return fmt.Errorf("detach program %s failed", programName)
	}

	e.fd = program.FD()

	e.sock, err = utils.OpenRawSock(e.ifIndex)
	if err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(e.sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, program.FD()); err != nil {
		return err
	}

	if err := e.collection.DetachMap(mapFilter).Put(
		utils.Htonl(utils.IP4toDec(e.ipAddress)), uint32(0),
	); err != nil {
		return err
	}
	m := e.collection.DetachMap(mapMetric)
	go e.FanInMetric(m)
	return nil
}

func (e *provider) FanInMetric(m *ebpf.Map) {
	defer func() {
		if err := recover(); err != nil {
			klog.Errorf("panic: %v", err)
			klog.Errorf("stack: %s", string(debug.Stack()))
		}
	}()

	var (
		key ConnTuple
		val HttpPackage
	)
	for {
		for m.Iterate().Next(&key, &val) {
			// clean map
			if err := m.Delete(key); err != nil {
				klog.Errorf("delete map error: %v", err)
				continue
			}
			metric, err := DecodeMetrics(&key, &val)
			if err != nil {
				klog.Errorf("decode metrics error: %v", err)
				continue
			}
			e.ch <- *metric
		}
		time.Sleep(1 * time.Second)
	}
}

func (e *provider) Close() error {
	_ = syscall.SetsockoptInt(e.sock, syscall.SOL_SOCKET, SO_DETACH_BPF, e.fd)
	e.collection.Close()
	return nil
}
