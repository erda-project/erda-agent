package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	ebpf2 "github.com/erda-project/erda-agent/pkg/plugins/protocols/http/ebpf"
)

func TestEbpf(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	eBPFprogram := GetHttpEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}

	defer coll.Close()

	prog := coll.DetachProgram("socket__filter_package")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "socket__filter_package")
		return errors.New(msg)
	}

	sock, err := OpenRawSock(7082)
	// sock, err := OpenRawSock(2)
	if err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, ebpf2.SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}

	defer syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, ebpf2.SO_DETACH_BPF, prog.FD())

	m := coll.DetachMap("metrics_map")

	defer m.Close()

	if m == nil {
		return errors.New("nil map detach")
	}

	var (
		key ebpf2.ConnTuple
		val ebpf2.HttpPackage
	)

	for {
		for m.Iterate().Next(&key, &val) {
			metric, err := ebpf2.DecodeMetrics(&key, &val)
			if err != nil {
				fmt.Println(err)
			}
			if err := m.Delete(key); err != nil {
				panic(err)
			}
			fmt.Println(fmt.Sprintf("metric: %+v", metric))
		}
		time.Sleep(1 * time.Second)
	}
}

func GetHttpEBPFProg() []byte {
	b, err := os.ReadFile("/root/ltx/ebpf-agent/target/http-dev.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}

	return b
}
