package kafka

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"io/ioutil"
	"k8s.io/klog"
	"log"
	"syscall"
	"time"
	"unsafe"
)

const (
	SO_ATTACH_BPF = 0x32
)

type Ebpf struct {
	IfIndex   int
	IPaddress string
	NodeName  string

	ch chan Event

	// ebpf collection
	collection *ebpf.Collection

	// ebpf program
	socketProg *ebpf.Program
}

func NewEbpf(ifindex int, ip string, ch chan Event) *Ebpf {
	return &Ebpf{
		ch:        ch,
		IfIndex:   ifindex,
		IPaddress: ip,
	}
}

func (e *Ebpf) Load(spec *ebpf.CollectionSpec) error {
	klog.Infof("ip: %s, index: %d start kafka", e.IPaddress, e.IfIndex)
	var err error
	e.collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	prog := e.collection.DetachProgram("socket__kafka_filter")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "rpc__filter_package")
		return errors.New(msg)
	}

	parserProg := e.collection.DetachProgram("socket__kafka_response_parser")
	if parserProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "socket__kafka_response_parser")
		return errors.New(msg)
	}

	sock, err := OpenRawSock(e.IfIndex)
	if err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}
	//if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, parserProg.FD()); err != nil {
	//	return err
	//}

	// register tail call
	tailCallMap := e.collection.DetachMap("tail_jmp_map")
	if err := tailCallMap.Update(uint32(1), uint32(parserProg.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update tail call map: %v", err)
	}

	go func() {
		m := e.collection.DetachMap("kafka_event")
		var (
			key []byte
			val []byte
		)
		for {
			for m.Iterate().Next(&key, &val) {
				if err := m.Delete(key); err != nil {
					klog.Errorf("delete map error: %v", err)
					continue
				}
				conn := ConnTuple{}
				if err := binary.Read(bytes.NewReader(key), binary.LittleEndian, &conn); err != nil {
					klog.Errorf("decode conn error: %v", err)
					continue
				}
				ev := decodeResponse(val)
				e.ch <- Event{ConnTuple: conn, Transaction: ev}
				klog.Infof("kafka key: %+v, val: %+v\n", conn, ev)
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

// Htons converts to network byte order short uint16.
func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// Htonl converts to network byte order long uint32.
func Htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func OpenRawSock(index int) (int, error) {
	// ETH_P_IP: Internet Protocol version 4 (IPv4)
	// ETH_P_ARP: Address Resolution Protocol (ARP)
	// ETH_P_IPV6: Internet Protocol version 6 (IPv6)
	// ETH_P_RARP: Reverse ARP
	// ETH_P_LOOP: Loopback protocol
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(Htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = Htons(ETH_P_ALL)
	//设置套接字的网卡序号
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/kafka.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
