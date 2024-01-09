package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog/v2"
)

const (
	tcpSendMsgFN = "tcp_sendmsg"
	tcpRecvMsgFN = "tcp_recvmsg"
	tcpCloseFN   = "tcp_close"
)

type Ebpf struct {
	IfIndex   int
	IPaddress string
	NodeName  string
	//hostnetwork类型的pod,使用pod来区分k8s的元数据
	PortMap map[int32]K8SMeta
	Ch      chan Metric
}

type K8SMeta struct {
	PodName     string
	NameSpace   string
	ServiceName string
}

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func NewEbpf(ifindex int, ch chan Metric) *Ebpf {
	return &Ebpf{
		IfIndex: ifindex,
		Ch:      ch,
	}
}

func (e *Ebpf) Load() error {
	eBPFprogram := GetEBPFProg()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	defer coll.Close()
	prog := coll.DetachProgram("rpc__filter_package")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "rpc__filter_package")
		return errors.New(msg)
	}

	tcpSendMsgProg := coll.DetachProgram("kprobe_tcp_sendmsg")
	if tcpSendMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_sendmsg")
		log.Fatal(errors.New(msg))
	}

	kprobeTcpRecvMsgProg := coll.DetachProgram("kprobe_tcp_recvmsg")
	if kprobeTcpRecvMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_recvmsg")
		log.Fatal(errors.New(msg))
	}

	kretprobeTcpRecvMsgProg := coll.DetachProgram("kretprobe_tcp_recvmsg")
	if kretprobeTcpRecvMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kretprobe_tcp_recvmsg")
		log.Fatal(errors.New(msg))
	}

	kprobeTcpCloseProg := coll.DetachProgram("kprobe_tcp_close")
	if kprobeTcpCloseProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_close")
		log.Fatal(errors.New(msg))
	}

	tcpSendMsgKP, err := link.Kprobe(tcpSendMsgFN, tcpSendMsgProg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer tcpSendMsgKP.Close()

	kprobeTcpRecvMsgKP, err := link.Kprobe(tcpRecvMsgFN, kprobeTcpRecvMsgProg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeTcpRecvMsgKP.Close()

	kretprobeTcpRecvMsgKP, err := link.Kretprobe(tcpRecvMsgFN, kretprobeTcpRecvMsgProg, nil)
	if err != nil {
		log.Fatalf("opening kretprobe: %s", err)
	}
	defer kretprobeTcpRecvMsgKP.Close()

	kprobeTcpCloseKP, err := link.Kprobe(tcpCloseFN, kprobeTcpCloseProg, nil)
	if err != nil {
		log.Fatalf("opening kretprobe: %s", err)
	}
	defer kprobeTcpCloseKP.Close()

	sock, err := OpenRawSock(e.IfIndex)
	if err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}
	m := coll.DetachMap("response_map")
	var (
		key uint32
		val []byte
	)
	for {
		for m.Iterate().Next(&key, &val) {
			value := DecodeMapItem(val)
			metric := e.Converet(value)
			if err := m.Delete(key); err != nil {
				panic(err)
			}
			klog.Infof("receive metric: +v", metric)
			if metric == nil {
				break
			}
			e.Ch <- *metric
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func (e *Ebpf) Converet(p *MapPackage) *Metric {
	m := new(Metric)
	m.Type = p.Type
	m.DstIP = p.DstIP
	m.DstPort = p.DstPort
	m.SrcIP = p.SrcIP
	m.SrcPort = p.SrcPort
	m.Duration = p.Duration
	m.Host = p.Host
	m.Method = p.Method
	m.Protocol = p.Protocol
	m.URL = p.URL
	m.Code = p.Code
	m.NodeName = e.NodeName
	m.IfIndex = e.IfIndex
	if m.DstIP == e.IPaddress {
		m.Flow = 0
	} else {
		m.Flow = 1
	}
	m.Pid = p.Pid
	return m
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/rpc.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
