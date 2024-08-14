package ebpf

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/erda-project/ebpf-agent/pkg/btfs"
	"k8s.io/klog"
)

const (
	tcpSendMsgFN = "tcp_sendmsg"
	tcpRecvMsgFN = "tcp_recvmsg"
	tcpCloseFN   = "tcp_close"
)

type Ebpf struct {
	sync.Mutex

	IfIndex   int
	IPaddress string
	NodeName  string
	//hostnetwork类型的pod,使用pod来区分k8s的元数据
	PortMap map[int32]K8SMeta
	Ch      chan Metric

	// ebpf collection
	collection *ebpf.Collection

	// ebpf program
	socketProg              *ebpf.Program
	tcpSendMsgProg          *ebpf.Program
	kprobeTcpRecvMsgProg    *ebpf.Program
	kretprobeTcpRecvMsgProg *ebpf.Program
	kprobeTcpCloseProg      *ebpf.Program

	// ebpf link
	tcpSendMsgKP          link.Link
	kprobeTcpRecvMsgKP    link.Link
	kretprobeTcpRecvMsgKP link.Link
	kprobeTcpCloseKP      link.Link
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

func NewEbpf(ifindex int, ip string, ch chan Metric) *Ebpf {
	return &Ebpf{
		IfIndex:   ifindex,
		Ch:        ch,
		IPaddress: ip,
	}
}

func (e *Ebpf) Load(spec *ebpf.CollectionSpec) error {
	klog.Infof("ip: %s, index: %d start rpc", e.IPaddress, e.IfIndex)
	var err error
	e.collection, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfs.BtfSpec,
		},
	})
	if err != nil {
		return err
	}
	prog := e.collection.DetachProgram("rpc__filter_package")
	if prog == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "rpc__filter_package")
		return errors.New(msg)
	}

	amqpFilterProg := e.collection.DetachProgram("socket__amqp_filter")
	if amqpFilterProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "socket__amqp_filter")
		return errors.New(msg)
	}

	e.tcpSendMsgProg = e.collection.DetachProgram("kprobe_tcp_sendmsg")
	if e.tcpSendMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_sendmsg")
		return errors.New(msg)
	}

	e.kprobeTcpRecvMsgProg = e.collection.DetachProgram("kprobe_tcp_recvmsg")
	if e.kprobeTcpRecvMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_recvmsg")
		return errors.New(msg)
	}

	e.kretprobeTcpRecvMsgProg = e.collection.DetachProgram("kretprobe_tcp_recvmsg")
	if e.kretprobeTcpRecvMsgProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kretprobe_tcp_recvmsg")
		return errors.New(msg)
	}

	e.kprobeTcpCloseProg = e.collection.DetachProgram("kprobe_tcp_close")
	if e.kprobeTcpCloseProg == nil {
		msg := fmt.Sprintf("Error: no program named %s found !", "kprobe_tcp_close")
		return errors.New(msg)
	}

	e.tcpSendMsgKP, err = link.Kprobe(tcpSendMsgFN, e.tcpSendMsgProg, nil)
	if err != nil {
		return err
	}

	e.kprobeTcpRecvMsgKP, err = link.Kprobe(tcpRecvMsgFN, e.kprobeTcpRecvMsgProg, nil)
	if err != nil {
		return err
	}

	e.kretprobeTcpRecvMsgKP, err = link.Kretprobe(tcpRecvMsgFN, e.kretprobeTcpRecvMsgProg, nil)
	if err != nil {
		return err
	}

	e.kprobeTcpCloseKP, err = link.Kprobe(tcpCloseFN, e.kprobeTcpCloseProg, nil)
	if err != nil {
		return err
	}

	sock, err := OpenRawSock(e.IfIndex)
	if err != nil {
		return err
	}

	// register tail call
	tailCallMap := e.collection.DetachMap("tail_jmp_map")
	if err := tailCallMap.Update(uint32(1), uint32(amqpFilterProg.FD()), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to update tail call map: %v", err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FD()); err != nil {
		return err
	}
	const keyIPAddr uint32 = 1
	// inject target ip address, if request srcip no equal target ip, will drop
	if err := e.collection.DetachMap("filter_map").Put(keyIPAddr, uint64(Htonl(IP4toDec(e.IPaddress)))); err != nil {
		return err
	}
	go func() {
		e.Lock()
		m := e.collection.DetachMap("grpc_trace_map")
		e.Unlock()
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
				e.Ch <- *metric
				//if metric.RpcType != RPC_TYPE_MYSQL {
				//	klog.Infof("metric: %v", metric.CovertMetric())
				//}
			}
			time.Sleep(1 * time.Second)
		}
	}()
	go func() {
		e.Lock()
		m := e.collection.DetachMap("amqp_trace_map")
		e.Unlock()
		var (
			key uint32
			val []byte
		)
		for {
			for m.Iterate().Next(&key, &val) {
				if err := m.Delete(key); err != nil {
					panic(err)
				}
				ev := DecodeAMQPMapItem(val)
				klog.Infof("length: %d, amqp: %v", len(val), ev)
			}
			time.Sleep(1 * time.Second)
		}
	}()
	return nil
}

func (e *Ebpf) Close() {
	e.tcpSendMsgKP.Close()
	e.kprobeTcpRecvMsgKP.Close()
	e.kretprobeTcpRecvMsgKP.Close()
	e.kprobeTcpCloseKP.Close()

	e.socketProg.Close()
	e.kprobeTcpCloseProg.Close()
	e.kprobeTcpRecvMsgProg.Close()
	e.kretprobeTcpRecvMsgProg.Close()
	e.tcpSendMsgProg.Close()

	e.collection.Close()
}

func (e *Ebpf) Converet(p *MapPackage) *Metric {
	m := new(Metric)
	if p.RpcType == 1 {
		m.RpcType = RPC_TYPE_GRPC
	} else if p.RpcType == 3 {
		m.RpcType = RPC_TYPE_DUBBO
	} else if p.RpcType == 4 {
		m.RpcType = RPC_TYPE_MYSQL
	} else if p.RpcType == 5 {
		m.RpcType = RPC_TYPE_REDIS
	}
	m.Phase = p.Phase
	m.EthernetType = p.EthernetType
	m.DstIP = p.DstIP
	m.DstPort = p.DstPort
	m.SrcIP = p.SrcIP
	m.SrcPort = p.SrcPort
	m.Seq = p.Seq
	m.NodeName = e.NodeName
	m.Pid = p.Pid
	m.Duration = p.Duration
	m.Path = p.Path
	m.PathLen = p.PathLen
	m.Status = p.Status
	m.MysqlErr = p.MysqlErr
	return m
}

func GetEBPFProg() []byte {
	b, err := ioutil.ReadFile("target/rpc.bpf.o")
	if err != nil {
		log.Println("Could not read BPF object file", err.Error())
	}
	return b
}
