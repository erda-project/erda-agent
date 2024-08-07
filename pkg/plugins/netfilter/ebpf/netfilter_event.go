package ebpf

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	ethProtoIP   = 0x0800
	ethProtoIPv6 = 0x86DD
)

const (
	ipprotoICMP   = 1
	ipprotoTCP    = 6
	ipprotoUDP    = 17
	ipprotoICMPv6 = 58
)

const (
	routeEventIf      = 0x0001
	routeEventIptable = 0x0002
)

var (
	nfVerdictName = []string{
		"DROP",
		"ACCEPT",
		"STOLEN",
		"QUEUE",
		"REPEAT",
		"STOP",
	}

	hookNames = []string{
		"PREROUTING",
		"INPUT",
		"FORWARD",
		"OUTPUT",
		"POSTROUTING",
	}

	tcpFlagNames = []string{
		"CWR",
		"ECE",
		"URG",
		"ACK",
		"PSH",
		"RST",
		"SYN",
		"FIN",
	}
)

func _get(names []string, idx uint32, defaultVal string) string {
	if int(idx) < len(names) {
		return names[idx]
	}

	return defaultVal
}

type l2Info struct {
	DestMac [6]byte
	L3Proto uint16
}

type l3Info struct {
	Saddr     [16]byte
	Daddr     [16]byte
	TotLen    uint16
	IPVersion uint8
	L4Proto   uint8
}

type srcL3Info struct {
	SrcSaddr     [16]byte
	SrcDaddr     [16]byte
	SrcTotLen    uint16
	SrcIPVersion uint8
	SrcL4Proto   uint8
}

type l4Info struct {
	Sport    uint16
	Dport    uint16
	Ack      uint32
	TCPFlags uint16
	Pad      [2]byte
}

type srcL4Info struct {
	SrcSport    uint16
	SrcDport    uint16
	SrcAck      uint32
	SrcTCPFlags uint16
	SrcPad      [2]byte
}

type icmpInfo struct {
	IcmpID   uint16
	IcmpSeq  uint16
	IcmpType uint8
	Pad      [3]byte
}

type iptablesInfo struct {
	TableName [32]byte
	Verdict   uint32
	IptDelay  uint64
	Hook      uint8
	Pf        uint8
	Pad       [2]byte
}

type pktInfo struct {
	Ifname  [16]byte
	Len     uint32
	CPU     uint32
	Pid     uint32
	NetNS   uint32
	PktType uint8
	Pad     [3]byte
}

type perfEvent struct {
	Skb     uint64
	StartNs uint64
	Flags   uint8
	Pad     [3]byte

	pktInfo
	l2Info
	l3Info
	l4Info
	icmpInfo
	iptablesInfo
}

type ConnEvent struct {
	Src      [16]byte
	Dst      [16]byte
	Sport    uint16
	Dport    uint16
	OriSrc   [16]byte
	OriDst   [16]byte
	OriSport uint16
	OriDport uint16
}

var earliestTs = uint64(0)

func (e *perfEvent) outputTimestamp() string {
	return time.Unix(0, int64(e.StartNs)).Format("15:04:05")
}

func (e *perfEvent) outputTcpFlags() string {
	var flags []string
	tcpFlags := uint8(e.TCPFlags >> 8)
	for i := 0; i < len(tcpFlagNames); i++ {
		if tcpFlags&(1<<i) != 0 {
			flags = append(flags, tcpFlagNames[i])
		}
	}

	return strings.Join(flags, ",")
}

func (e *perfEvent) outputPktInfo() string {
	var saddr, daddr net.IP
	if e.l2Info.L3Proto == ethProtoIP {
		saddr = net.IP(e.Saddr[:4])
		daddr = net.IP(e.Daddr[:4])
	} else {
		saddr = net.IP(e.Saddr[:])
		daddr = net.IP(e.Daddr[:])
	}

	if e.L4Proto == ipprotoTCP {
		tcpFlags := e.outputTcpFlags()
		if tcpFlags == "" {
			return fmt.Sprintf("T:%s:%d->%s:%d",
				saddr, e.Sport, daddr, e.Dport)
		}
		return fmt.Sprintf("T_%s:%s:%d->%s:%d", tcpFlags,
			saddr, e.Sport, daddr, e.Dport)

	} else if e.L4Proto == ipprotoUDP {
		return fmt.Sprintf("U:%s:%d->%s:%d",
			saddr, e.Sport, daddr, e.Dport)
	} else if e.L4Proto == ipprotoICMP || e.L4Proto == ipprotoICMPv6 {
		if e.IcmpType == 8 || e.IcmpType == 128 {
			return fmt.Sprintf("I_request:%s->%s", saddr, daddr)
		} else if e.IcmpType == 0 || e.IcmpType == 129 {
			return fmt.Sprintf("I_reply:%s->%s", saddr, daddr)
		} else {
			return fmt.Sprintf("I:%s->%s", saddr, daddr)
		}
	} else {
		return fmt.Sprintf("%d:%s->%s", e.L4Proto, saddr, daddr)
	}
}

func nullTerminatedStr(b []byte) string {
	off := 0
	for ; off < len(b) && b[off] != 0; off++ {
	}
	b = b[:off]
	return *(*string)(unsafe.Pointer(&b))
}

func (e *perfEvent) outputTraceInfo() string {
	iptables := ""
	if e.Flags&routeEventIptable == routeEventIptable {
		pf := "PF_INET"
		if e.Pf == 10 {
			pf = "PF_INET6"
		}
		iptName := nullTerminatedStr(e.TableName[:])
		hook := _get(hookNames, uint32(e.Hook), fmt.Sprintf("~UNK~[%d]", e.Hook))
		verdict := _get(nfVerdictName, e.Verdict, fmt.Sprintf("~UNK~[%d]", e.Verdict))
		cost := time.Duration(e.IptDelay)
		iptables = fmt.Sprintf("pf=%s, table=%s hook=%s verdict=%s cost=%s", pf, iptName, hook, verdict, cost)
	}

	pktType := e.outputPktType(e.PktType)
	return fmt.Sprintf("pkt_type=%s iptables=[%s]", pktType, iptables)
}

func (e *perfEvent) outputPktType(pktType uint8) string {
	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PACKET_USER   = 6
		PACKET_KERNEL = 7
	)
	pktTypes := map[uint8]string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PACKET_USER:              "USER",
		PACKET_KERNEL:            "KERNEL",
	}
	if s, ok := pktTypes[pktType]; ok {
		return s
	}
	return ""
}

func (e *perfEvent) output() string {
	var s strings.Builder

	// time
	t := e.outputTimestamp()
	s.WriteString(fmt.Sprintf("[%-8s] ", t))

	// skb
	s.WriteString(fmt.Sprintf("[0x%-16x] ", e.Skb))

	// netns
	s.WriteString(fmt.Sprintf("[%-10d] ", e.NetNS))

	// pid
	s.WriteString(fmt.Sprintf("%-8d ", e.Pid))

	// cpu
	s.WriteString(fmt.Sprintf("%-6d ", e.CPU))

	// interface
	ifname := nullTerminatedStr(e.Ifname[:])
	s.WriteString(fmt.Sprintf("%-18s ", ifname))

	// dest mac
	destMac := net.HardwareAddr(e.DestMac[:]).String()
	s.WriteString(fmt.Sprintf("%-18s ", destMac))

	// ip len
	s.WriteString(fmt.Sprintf("%-6d ", e.TotLen))

	// pkt info
	pktInfo := e.outputPktInfo()
	s.WriteString(fmt.Sprintf("%-54s ", pktInfo))

	// trace info
	traceInfo := e.outputTraceInfo()
	s.WriteString(traceInfo)

	return s.String()
}
