package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"k8s.io/klog"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/hpack"
)

type RpcType string

const (
	ETHERNET_TYPE_IPV4 = "ipv4"
	ETHERNET_TYPE_IPV6 = "ipv6"
)

const (
	// RPC_TYPE_DUBBO dubbo
	RPC_TYPE_DUBBO RpcType = "DUBBO"
	// RPC_TYPE_GRPC grpc
	RPC_TYPE_GRPC RpcType = "GRPC"
)

type MapPackage struct {
	//DUBBO, GRPC etc.
	RpcType      uint32
	Phase        uint32
	EthernetType string
	DstIP        string
	DstPort      uint16
	SrcIP        string
	SrcPort      uint16
	Seq          uint16
	Duration     uint32
	Pid          uint32
	PathLen      int
	Path         string
	Status       string
}

type Metric struct {
	RpcType      RpcType
	Phase        uint32
	EthernetType string
	DstIP        string
	DstPort      uint16
	SrcIP        string
	SrcPort      uint16
	Seq          uint16
	PodName      string
	NodeName     string
	NameSpace    string
	ServiceName  string
	Pid          uint32
	Duration     uint32
	PathLen      int
	Path         string
	Status       string
}

func (m *Metric) CovertMetric() metric.Metric {
	var metric metric.Metric
	metric.Measurement = "traffic"
	metric.AddTags("podname", m.PodName)
	metric.AddTags("nodename", m.NodeName)
	metric.AddTags("namespace", m.NameSpace)
	metric.AddTags("servicename", m.ServiceName)
	metric.AddTags("dstip", m.DstIP)
	metric.AddTags("dstport", strconv.Itoa(int(m.DstPort)))
	metric.AddTags("srcip", m.SrcIP)
	metric.AddTags("srcport", strconv.Itoa(int(m.SrcPort)))
	return metric
}

func (m *Metric) String() string {
	return fmt.Sprintf("phase: %d, dstip: %s, dstport: %d, srcip: %s, srcport: %d, seq: %d",
		m.Phase, m.DstIP, m.DstPort, m.SrcIP, m.SrcPort, m.Seq)
}

func DecodeMapItem(e []byte) *MapPackage {
	m := new(MapPackage)
	m.RpcType = uint32(e[0])
	m.Phase = uint32(e[4])
	etherType := uint32(e[8])
	if etherType == 0 {
		m.EthernetType = ETHERNET_TYPE_IPV4
	} else if etherType == 1 {
		m.EthernetType = ETHERNET_TYPE_IPV6
	}
	m.DstIP = net.IP(e[12:16]).String()
	m.DstPort = binary.BigEndian.Uint16(e[16:20])
	m.SrcIP = net.IP(e[20:24]).String()
	m.SrcPort = binary.BigEndian.Uint16(e[24:28])
	m.Seq = binary.BigEndian.Uint16(e[28:32])
	m.Duration = binary.LittleEndian.Uint32(e[32:36]) / 1000 / 1000
	m.Pid = binary.LittleEndian.Uint32(e[36:40])
	m.PathLen = int(e[40])
	var err error
	if m.RpcType == 1 && m.PathLen > 0 && m.PathLen < 100 && m.PathLen+41 < len(e) {
		m.Path, err = encodeHeader(e[41 : m.PathLen+41+1])
		if err != nil {
			klog.Errorf("encode path header error: %v", err)
			m.Path = string(e[41 : m.PathLen+41+1])
		}
	}
	// dubbo path
	if m.RpcType == 3 {
		//m.Path = string(e[41:121])
		tmp := e[41:121]
		j := 0
		for i := 0; i < len(tmp); i++ {
			if tmp[i] == 0x05 {
				m.Path += string(tmp[j:i])
				j = i + 1
			}
			if j != 0 && tmp[i] == 0x00 {
				m.Path += string(tmp[j:i])
				break
				j = i + 1
			}
		}
	}
	m.Status, err = encodeHeader(e[141:142])
	if err != nil {
		klog.Errorf("encode status header error: %v", err)
	}
	// dubbo status
	if m.RpcType == 3 {
		m.Status = strconv.Itoa(int(e[142]))
	}
	return m
}

func encodeHeader(source []byte) (string, error) {
	encodeString := hex.EncodeToString(source)
	encodePath := strings.TrimRight(encodeString, "00")
	encodedHex := []byte(encodePath)
	encoded := make([]byte, len(encodedHex)/2)
	_, err := hex.Decode(encoded, encodedHex)
	if err != nil {
		return "", err
	}
	decoder := hpack.NewDecoder(2048)
	hf, err := decoder.Decode(encoded)
	if err != nil {
		return "", err
	}
	var value string
	for _, h := range hf {
		value = h.Value
	}
	return value, nil
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

// IP4toDec transforms and IPv4 to decimal
func IP4toDec(IPv4Addr string) uint32 {
	bits := strings.Split(IPv4Addr, ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	// left shifting 24,16,8,0 and bitwise OR

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}

// OpenRawSock 创建一个原始的socket套接字
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
