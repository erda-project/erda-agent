package utils

import (
	"encoding/binary"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// ETH_P_IP: Internet Protocol version 4 (IPv4)
// ETH_P_ARP: Address Resolution Protocol (ARP)
// ETH_P_IPV6: Internet Protocol version 6 (IPv6)
// ETH_P_RARP: Reverse ARP
// ETH_P_LOOP: Loopback protocol
const EthPAll uint16 = 0x03

// OpenRawSock opens a raw socket for the given interface index.
func OpenRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET,
		syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(Htons(EthPAll)))
	if err != nil {
		return 0, err
	}

	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = Htons(EthPAll)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}

	return sock, nil
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
