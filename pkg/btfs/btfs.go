package btfs

import (
	"bytes"
	"embed"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/btf"
)

func init() {
	setKernelSpec()
}

var BtfSpec *btf.Spec

var (
	once sync.Once
	// TODO: add more kernel release to btf file mapping
	releaseToBtf = map[string]string{
		"5.10.134-16.1.al8.x86_64":    "5.4.28-200.el7.x86_64.btf",
		"5.4.278-1.el7.elrepo.x86_64": "5.4.28-200.el7.x86_64.btf",
		"5.5.5-1.el7.elrepo.x86_64":   "5.4.28-200.el7.x86_64.btf",
		"4.18.0-147.5.1.el8_1.x86_64": "4.18.0-147.5.1.el8_1.x86_64.btf",
	}
)

//go:embed archives/*
var btfFiles embed.FS

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func setKernelSpec() {
	once.Do(func() {
		btfSpec, err := btf.LoadKernelSpec()
		if err != nil {
			var uname syscall.Utsname
			if err := syscall.Uname(&uname); err != nil {
				panic(err)
			}
			release := int8ToStr(uname.Release[:])
			releaseTarget, ok := releaseToBtf[release]
			if !ok {
				panic("no btf file found for kernel release: " + release)
			}
			btfFileReader, err := btfFiles.ReadFile("archives/" + releaseTarget)
			if err != nil {
				panic(err)
			}
			btfSpec, err = btf.LoadSpecFromReader(bytes.NewReader(btfFileReader))
			if err != nil {
				panic(err)
			}
			BtfSpec = btfSpec
			return
		}
		BtfSpec = btfSpec
	})
}
