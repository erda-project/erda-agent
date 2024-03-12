package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"io"
	"k8s.io/klog/v2"
	"net"
	"time"
)

func RunEbpf() {
	spec, err := loadNetfilter()
	if err != nil {
		panic(err)
	}
	var bpfObj netfilterObjects
	if err := spec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	}); err != nil {
		panic(err)
	}

	//kpIpForward, err := link.Kprobe("ip_forward", bpfObj.K_ipFroward, nil)
	//if err != nil {
	//	panic(err)
	//}
	//defer kpIpForward.Close()
	//
	//krpIpForward, err := link.Kretprobe("ip_forward", bpfObj.Kr_ipFroward, nil)
	//if err != nil {
	//	panic(err)
	//}
	//defer krpIpForward.Close()

	kp, err := link.Kprobe("ipt_do_table", bpfObj.K_iptDoTable, nil)
	if err != nil {
		panic(err)
	}
	defer kp.Close()

	krp, err := link.Kretprobe("ipt_do_table", bpfObj.KrIptDoTable, nil)
	if err != nil {
		panic(err)
	}
	defer krp.Close()

	kpNat, err := link.Kprobe("nf_nat_setup_info", bpfObj.K_natSetUpInfo, nil)
	if err != nil {
		panic(err)
	}
	defer kpNat.Close()

	krpNat, err := link.Kretprobe("nf_nat_setup_info", bpfObj.Kr_natSetUpInfo, nil)
	if err != nil {
		panic(err)
	}
	defer krpNat.Close()

	go func() {
		for {
			var (
				key uint64
				val []byte
			)
			for bpfObj.netfilterMaps.NfConnBuf.Iterate().Next(&key, &val) {
				if err := bpfObj.netfilterMaps.NfConnBuf.Delete(key); err != nil {
					panic(err)
				}
				var event connEvent
				if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &event); err != nil {
					klog.Warningf("failed to decode event: %v", err)
					continue
				}
				if event.Sport == 9095 || event.Dport == 9095 || event.Sport == 9529 || event.Dport == 9529 {
					klog.Infof("original srcIP: %s, original srcPort: %d, original dstIP: %s, original dstPort: %d, reply srcIP: %s, reply srcPort: %d, reply dstIP: %s, reply dstPort: %d",
						net.IP(event.OriSrc[:4]), event.OriSport, net.IP(event.OriDst[:4]), event.OriDport, net.IP(event.Src[:4]), event.Sport, net.IP(event.Dst[:4]), event.Dport)
				}
			}
		}
	}()

	for {
		var (
			key uint64
			val []byte
		)
		for bpfObj.netfilterMaps.EventBuf.Iterate().Next(&key, &val) {
			if err := bpfObj.netfilterMaps.EventBuf.Delete(key); err != nil {
				panic(err)
			}
			var event perfEvent
			if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &event); err != nil {
				klog.Warningf("failed to decode event: %v", err)
				continue
			}
			if event.Sport == 9095 || event.Dport == 9095 || event.Sport == 9529 || event.Dport == 9529 {
				klog.Infof(event.output())
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func _NetfilterClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func loadNetfilter() (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(GetEBPFProg()))
	if err != nil {
		return nil, fmt.Errorf("can't load netfilter: %w", err)
	}

	return spec, err
}

func loadNetfilterObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadNetfilter()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

type netfilterSpecs struct {
	netfilterProgramSpecs
	netfilterMapSpecs
}

type netfilterProgramSpecs struct {
	K_iptDoTable *ebpf.ProgramSpec `ebpf:"kprobe_ipt_do_table"`
	KrIptDoTable *ebpf.ProgramSpec `ebpf:"kretprobe_ipt_do_table"`
	//K_ipForward     *ebpf.ProgramSpec `ebpf:"kprobe_ip_forward"`
	//Kr_ipForward    *ebpf.ProgramSpec `ebpf:"kretprobe_ip_forward"`
	K_natSetUpInfo  *ebpf.ProgramSpec `ebpf:"kprobe_nf_nat_setup_info"`
	Kr_natSetUpInfo *ebpf.ProgramSpec `ebpf:"kretprobe_nf_nat_setup_info"`
}

type netfilterMapSpecs struct {
	EventBuf *ebpf.MapSpec `ebpf:"event_buf"`
	IptMaps  *ebpf.MapSpec `ebpf:"ipt_maps"`
	//IpRcvMaps  *ebpf.MapSpec `ebpf:"ip_rcv_maps"`
	NfConnMaps *ebpf.MapSpec `ebpf:"conn_maps"`
	NfConnBuf  *ebpf.MapSpec `ebpf:"nf_conn_maps"`
}

type netfilterObjects struct {
	netfilterPrograms
	netfilterMaps
}

func (o *netfilterObjects) Close() error {
	return _NetfilterClose(
		&o.netfilterPrograms,
		&o.netfilterMaps,
	)
}

type netfilterMaps struct {
	EventBuf *ebpf.Map `ebpf:"event_buf"`
	IptMaps  *ebpf.Map `ebpf:"ipt_maps"`
	//IpRcvMaps  *ebpf.Map `ebpf:"ip_rcv_maps"`
	NfConnMaps *ebpf.Map `ebpf:"conn_maps"`
	NfConnBuf  *ebpf.Map `ebpf:"nf_conn_maps"`
}

func (m *netfilterMaps) Close() error {
	return _NetfilterClose(
		m.EventBuf,
		m.IptMaps,
		//m.IpRcvMaps,
		m.NfConnMaps,
		m.NfConnBuf,
	)
}

type netfilterPrograms struct {
	K_iptDoTable *ebpf.Program `ebpf:"kprobe_ipt_do_table"`
	KrIptDoTable *ebpf.Program `ebpf:"kretprobe_ipt_do_table"`
	//K_ipFroward     *ebpf.Program `ebpf:"kprobe_ip_forward"`
	//Kr_ipFroward    *ebpf.Program `ebpf:"kretprobe_ip_forward""`
	K_natSetUpInfo  *ebpf.Program `ebpf:"kprobe_nf_nat_setup_info"`
	Kr_natSetUpInfo *ebpf.Program `ebpf:"kretprobe_nf_nat_setup_info"`
}

func (p *netfilterPrograms) Close() error {
	return _NetfilterClose(
		p.K_iptDoTable,
		p.KrIptDoTable,
		//p.K_ipFroward,
		//p.Kr_ipFroward,
		p.K_natSetUpInfo,
		p.Kr_natSetUpInfo,
	)
}
