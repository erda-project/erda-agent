package ebpf

import (
	"bytes"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

func RunEbpf() *NetfilterObjects {
	spec, err := loadNetfilter()
	if err != nil {
		panic(err)
	}
	var bpfObj NetfilterObjects
	if err := spec.LoadAndAssign(&bpfObj, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	}); err != nil {
		panic(err)
	}
	return &bpfObj
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

type NetfilterObjects struct {
	netfilterPrograms
	netfilterMaps
}

func (o *NetfilterObjects) Close() error {
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
