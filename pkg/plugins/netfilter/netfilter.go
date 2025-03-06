package netfilter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/erda-project/erda-agent/metric"
	netebpf "github.com/erda-project/erda-agent/pkg/plugins/netfilter/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
	"github.com/patrickmn/go-cache"
	"k8s.io/klog"
	"net"
	"time"
)

type Interface interface {
	GetNatInfo(ip string, port uint16) (NatInfo, bool)
}

type provider struct {
	natEbpfMap *ebpf.Map
	natCache   *cache.Cache
}

type NatInfo struct {
	OriDstIP     string
	OriDstPort   uint16
	ReplyDstIP   string
	ReplyDstPort uint16
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.natCache = cache.New(time.Minute, 10*time.Second)
	return nil
}

func (p *provider) GetNatInfo(ip string, port uint16) (NatInfo, bool) {
	natInfo, ok := p.natCache.Get(fmt.Sprintf("%s:%d", ip, port))
	if !ok {
		return NatInfo{}, false
	}
	return natInfo.(NatInfo), true
}

func (p *provider) Gather(c chan *metric.Metric) {
	obj := netebpf.RunEbpf()
	kpNat, err := link.Kprobe("nf_nat_setup_info", obj.K_natSetUpInfo, nil)
	if err != nil {
		panic(err)
	}
	defer kpNat.Close()

	krpNat, err := link.Kretprobe("nf_nat_setup_info", obj.Kr_natSetUpInfo, nil)
	if err != nil {
		panic(err)
	}
	defer krpNat.Close()

	connMap := obj.NfConnBuf
	var (
		key uint64
		val []byte
	)
	for {
		for connMap.Iterate().Next(&key, &val) {
			if err := obj.NfConnBuf.Delete(key); err != nil {
				panic(err)
			}
			var event netebpf.ConnEvent
			if err := binary.Read(bytes.NewReader(val), binary.LittleEndian, &event); err != nil {
				klog.Warningf("failed to decode event: %v", err)
				continue
			}
			srcIP, dstIP := net.IP(event.OriSrc[:4]), net.IP(event.OriDst[:4])
			_, replyDstIP := net.IP(event.Dst[:4]), net.IP(event.Src[:4])
			//klog.Infof("srcIP: %s, srcPort: %d, dstIP: %s, dstPort: %d, reply srcIP :%s, reply dstIP: %s", srcIP, event.OriSport, dstIP, event.OriDport, replySrcIP, replyDstIP)
			natInfo := NatInfo{
				OriDstIP:     dstIP.String(),
				OriDstPort:   event.OriDport,
				ReplyDstIP:   replyDstIP.String(),
				ReplyDstPort: event.Sport,
			}
			p.natCache.Set(fmt.Sprintf("%s:%d", srcIP, event.OriSport), natInfo, time.Minute)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func init() {
	servicehub.Register("netfilter", &servicehub.Spec{
		Services:     []string{"netfilter"},
		Description:  "ebpf for ipt do table",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
