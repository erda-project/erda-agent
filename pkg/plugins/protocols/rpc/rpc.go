package rpc

import (
	"github.com/vishvananda/netlink"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/rpc/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	ch chan ebpf.Metric
}

func (p *provider) Init() error {
	p.ch = make(chan ebpf.Metric, 100)
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	links, err := netlink.LinkList()
	if err != nil {
		panic(err)
	}
	for _, link := range links {
		if link.Type() != "device" && link.Attrs().Index != 2 {
			continue
		}
		go func(l netlink.Link) {
			proj := ebpf.NewEbpf(l.Attrs().Index, p.ch)
			proj.Load()
		}(link)
	}
	for {
		select {
		case m := <-p.ch:
			klog.Infof("rpc metric: %+v", m)
		}
	}
}

func init() {
	servicehub.Register("rpc", &servicehub.Spec{
		Services:     []string{"rpc"},
		Description:  "ebpf for rpc",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
