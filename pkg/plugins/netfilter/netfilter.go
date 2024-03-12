package netfilter

import (
	"github.com/erda-project/ebpf-agent/metric"
	netebpf "github.com/erda-project/ebpf-agent/pkg/plugins/netfilter/ebpf"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct{}

func (p *provider) Init(ctx servicehub.Context) error {
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	//eBPFprogram := netebpf.GetEBPFProg()
	//spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(eBPFprogram))
	//if err != nil {
	//	panic(err)
	//}
	//proj := netebpf.NewEbpf()
	//if err := proj.Load(spec); err != nil {
	//	panic(err)
	//}
	go netebpf.RunEbpf()
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
