package memory

import (
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/memory/controller"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	memoryController controller.Controller
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.memoryController = controller.NewController()
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.memoryController.Start(c)
}

func init() {
	servicehub.Register("memory", &servicehub.Spec{
		Services:     []string{"memory"},
		Description:  "ebpf for memory",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
