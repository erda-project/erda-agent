package memory

import (
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/memory/controller"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	memoryController controller.Controller
	kprobeHelper     kprobe.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.memoryController = controller.NewController(p.kprobeHelper)
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.memoryController.Start(c)
}

func init() {
	servicehub.Register("memory", &servicehub.Spec{
		Services:     []string{"memory"},
		Description:  "ebpf for memory",
		Dependencies: []string{"kprobe"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
