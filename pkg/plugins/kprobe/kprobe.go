package kprobe

import (
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/controller"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/kprobesysctl"
	"github.com/erda-project/erda-infra/base/servicehub"
	corev1 "k8s.io/api/core/v1"
)

type Interface interface {
	GetSysctlStat(pid uint32) (kprobesysctl.SysctlStat, error)
	GetPodByUID(podUID string) (corev1.Pod, error)
}

type provider struct {
	kprobeController controller.Controller
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeController = controller.NewController()
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	p.kprobeController.Start(c)
}

func (p *provider) GetSysctlStat(pid uint32) (kprobesysctl.SysctlStat, error) {
	return p.kprobeController.GetSysctlStat(pid)
}

func (p *provider) GetPodByUID(podUID string) (corev1.Pod, error) {
	return p.kprobeController.GetPodByUID(podUID)
}

func init() {
	servicehub.Register("kprobe", &servicehub.Spec{
		Services:     []string{"kprobe"},
		Description:  "ebpf for kprobe",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
