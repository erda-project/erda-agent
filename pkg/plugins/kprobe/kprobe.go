package kprobe

import (
	"sync"
	"time"

	"github.com/erda-project/erda-infra/base/servicehub"
	corev1 "k8s.io/api/core/v1"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/controller"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe/kprobesysctl"
)

type Interface interface {
	GetSysctlStat(pid uint32) (kprobesysctl.SysctlStat, error)
	GetPodByUID(podUID string) (*corev1.Pod, error)
	GetService(ip string) (*corev1.Service, error)
	RegisterNetLinkListener() <-chan NeighLinkEvent
	GetVethes() ([]NeighLink, error)
}

type provider struct {
	sync.RWMutex
	kprobeController controller.Controller
	netLinks         map[int]NeighLink
	netLinkListeners []chan NeighLinkEvent
	ticker           *time.Ticker
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.kprobeController = controller.NewController()
	p.netLinks = make(map[int]NeighLink)
	neighs, err := GetAllVethes()
	if err != nil {
		return err
	}
	for _, neigh := range neighs {
		p.netLinks[neigh.Link.Attrs().Index] = neigh
	}
	return nil
}

func (p *provider) Start() error {
	p.ticker = time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				p.refreshVethes()
			}
		}
	}()
	return nil
}

func (p *provider) Close() error {
	p.ticker.Stop()
	return nil
}

func (p *provider) RegisterNetLinkListener() <-chan NeighLinkEvent {
	p.Lock()
	defer p.Unlock()
	ch := make(chan NeighLinkEvent, 10)
	p.netLinkListeners = append(p.netLinkListeners, ch)
	return ch
}

func (p *provider) GetVethes() ([]NeighLink, error) {
	p.RLock()
	defer p.RUnlock()
	ans := make([]NeighLink, 0)
	for _, v := range p.netLinks {
		ans = append(ans, v)
	}
	return ans, nil
}

func (p *provider) Gather(c chan *metric.Metric) {
	p.kprobeController.Start(c)
}

func (p *provider) GetSysctlStat(pid uint32) (kprobesysctl.SysctlStat, error) {
	return p.kprobeController.GetSysctlStat(pid)
}

func (p *provider) GetPodByUID(podUID string) (*corev1.Pod, error) {
	return p.kprobeController.GetPodByUID(podUID)
}

func (p *provider) GetService(ip string) (*corev1.Service, error) {
	return p.kprobeController.GetService(ip)
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
