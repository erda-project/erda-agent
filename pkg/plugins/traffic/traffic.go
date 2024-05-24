package traffic

import (
	"strconv"
	"time"

	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/traffic/controller"
	"github.com/erda-project/ebpf-agent/pkg/plugins/traffic/ebpf"
	"github.com/erda-project/ebpf-agent/pkg/plugins/traffic/red"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type provider struct {
	ch               chan ebpf.Metric
	trafficCollector *controller.Controller
	kprobeHelper     kprobe.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.ch = make(chan ebpf.Metric, 100)
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	return nil
}

func (p *provider) Gather(c chan *metric.Metric) {
	control := controller.NewController(p.ch, p.kprobeHelper)
	control.Run()
	redMetric := make(map[string]red.RED)
	calTicker := time.NewTicker(60 * time.Second)
	for {
		select {
		case m := <-p.ch:
			isErr := 0
			codeNum, _ := strconv.Atoi(m.Code)
			if codeNum > 499 {
				isErr = 1
			}
			if v, ok := redMetric[m.PodName]; ok {
				v.RequestCount += 1
				v.ErrCount += isErr
				v.DurationCount += int(m.Duration)
				redMetric[m.PodName] = v
			} else {
				redMetric[m.PodName] = red.RED{
					PodName:       m.PodName,
					NodeName:      m.NodeName,
					NameSpace:     m.NameSpace,
					ServiceName:   m.NameSpace,
					RequestCount:  1,
					ErrCount:      isErr,
					DurationCount: int(m.Duration),
				}
			}
			c <- m.CovertMetric()
		case <-calTicker.C:
			for k, v := range redMetric {
				v.QPS = float32(v.RequestCount) / 60
				v.ErrRate = float32(v.ErrCount) / float32(v.RequestCount) * 100
				v.Duration = float32(v.DurationCount) / float32(v.RequestCount)
				c <- v.CovertMetric()
				delete(redMetric, k)
			}
			klog.Infof("redmetric map is empty %+v", redMetric)
		}
	}
}

func init() {
	servicehub.Register("traffic", &servicehub.Spec{
		Services:     []string{"traffic"},
		Description:  "ebpf for traffic",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
