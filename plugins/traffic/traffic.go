package traffic

import (
	"log"
	"strconv"
	"time"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/plugins"
	"github.com/erda-project/ebpf-agent/plugins/traffic/controller"
	"github.com/erda-project/ebpf-agent/plugins/traffic/ebpf"
	"github.com/erda-project/ebpf-agent/plugins/traffic/red"
)

type Traffic struct{}

func (t *Traffic) Gather(c chan metric.Metric) {
	ch := make(chan ebpf.Metric)
	controller := controller.NewController(ch)
	controller.Run()

	redMetric := make(map[string]red.RED)
	calTicker := time.NewTicker(60 * time.Second)
	for {
		select {
		case m := <-ch:
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
			log.Printf("redmetric map is empty %+v\n", redMetric)
		}
	}
}

func init() {
	plugins.Add("traffic", &Traffic{})
}
