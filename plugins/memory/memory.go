package memory

import (
	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/plugins"
	"github.com/erda-project/ebpf-agent/plugins/memory/controller"
)

func init() {
	plugins.Add("memory", &Memory{})
}

type Memory struct{}

func (m *Memory) Gather(c chan metric.Metric) {
	memoryController := controller.NewController()
	memoryController.Start(c)
}
