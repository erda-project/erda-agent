package controller

import "github.com/erda-project/ebpf-agent/metric"

type Plugin interface {
	Gather(c chan *metric.Metric)
}
