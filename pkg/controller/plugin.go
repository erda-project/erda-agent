package controller

import "github.com/erda-project/erda-agent/metric"

type Plugin interface {
	Gather(c chan *metric.Metric)
}
