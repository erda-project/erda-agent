package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/envconf"
	"github.com/erda-project/ebpf-agent/pkg/exporter/collector"
	"github.com/erda-project/erda-infra/base/servicehub"
)

type Config struct {
	Plugins []string `file:"plugins"`
}

type provider struct {
	sync.Mutex
	Cfg *Config

	ctx             servicehub.Context
	plugins         []Plugin
	collectorClient *collector.ReportClient
	metrics         []*metric.Metric
}

func (p *provider) Init(ctx servicehub.Context) error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	p.ctx = ctx
	p.plugins = make([]Plugin, 0, len(p.Cfg.Plugins))
	p.metrics = make([]*metric.Metric, 0)
	reportConfig := &collector.CollectorConfig{}
	envconf.MustLoad(reportConfig)
	p.collectorClient = collector.CreateReportClient(reportConfig)
	return nil
}

func (p *provider) Run(ctx context.Context) error {
	for _, name := range p.Cfg.Plugins {
		plugin, err := findPlugin(p.ctx, name)
		if err != nil {
			return err
		}
		p.plugins = append(p.plugins, plugin)
	}
	ch := make(chan *metric.Metric, 1000)
	for _, plugin := range p.plugins {
		go plugin.Gather(ch)
	}
	ticker := time.NewTicker(5 * time.Second)
	for {
		select {
		case m := <-ch:
			p.Lock()
			//klog.Infof("metric: %+v", m)
			if m != nil {
				p.metrics = append(p.metrics, m)
			}
			p.Unlock()
		case <-ticker.C:
			p.Lock()
			if len(p.metrics) > 0 {
				if err := p.collectorClient.Send(p.metrics); err != nil {
					klog.Errorf("send metric to %s collector error: %v", p.collectorClient.CFG.ReportConfig.Collector.Addr, err)
					p.Unlock()
					continue
				}
				klog.Infof("send %d metric to %s collector success", len(p.metrics), p.collectorClient.CFG.ReportConfig.Collector.Addr)
				example := p.metrics[0]
				exampleStr, _ := json.Marshal(example)
				klog.Infof("example metric: %s", string(exampleStr))
				p.metrics = make([]*metric.Metric, 0)
			}
			p.Unlock()
		}
	}
	return nil
}

func (p *provider) Close() error {
	return nil
}

func findPlugin(ctx servicehub.Context, name string) (Plugin, error) {
	obj := ctx.Service(name)
	if obj == nil {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	plugin, ok := obj.(Plugin)
	if !ok {
		return nil, fmt.Errorf("item %s is not plugin", name)
	}
	return plugin, nil
}

func init() {
	servicehub.Register("agent.controller", &servicehub.Spec{
		Services: []string{},
		ConfigFunc: func() interface{} {
			return &Config{}
		},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
