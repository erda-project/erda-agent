package main

import (
	"context"
	"log"
	"net/http"

	"github.com/erda-project/erda-infra/base/servicehub"
	"k8s.io/klog"
)

type provider struct{}

func (p *provider) Init(ctx servicehub.Context) error {
	return p.Initialize(ctx)
}

func (p *provider) Run(ctx context.Context) error {
	klog.Infof("[alert] starting ebpf agent")
	var err error

	select {
	case <-ctx.Done():
	}
	return err
}

func (p *provider) Initialize(ctx servicehub.Context) error {
	go func() {
		log.Println(http.ListenAndServe("localhost:8777", nil))
	}()
	return nil
}

func init() {
	servicehub.Register("ebpf-agent", &servicehub.Spec{
		Services:     []string{"ebpf-agent"},
		Dependencies: []string{},
		Creator:      func() servicehub.Provider { return &provider{} },
	})
}
