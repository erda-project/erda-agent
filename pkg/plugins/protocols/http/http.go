package http

import (
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/erda-project/erda-infra/base/logs"
	"github.com/erda-project/erda-infra/base/servicehub"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/ebpf"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/meta"
)

// TODO: go:embed http.bpf.o
type provider struct {
	Log          logs.Logger
	ch           chan ebpf.Metric
	kprobeHelper kprobe.Interface
	meta         meta.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.ch = make(chan ebpf.Metric, 100)
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.meta = meta.New(p.Log, p.kprobeHelper)
	return nil
}

func (p *provider) Gather(c chan metric.Metric) {
	vethes, err := p.kprobeHelper.GetVethes()
	if err != nil {
		p.Log.Fatalf("failed to get vethes, err: %v", err)
	}

	p.Log.Debugf("get vethes: %+v", vethes)

	for _, v := range vethes {
		var (
			lName  = v.Link.Attrs().Name
			lIndex = v.Link.Attrs().Index
			nIP    = v.Neigh.IP.String()
		)
		e := ebpf.New(p.Log, lIndex, nIP, p.ch)
		defer e.Close()
		p.Log.Infof("gonna to load ebpf program for veth: %s (index: %d), ip: %s", lName, lIndex, nIP)
		if err := e.Load(); err != nil {
			p.Log.Fatalf("failed to load ebpf program, err: %v", err)
		}
	}

	go func() {
		defer func() {
			if err := recover(); err != nil {
				p.Log.Errorf("panic: %v", err)
				p.Log.Errorf("stack: %s", string(debug.Stack()))
			}
		}()

		for {
			select {
			case m := <-p.ch:
				export := p.meta.Convert(&m)
				if export != nil {
					p.Log.Infof("recive metric: %+v", export.String())
				}
			}
		}
	}()

	// ctrl c singal
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM)
	<-s
}

func init() {
	servicehub.Register("http", &servicehub.Spec{
		Services:     []string{"http"},
		Description:  "ebpf for http",
		Dependencies: []string{},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
