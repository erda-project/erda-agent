package http

import (
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/erda-project/ebpf-agent/metric"
	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	"github.com/erda-project/ebpf-agent/pkg/plugins/netfilter"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/ebpf"
	"github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/meta"
	"github.com/erda-project/erda-infra/base/logs"
	"github.com/erda-project/erda-infra/base/servicehub"
)

// TODO: go:embed http.bpf.o
type provider struct {
	sync.RWMutex

	Log          logs.Logger
	ch           chan ebpf.Metric
	kprobeHelper kprobe.Interface
	netNatHelper netfilter.Interface
	meta         meta.Interface
	engines      map[int]ebpf.Interface
}

func (p *provider) Init(ctx servicehub.Context) error {
	p.ch = make(chan ebpf.Metric, 100)
	p.kprobeHelper = ctx.Service("kprobe").(kprobe.Interface)
	p.netNatHelper = ctx.Service("netfilter").(netfilter.Interface)
	p.meta = meta.New(p.Log, p.kprobeHelper, p.netNatHelper)
	p.engines = make(map[int]ebpf.Interface)
	return nil
}

func (p *provider) Gather(c chan *metric.Metric) {
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
		e := ebpf.New(lIndex, nIP, p.ch)
		p.Log.Infof("gonna to load ebpf program for veth: %s (index: %d), ip: %s", lName, lIndex, nIP)
		if err := e.Load(); err != nil {
			p.Log.Fatalf("failed to load ebpf program, err: %v", err)
		}
		p.Lock()
		p.engines[lIndex] = e
		p.Unlock()
	}
	//ebpfProvider := ebpf.New(1, "127.0.0.1", p.ch)
	//if err := ebpfProvider.Load(); err != nil {
	//	panic(err)
	//}

	vethEvents := p.kprobeHelper.RegisterNetLinkListener()
	go func() {
		for {
			select {
			case event := <-vethEvents:
				switch event.Type {
				case kprobe.LinkAdd:
					p.Log.Infof("veth add, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
					ebpfProvider := ebpf.New(event.Link.Attrs().Index, event.Neigh.IP.String(), p.ch)
					if err := ebpfProvider.Load(); err != nil {
						p.Log.Errorf("failed to load ebpf, err: %v", err)
						continue
					}
					p.Lock()
					p.engines[event.Link.Attrs().Index] = ebpfProvider
					p.Unlock()
				case kprobe.LinkDelete:
					p.Log.Infof("veth del, index: %d", event.Link.Attrs().Index)
					p.RLock()
					ebpfProvider, ok := p.engines[event.Link.Attrs().Index]
					p.RUnlock()
					if ok {
						ebpfProvider.Close()
						p.Lock()
						delete(p.engines, event.Link.Attrs().Index)
						p.Unlock()
					}
				default:
					p.Log.Infof("unknown event type: %v", event.Type)
				}
			}
		}
	}()

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
				//p.Log.Infof("recive metric: %+v", m.String())
				export := p.meta.Convert(&m)
				if export != nil {
					p.Log.Infof("recive metric: %+v", export.String())
					c <- export
				}
			}
		}
	}()

	// ctrl c singal
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-s
		p.Close()
	}()
}

func (p *provider) Close() {
	p.Lock()
	for _, e := range p.engines {
		e.Close()
	}
	p.Unlock()

}

func init() {
	servicehub.Register("http", &servicehub.Spec{
		Services:     []string{"http"},
		Description:  "ebpf for http",
		Dependencies: []string{"kprobe", "netfilter"},
		Creator: func() servicehub.Provider {
			return &provider{}
		},
	})
}
