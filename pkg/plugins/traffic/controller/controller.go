package controller

import (
	_ "net/http/pprof"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"

	"github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	ebpf2 "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http/ebpf"
	"github.com/erda-project/ebpf-agent/pkg/plugins/traffic/ebpf"
)

type Controller struct {
	stopper      chan struct{}
	ch           chan ebpf.Metric
	ebpfs        map[int]ebpf2.Interface
	kprobeHelper kprobe.Interface
}

func NewController(ch chan ebpf.Metric, kprobeHelper kprobe.Interface) *Controller {
	return &Controller{
		ch:           ch,
		ebpfs:        make(map[int]ebpf2.Interface),
		kprobeHelper: kprobeHelper,
	}
}
func (c *Controller) Run() {
	defer runtime.HandleCrash()

	ch := make(chan ebpf2.Metric, 100)
	vethes, err := c.kprobeHelper.GetVethes()
	if err != nil {
		panic(err)
	}
	for _, veth := range vethes {
		ebpfProvider := ebpf2.New(veth.Link.Attrs().Index, veth.Neigh.IP.String(), ch)
		if err := ebpfProvider.Load(); err != nil {
			klog.Errorf("failed to load ebpf, err: %v", err)
			continue
		}
		c.ebpfs[veth.Link.Attrs().Index] = ebpfProvider
	}
	//ebpfProvider := ebpf2.New(1, "127.0.0.1", ch)
	//if err := ebpfProvider.Load(); err != nil {
	//	panic(err)
	//}
	go func() {
		for {
			select {
			case m := <-ch:
				klog.Infof("metric: %v", m)
			}
		}
	}()
	vethEvents := c.kprobeHelper.RegisterNetLinkListener()
	go func() {
		for {
			select {
			case event := <-vethEvents:
				switch event.Type {
				case kprobe.LinkAdd:
					klog.Infof("veth add, index: %d, ip: %s", event.Link.Attrs().Index, event.Neigh.IP.String())
					ebpfProvider := ebpf2.New(event.Link.Attrs().Index, event.Neigh.IP.String(), ch)
					if err := ebpfProvider.Load(); err != nil {
						klog.Errorf("failed to load ebpf, err: %v", err)
						continue
					}
					c.ebpfs[event.Link.Attrs().Index] = ebpfProvider
				case kprobe.LinkDelete:
					klog.Infof("veth del, index: %d", event.Link.Attrs().Index)
					ebpfProvider, ok := c.ebpfs[event.Link.Attrs().Index]
					if ok {
						ebpfProvider.Close()
						delete(c.ebpfs, event.Link.Attrs().Index)
					}
				default:
					klog.Infof("unknown event type: %v", event.Type)
				}
			}
		}
	}()
}
