package main

import (
	_ "embed"
	_ "net/http/pprof"

	_ "github.com/erda-project/ebpf-agent/pkg/controller"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/memory"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/traffic"
	"github.com/erda-project/erda-infra/base/servicehub"
)

//go:embed bootstrap.yaml
var bootstrapCfg string

func main() {
	hub := servicehub.New()
	hub.RunWithOptions(&servicehub.RunOptions{
		Content: bootstrapCfg,
	})
}
