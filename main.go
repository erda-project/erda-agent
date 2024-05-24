package main

import (
	_ "embed"
	_ "net/http/pprof"

	_ "github.com/erda-project/ebpf-agent/pkg/controller"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/kprobe"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/memory"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/netfilter"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/http"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/kafka"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/protocols/rpc"
	_ "github.com/erda-project/ebpf-agent/pkg/plugins/traffic"
	"github.com/erda-project/erda-infra/base/servicehub"
)

//go:embed bootstrap.yaml
var bootstrapCfg string

////go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -cc clang netfilter ./ebpf/plugins/netfilter/main.c -- -D__TARGET_ARCH_x86 -I./ebpf/include -Wall

func main() {
	hub := servicehub.New()
	hub.RunWithOptions(&servicehub.RunOptions{
		Content: bootstrapCfg,
	})
}
