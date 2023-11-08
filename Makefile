ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
PROGRAM = main
IMAGE_TAG = $(shell date '+%Y%m%d%H%M%S')

build:
	sh tools/ebpf/build/build.sh
	CC=$(CLANG) \
		CGO_ENABLED=0 \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
                go build \
                -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
                -o $(PROGRAM) ./*.go

# docker run -it  --network=host --privileged 562363fe10a4 bash
image: build
	docker build -t "registry.erda.cloud/erda/ebpf-agent:1.0-$(IMAGE_TAG)" -f tools/agent/Dockerfile .
run:
	sudo ./main
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
clean:
	rm -rf main
	rm -rf target