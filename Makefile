ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
PROGRAM = main
PROJ_PATH := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
REGISTRY ?= registry.erda.cloud/erda
KERNEL_VERSION ?= 5.15.0-87-generic
EBPF_DEVEL_VERSION ?= v0.2
IMAGE_TAG = $(shell date '+%Y%m%d%H%M%S')

build: build-ebpf build-ebpf-agent

build-ebpf: clean
	docker run --rm \
    	-v ${PROJ_PATH}:/build \
    	-e KERNEL_VERSION=${KERNEL_VERSION} \
    	registry.erda.cloud/erda/ebpf-devel:${EBPF_DEVEL_VERSION} \
    	sh -c " \
    		cd build && \
    		bash -x tools/ebpf/build/compile_ebpf.sh \
    	"

build-ebpf-agent:
	CC=$(CLANG) \
		CGO_ENABLED=0 \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
                go build \
                -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
                -o $(PROGRAM) ./*.go

build-ebpf-dvel-image:
	docker build -t $(REGISTRY)/ebpf-devel:$(EBPF_DEVEL_VERSION) \
		--build-arg KERNEL_VERSION=$(KERNEL_VERSION) \
		-f tools/ebpf/image/Dockerfile .

# docker run -it  --network=host --privileged 562363fe10a4 bash
image: build
	docker build -t $(REGISTRY)/ebpf-agent:1.0-$(IMAGE_TAG) \
 		-f tools/agent/Dockerfile .
run:
	sudo ./main
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
clean:
	rm -rf main
	rm -rf target