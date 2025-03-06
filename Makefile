ARCH := $(shell uname -m)
ARCH := $(subst x86_64,amd64,$(ARCH))
GOARCH := $(ARCH)
CGO_EXTLDFLAGS_STATIC = '-w -extldflags "-static"'
PROGRAM = main
GOPROXY ?= https://goproxy.cn,direct
PROJ_PATH := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
REGISTRY ?= registry.erda.cloud/erda
KERNEL_VERSION ?= 5.15.0-87-generic
EBPF_DEVEL_VERSION ?= v0.4
IMAGE_TAG = $(shell date '+%Y%m%d%H%M%S')
DOCKER_IMAGE="$(REGISTRY)/ebpf-agent:1.0-$(IMAGE_TAG)"

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

build-ebpf-local: clean
	KERNEL_VERSION=${KERNEL_VERSION} bash -x tools/ebpf/build/compile_ebpf.sh

build-ebpf-agent:
	CC=$(CLANG) \
		CGO_ENABLED=0 \
		CGO_CFLAGS=$(CGO_CFLAGS_STATIC) \
		GOPROXY=$(GOPROXY) \
		CGO_LDFLAGS=$(CGO_LDFLAGS_STATIC) \
                GOARCH=$(GOARCH) \
                go build \
                -tags netgo -ldflags $(CGO_EXTLDFLAGS_STATIC) \
                -o $(PROGRAM) ./*.go

build-ebpf-dvel-image:
	docker buildx build --platform=linux/amd64 -t $(REGISTRY)/ebpf-devel:$(EBPF_DEVEL_VERSION) \
		--build-arg KERNEL_VERSION=$(KERNEL_VERSION) \
		-f tools/ebpf/image/Dockerfile . --push

# docker run -it  --network=host --privileged 562363fe10a4 bash
image:
	docker build --build-arg "KERNEL_VERSION=${KERNEL_VERSION}" -t $(REGISTRY)/ebpf-agent:1.0-$(IMAGE_TAG) \
 		-f tools/agent/Dockerfile .
run:
	sudo ./main
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
clean:
	rm -rf main
	rm -rf target

login:
	docker login -u "${DOCKER_REGISTRY_USERNAME}" -p "${DOCKER_REGISTRY_PASSWORD}" "${DOCKER_REGISTRY}"

buildkit-image:
	buildctl \
        --addr tcp://buildkitd.default.svc.cluster.local:1234 \
        --tlscacert=/.buildkit/ca.pem \
        --tlscert=/.buildkit/cert.pem \
        --tlskey=/.buildkit/key.pem \
         build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile="./tools/agent" \
        --opt label:"branch=$(git rev-parse --abbrev-ref HEAD)" \
        --opt label:"commit=$(git rev-parse HEAD)" \
        --opt label:"build-time=$(date '+%Y-%m-%d %T%z')" \
        --opt build-arg:"KERNEL_VERSION=${KERNEL_VERSION}" \
        --output type=image,name=${DOCKER_IMAGE},push=true
	echo "action meta: image=${DOCKER_IMAGE}"