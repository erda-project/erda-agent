FROM registry.erda.cloud/retag/ubuntu:22.04

ARG KERNEL_VERSION

RUN apt update  && \
    apt -y --no-install-recommends install libssl-dev dkms bc build-essential git make libelf-dev clang llvm strace \
    tar bpfcc-tools gcc-multilib libbpf-dev linux-headers-${KERNEL_VERSION} flex bison curl ca-certificates