FROM registry.erda.cloud/retag/ubuntu:22.04

ARG KERNEL_VERSION

RUN apt update  && \
    apt -y --no-install-recommends install libssl-dev dkms bc build-essential git make libelf-dev clang llvm strace \
    tar bpfcc-tools gcc-multilib libbpf-dev linux-headers-${KERNEL_VERSION} flex bison curl ca-certificates

RUN curl -k -OL https://golang.google.cn/dl/go1.24.1.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz && \
    rm go1.24.1.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin