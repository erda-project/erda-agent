FROM ubuntu:22.04

ARG KERNEL_VERSION

RUN apt update  && \
    apt -y --no-install-recommends install libssl-dev dkms bc build-essential git make libelf-dev clang llvm strace \
    tar bpfcc-tools gcc-multilib libbpf-dev linux-headers-${KERNEL_VERSION} flex bison curl

RUN curl -k -OL https://golang.org/dl/go1.22.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && \
    rm go1.22.5.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin