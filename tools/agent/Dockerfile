FROM registry.erda.cloud/erda/ebpf-devel:v0.2 as builder
ARG KERNEL_VERSION
COPY . /app
RUN cd /app && set KERNEL_VERSION=$KERNEL_VERSION && bash -x tools/ebpf/build/compile_ebpf.sh


FROM registry.erda.cloud/retag/alpine:3.18
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=builder /app/main /
COPY --from=builder /app/bootstrap.yaml /
COPY --from=builder /app/target /target

ENTRYPOINT ["/main"]