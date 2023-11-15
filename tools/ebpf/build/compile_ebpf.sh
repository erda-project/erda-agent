#!/bin/bash

set -o errexit -o pipefail

mkdir -p target

PLUGINS_PATH="ebpf/plugins"
KERNEL_VERSION=${KERNEL_VERSION}

INCLUDE_FLAGS=(
    -I/lib/modules/${KERNEL_VERSION}/build/include
    -I/lib/modules/${KERNEL_VERSION}/build/include/uapi
    -I/lib/modules/${KERNEL_VERSION}/build/include/generated/uapi
    -I/lib/modules/${KERNEL_VERSION}/build/arch/x86/include
    -I/lib/modules/${KERNEL_VERSION}/build/arch/x86/include/uapi
    -I/lib/modules/${KERNEL_VERSION}/build/arch/x86/include/generated
    -I/usr/src/linux-headers-${KERNEL_VERSION}/include
    -I/usr/src/linux-headers-${KERNEL_VERSION}/include/uapi
    -I/usr/src/linux-headers-${KERNEL_VERSION}/include/generated/uapi
    -I/usr/src/linux-headers-${KERNEL_VERSION}/arch/x86/include
    -I/usr/src/linux-headers-${KERNEL_VERSION}/arch/x86/include/uapi
    -I/usr/src/linux-headers-${KERNEL_VERSION}/arch/x86/include/generated
    -I/lib/gcc/x86_64-linux-gnu/12/include
)

DEFINES=(
    -D__TARGET_ARCH_x86
    -D__KERNEL__
    -D__ASM_SYSREG_H
    -DCONFIG_64BIT
    -DBUILD_FALCO_MODERN_BPF=True
    -D__BPF_TRACING__
)

COMPILER_FLAGS=(
    -Wno-unused-value
    -Wno-unused-variable
    -Wno-unused-function
    -gdwarf
    -Wall
    -Wno-address-of-packed-member
    -Wno-frame-address
    -Wno-macro-redefined
    -Wno-incompatible-pointer-types
    -Wno-gnu-variable-sized-type-not-at-end
    -Werror
    -Wno-compare-distinct-pointer-types
    -objc-arc-contract
    -ggdb
    -O2
)

for plugin in $(ls $PLUGINS_PATH)
do
    clang "${INCLUDE_FLAGS[@]}" "${DEFINES[@]}" "${COMPILER_FLAGS[@]}" \
        -emit-llvm -Xclang -disable-llvm-passes \
        -c $PLUGINS_PATH/"$plugin"/main.c -o - | opt -O2 -mtriple=bpf-pc-linux | \
        llvm-dis | llc -march=bpf -mcpu=probe -filetype=obj -o target/"$plugin".bpf.o
done
