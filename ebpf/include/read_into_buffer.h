#ifndef __READ_INTO_BUFFER_H
#define __READ_INTO_BUFFER_H

#include <linux/types.h>
#include <linux/version.h>

#define BLK_SIZE (16)

#define STRINGIFY(a) #a

#define READ_INTO_BUFFER(name, total_size, blk_size)                                                                \
    static __always_inline void read_into_buffer_##name(char *buffer, struct __sk_buff *skb, u32 offset) {          \
        const u32 end = (total_size) < (skb->len - offset) ? offset + (total_size) : skb->len;                      \
        unsigned i = 0;                                                                                             \
                                                                                                                    \
    _Pragma( STRINGIFY(unroll(total_size/blk_size)) )                                                               \
        for (; i < ((total_size) / (blk_size)); i++) {                                                              \
            if (offset + (blk_size) - 1 >= end) { break; }                                                          \
                                                                                                                    \
            bpf_skb_load_bytes(skb, offset, buffer, (blk_size));                                     \
            offset += (blk_size);                                                                                   \
            buffer += (blk_size);                                                                                   \
        }                                                                                                           \
        if ((i * (blk_size)) >= total_size) {                                                                       \
            return;                                                                                                 \
        }                                                                                                           \
        const s64 left_payload = (s64)end - (s64)offset;                                                            \
        if (left_payload < 1) {                                                                                     \
            return;                                                                                                 \
        }                                                                                                           \
                                                                                                                    \
        const s64 read_size = left_payload < (blk_size) - 1 ? left_payload : (blk_size) - 1;                        \
                                                                                                                    \
        const s64 left_buffer = (s64)(total_size) < (s64)(i*(blk_size)) ? 0 : total_size - i*(blk_size);            \
        if (read_size <= left_buffer) {                                                                             \
            bpf_skb_load_bytes(skb, offset, buffer, read_size);                                      \
        }                                                                                                           \
        return;                                                                                                     \
    }                                                                                                               \

#endif
