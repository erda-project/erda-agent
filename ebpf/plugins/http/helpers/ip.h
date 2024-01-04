#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <linux/kconfig.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/string.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/types.h>

#include "../../../include/bpf_endian.h"
#include "../../../include/bpf_traffic_helpers.h"
#include "./conn.h"

/* Helper macro to print out debug messages */
#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

typedef struct {
    __u32 offset;
} skb_reader_t;


static __always_inline __u64 read_conn_info(struct __sk_buff *skb, skb_reader_t *skb_reader, conn_tuple_t *conn_info) {
    __u16 l3_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    skb_reader->offset = ETH_HLEN;

    __u8 l4_proto = load_byte(skb, skb_reader->offset + offsetof(struct iphdr, protocol));
    switch (l3_proto) {
    case ETH_P_IP: {
        struct iphdr iph;
        bpf_skb_load_bytes(skb, skb_reader->offset, &iph, sizeof(iph));

        conn_info->saddr_l = iph.saddr;
        conn_info->daddr_l = iph.daddr;
        
        skb_reader->offset += (iph.ihl << 2);
        break;
    }
    case ETH_P_IPV6: {

    }
    default:
        return 0;
    }

    conn_info->proto = l4_proto;

    switch (l4_proto) {
    case IPPROTO_TCP: 
        {
            struct tcphdr tcph; 
            bpf_skb_load_bytes(skb, skb_reader->offset, &tcph, sizeof(tcph));

            conn_info->sport = bpf_ntohs(tcph.source);
            conn_info->dport = bpf_ntohs(tcph.dest);

            skb_reader->offset += (tcph.doff << 2);
        }
        break;
    // TODO: udp
    // case IPPROTO_UDP:
    default: 
        return 0;
    }

    return 0;
} 