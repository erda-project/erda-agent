#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/string.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/types.h>

#include "../../../../include/bpf_endian.h"
#include "../../../../include/bpf_traffic_helpers.h"
#include "../../../../include/common.h"
#include "../../../../include/protocol.h"
#include "./types.h"

struct bpf_map_def SEC("maps/filter_map") filter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps/http_processing_map") http_processing_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(sock_key),
    .value_size = sizeof(http_info_t),
    .max_entries = 1024 * 16,
};

struct bpf_map_def SEC("maps/metrics_map") metrics_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(sock_key),
	.value_size = sizeof(http_info_t),
	.max_entries = 1024 * 16,
};

static __always_inline __u8 char_to_u8(char c) {
    if (c < '0' || c > '9')
        return -1;

    return c - '0';
}

static __always_inline __u16 read_status_code(char const *payload) {
    return char_to_u8(payload[HTTP_STATUS_OFFSET]) * 100 +
           char_to_u8(payload[HTTP_STATUS_OFFSET + 1]) * 10 +
           char_to_u8(payload[HTTP_STATUS_OFFSET + 2]);
}

static __always_inline void load_http_payload_prefix(struct __sk_buff *skb, __u32 *offset, http_method_t *method, http_phase_t *phase) {
    if ((skb->len - *offset) <= HTTP_PAYLOAD_PREFIX_SIZE) {
        return;
    }

    char p[HTTP_PAYLOAD_PREFIX_SIZE];
    bpf_skb_load_bytes(skb, *offset, p, HTTP_PAYLOAD_PREFIX_SIZE);

    // Response phase
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        *phase = HTTP_RESPONSE;
        return;
    }

    // Request phase
    *phase = HTTP_REQUEST;
    if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) {
        *method = HTTP_GET;
        *offset += 4;
    } else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') && (p[5] == '/')) {
        *method = HTTP_POST;
        *offset += 5;
    } else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) {
        *method = HTTP_PUT;
        *offset += 4;
    } else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) {
        *method = HTTP_DELETE;
        *offset += 7;
    } else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') && (p[5] == '/')) {
        *method = HTTP_HEAD;
        *offset += 5;
    } else if ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7] == ' ') && ((p[8] == '/') || (p[8] == '*'))) {
        *method = HTTP_OPTIONS;
        *offset += 8;
    } else if ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5] == ' ') && (p[6] == '/')) {
        *method = HTTP_PATCH;
        *offset += 6;
    }
}

static __always_inline void load_http_payload(struct __sk_buff *skb, __u32 offset, void *to) {
    __u32 const end_offset = HTTP_PAYLOAD_SIZE < (skb->len - offset) ? (offset + HTTP_PAYLOAD_SIZE) : skb->len;

    if (offset == end_offset) {
        return;
    }

    __u8 i = 0;
#pragma unroll(HTTP_PAYLOAD_SIZE / HTTP_PAYLOAD_BLOCK_SIZE)
    for (; i < (HTTP_PAYLOAD_SIZE / HTTP_PAYLOAD_BLOCK_SIZE); i++) {
        if (offset + HTTP_PAYLOAD_BLOCK_SIZE > end_offset) {
            break;
        }

        bpf_skb_load_bytes(skb, offset, &to[i * HTTP_PAYLOAD_BLOCK_SIZE], HTTP_PAYLOAD_BLOCK_SIZE);
        offset += HTTP_PAYLOAD_BLOCK_SIZE;
    }

    void *buf = &to[i * HTTP_PAYLOAD_BLOCK_SIZE];
    if (i * HTTP_PAYLOAD_BLOCK_SIZE >= HTTP_PAYLOAD_SIZE) {
        return;
    } else if (offset + 14 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 15);
    } else if (offset + 13 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 14);
    } else if (offset + 12 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 13);
    } else if (offset + 11 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 12);
    } else if (offset + 10 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 11);
    } else if (offset + 9 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 10);
    } else if (offset + 8 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 9);
    } else if (offset + 7 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 8);
    } else if (offset + 6 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 7);
    } else if (offset + 5 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 6);
    } else if (offset + 4 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 5);
    } else if (offset + 3 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 4);
    } else if (offset + 2 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 3);
    } else if (offset + 1 < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 2);
    } else if (offset < end_offset) {
        bpf_skb_load_bytes(skb, offset, buf, 1);
    }
}

static __always_inline void compose_conn_key(sock_key *k, conn_tuple_t *conn_tuple, http_phase_t phase) {
    #define SELECT_IP(proto, saddr, daddr) \
        do { \
            if (k != NULL) { \
                 switch (proto) { \
                    case ETH_P_IP: \
                        k->srcIP = (saddr##_l); \
                        k->dstIP = (daddr##_l); \
                        break; \
                    case ETH_P_IPV6: \
                        k->srcIP = (saddr##_h); \
                        k->dstIP = (daddr##_h); \
                        break; \
                    default: \
                        return; \
                } \
            }\
        } while (0)
    
    switch (phase) {
        case HTTP_REQUEST: {
            SELECT_IP(conn_tuple->l3_proto, conn_tuple->saddr, conn_tuple->daddr);
            k->srcPort = conn_tuple->sport;
            k->dstPort = conn_tuple->dport;
            break;
        }
        case HTTP_RESPONSE: {
            SELECT_IP(conn_tuple->l3_proto, conn_tuple->daddr, conn_tuple->saddr);
            k->srcPort = conn_tuple->dport;
            k->dstPort = conn_tuple->sport;
            break;
        }
        default:
            return;
    }

    return;
}

static __always_inline void read_http_info(struct __sk_buff *skb, conn_tuple_t *conn_tuple, __u32 offset) {
    http_info_t http_info = {0};

    // Load payload prefix
    http_method_t method=HTTP_METHOD_UNKNOWN;
    http_phase_t phase=HTTP_PHASE_UNKNOWN;
    load_http_payload_prefix(skb, &offset, &method, &phase);

    // Load payload.
    load_http_payload(skb, offset, http_info.request_fragment);

    char *payload = &http_info.request_fragment;

    // Generate process conn tunple key with phase.
    sock_key conn_key = {};
    compose_conn_key(&conn_key, conn_tuple, phase);

    // Logical processing based on the phase.
    switch (phase) {
        case HTTP_REQUEST: {
//            if (bpf_map_lookup_elem(&filter_map, &conn_key.srcIP) == NULL) {
//                return;
//            }

            if (method == HTTP_METHOD_UNKNOWN) {
                return;
            }
            
            http_info.method = method;
            __u64 start_ts = bpf_ktime_get_ns();
            http_info.request_ts = start_ts;
            // Update process map.
            bpf_map_update_elem(&http_processing_map, &conn_key, &http_info, BPF_ANY);
            break;
        }
        case HTTP_RESPONSE: {
            http_info_t *http_processing = bpf_map_lookup_elem(&http_processing_map, &conn_key);
            if (!http_processing) {
                return;
            }

            __u64 duration = bpf_ktime_get_ns() - http_processing->request_ts;
            if (duration > 0) {
                http_processing->duration = duration;
            }

            http_processing->status_code = read_status_code(payload);
            // Cleanup.
            bpf_map_delete_elem(&http_processing_map, &conn_key);

            // Update metrics map
            bpf_map_update_elem(&metrics_map, &conn_key, http_processing, BPF_ANY);
            break;
        }
        case HTTP_PHASE_UNKNOWN:
            return;
        default:
            return;
    }
}
