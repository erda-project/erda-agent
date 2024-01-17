#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/string.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/types.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>

enum package_phase {
	P_REQUEST = 1,
	P_RESPONSE = 2,
};

enum eth_ip_type {
    ETH_TYPE_IPV4 = 0,
    ETH_TYPE_IPV6 = 1,
};

#define MAX_HTTP2_PATH_CONTENT_LENGTH 50
#define MAX_HTTP2_STATUS_HEADER_LENGTH 1

struct grpc_package_t {
	__u32 phase;
	__u32 ip_type;
	__u32 dstIP;
    __u32 dstPort;
    __u32 srcIP;
	__u32 srcPort;
	__u32 seq;
	//packge的产生时间
	__u32 duration;
	__u32 pid;
	__u8 path_len;
	char path[MAX_HTTP2_PATH_CONTENT_LENGTH];
	char status[MAX_HTTP2_STATUS_HEADER_LENGTH];
};

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

#define HTTP2_FRAME_HEADER_SIZE 9
#define HTTP2_SETTINGS_SIZE 6

#define HTTP2_MARKER_SIZE 24

#define GRPC_MAX_FRAMES_TO_FILTER 10
#define GRPC_MAX_FRAMES_TO_PROCESS 1
#define GRPC_MAX_HEADERS_TO_PROCESS 10

#define GRPC_ENCODED_CONTENT_TYPE "\x1d\x75\xd0\x62\x0d\x26\x3d\x4c\x4d\x65\x64"
#define GRPC_CONTENT_TYPE_LEN (sizeof(GRPC_ENCODED_CONTENT_TYPE) - 1)

#define TCP_FLAGS_OFFSET 13

#define HTTP2_CONTENT_TYPE_IDX 31
#define HTTP2_PATH_HEADER_IDX 5
#define HTTP2_STATUS_HEADER_IDX 8

typedef enum
{
    // Connection type
    CONN_TYPE_UDP = 0,
    CONN_TYPE_TCP = 1,

    // Connection family
    CONN_V4 = 0 << 1,
    CONN_V6 = 1 << 1,
} metadata_mask_t;

typedef struct {
    __u32 offset;
    __u32 length;
} frame_info_t;

typedef enum {
    kDataFrame          = 0,
    kHeadersFrame       = 1,
    kPriorityFrame      = 2,
    kRSTStreamFrame     = 3,
    kSettingsFrame      = 4,
    kPushPromiseFrame   = 5,
    kPingFrame          = 6,
    kGoAwayFrame        = 7,
    kWindowUpdateFrame  = 8,
    kContinuationFrame  = 9,
} __attribute__ ((packed)) frame_type_t;

struct http2_frame {
    __u32 length : 24;
    frame_type_t type;
    __u8 flags;
    __u8 reserved : 1;
    __u32 stream_id : 31;
} __attribute__ ((packed));

typedef enum {
    PAYLOAD_UNDETERMINED,
    PAYLOAD_GRPC,
    PAYLOAD_NOT_GRPC,
} grpc_status_t;

typedef union {
    struct {
        __u8 index : 7;
        __u8 reserved : 1;
    } __attribute__((packed)) indexed;
    struct {
        __u8 index : 6;
        __u8 reserved : 2;
    } __attribute__((packed)) literal;
    __u8 raw;
} __attribute__((packed)) field_index;

typedef struct {
    /* Using the type unsigned __int128 generates an error in the ebpf verifier */
    __u64 saddr_h;
    __u64 saddr_l;
    __u64 daddr_h;
    __u64 daddr_l;
    __u16 sport;
    __u16 dport;
    __u32 netns;
    __u32 pid;
    __u16 l3_proto;
    // Metadata description:
    // First bit indicates if the connection is TCP (1) or UDP (0)
    // Second bit indicates if the connection is V6 (1) or V4 (0)
    __u32 metadata; // This is that big because it seems that we atleast need a 32-bit aligned struct
} conn_tuple_t;

typedef struct {
    __u32 dstIP;
    __u32 dstPort;
    __u32 srcIP;
    __u32 srcPort;
} sock_key;

typedef struct {
    __u32 data_off;
    __u32 data_end;
    __u32 tcp_seq;
    __u8 tcp_flags;
} skb_info_t;

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
    __u16 frag_off;

    bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
    frag_off = __bpf_ntohs(frag_off);
    return frag_off & (IP_MF | IP_OFFSET);
}

static __always_inline void skip_literal_header(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, __u8 idx) {
    string_literal_header len;
    if (skb_info->data_off + sizeof(len) > frame_end) {
        return;
    }

    bpf_skb_load_bytes(skb, skb_info->data_off, &len, sizeof(len));
    skb_info->data_off += sizeof(len) + len.length;

    // If the index is zero, that means the header name is not indexed, so we
    // have to skip both the name and the index.
    if (!idx && skb_info->data_off + sizeof(len) <= frame_end) {
        bpf_skb_load_bytes(skb, skb_info->data_off, &len, sizeof(len));
        skb_info->data_off += sizeof(len) + len.length;
    }

    return;
}


static __always_inline bool is_empty_frame_header(const char *frame) {
#define EMPTY_FRAME_HEADER "\0\0\0\0\0\0\0\0\0"

    return !bpf_memcmp(frame, EMPTY_FRAME_HEADER, sizeof(EMPTY_FRAME_HEADER) - 1);
}

#define is_indexed(x) ((x) & (1 << 7))
#define is_literal(x) ((x) & (1 << 6))

static __always_inline bool is_encoded_grpc_content_type(const char *content_type_buf) {
    return !bpf_memcmp(content_type_buf, GRPC_ENCODED_CONTENT_TYPE, GRPC_CONTENT_TYPE_LEN);
}

static __always_inline void get_path(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, field_index *idx, struct grpc_package_t *pkg) {
    // We only care about indexed names
    if (idx->literal.index != HTTP2_PATH_HEADER_IDX) {
        return;
    }

    string_literal_header len;
    if (skb_info->data_off + sizeof(len) > frame_end) {
        return;
    }

    bpf_skb_load_bytes(skb, skb_info->data_off, &len, sizeof(len));
    pkg->path_len = len.length+sizeof(idx->raw);

    bpf_skb_load_bytes(skb, skb_info->data_off-sizeof(idx->raw), pkg->path, MAX_HTTP2_PATH_CONTENT_LENGTH);

    return;
}

static __always_inline void get_status(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, field_index *idx, struct grpc_package_t *pkg) {
    // We only care about indexed names
    if (idx->literal.index != HTTP2_STATUS_HEADER_IDX) {
        return;
    }

    string_literal_header len;
    if (skb_info->data_off + sizeof(len) > frame_end) {
        return;
    }

    bpf_skb_load_bytes(skb, skb_info->data_off, &len, sizeof(len));

    bpf_skb_load_bytes(skb, skb_info->data_off-sizeof(idx->raw), pkg->status, MAX_HTTP2_STATUS_HEADER_LENGTH);

    return;
}

static __always_inline void read_ipv6_skb(struct __sk_buff *skb, __u64 off, __u64 *addr_l, __u64 *addr_h) {
    *addr_h |= (__u64)load_word(skb, off) << 32;
    *addr_h |= (__u64)load_word(skb, off + 4);
    *addr_h = bpf_ntohll(*addr_h);

    *addr_l |= (__u64)load_word(skb, off + 8) << 32;
    *addr_l |= (__u64)load_word(skb, off + 12);
    *addr_l = bpf_ntohll(*addr_l);
}

static __always_inline void read_ipv4_skb(struct __sk_buff *skb, __u64 off, __u64 *addr) {
    *addr = load_word(skb, off);
    *addr = bpf_ntohll(*addr) >> 32;
}

static __always_inline bool is_http2_preface(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, HTTP2_MARKER_SIZE);

#define HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    bool match = !bpf_memcmp(buf, HTTP2_PREFACE, sizeof(HTTP2_PREFACE)-1);

    return match;
}

__maybe_unused static __always_inline __u64 read_conn_tuple_skb(struct __sk_buff *skb, skb_info_t *info, conn_tuple_t *tup) {
    bpf_memset(info, 0, sizeof(skb_info_t));
    info->data_off = ETH_HLEN;

    __u16 l3_proto = load_half(skb, offsetof(struct ethhdr, h_proto));
    info->data_end = ETH_HLEN;
    __u8 l4_proto = 0;
    switch (l3_proto) {
    case ETH_P_IP:
    {
        __u8 ipv4_hdr_len = (load_byte(skb, info->data_off) & 0x0f) << 2;
        info->data_end += load_half(skb, info->data_off + offsetof(struct iphdr, tot_len));
        if (ipv4_hdr_len < sizeof(struct iphdr)) {
            return 0;
        }
        l4_proto = load_byte(skb, info->data_off + offsetof(struct iphdr, protocol));
        tup->metadata |= CONN_V4;
        tup->l3_proto = ETH_P_IP;
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, saddr), &tup->saddr_l);
        read_ipv4_skb(skb, info->data_off + offsetof(struct iphdr, daddr), &tup->daddr_l);
        info->data_off += ipv4_hdr_len;
        break;
    }
    case ETH_P_IPV6:
        info->data_end += sizeof(struct ipv6hdr) + load_half(skb, info->data_off + offsetof(struct ipv6hdr, payload_len));
        l4_proto = load_byte(skb, info->data_off + offsetof(struct ipv6hdr, nexthdr));
        tup->metadata |= CONN_V6;
        tup->l3_proto = ETH_P_IPV6;
//        struct ipv6hdr ipv6;
//        bpf_skb_load_bytes(skb, info->data_off, &ipv6, sizeof(ipv6));
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, saddr), &tup->saddr_l, &tup->saddr_h);
        read_ipv6_skb(skb, info->data_off + offsetof(struct ipv6hdr, daddr), &tup->daddr_l, &tup->daddr_h);
        info->data_off += sizeof(struct ipv6hdr);
        break;
    default:
        return 0;
    }

    switch (l4_proto) {
    case IPPROTO_UDP:
        tup->metadata |= CONN_TYPE_UDP;
        tup->sport = load_half(skb, info->data_off + offsetof(struct udphdr, source));
        tup->dport = load_half(skb, info->data_off + offsetof(struct udphdr, dest));
        info->data_off += sizeof(struct udphdr);
        break;
    case IPPROTO_TCP:
        tup->metadata |= CONN_TYPE_TCP;
        tup->sport = load_half(skb, info->data_off + offsetof(struct tcphdr, source));
        tup->dport = load_half(skb, info->data_off + offsetof(struct tcphdr, dest));

        info->tcp_seq = load_word(skb, info->data_off + offsetof(struct tcphdr, seq));
        info->tcp_flags = load_byte(skb, info->data_off + TCP_FLAGS_OFFSET);
        // TODO: Improve readability and explain the bit twiddling below
        info->data_off += ((load_byte(skb, info->data_off + offsetof(struct tcphdr, ack_seq) + 4) & 0xF0) >> 4) * 4;
        break;
    default:
        return 0;
    }

    if ((info->data_end - info->data_off) < 0) {
        return 0;
    }

    return 1;
}

static __always_inline void check_and_skip_magic(const struct __sk_buff *skb, skb_info_t *info) {
    if (info->data_off + HTTP2_MARKER_SIZE >= skb->len) {
        return;
    }

    char buf[HTTP2_MARKER_SIZE];
    bpf_skb_load_bytes(skb, info->data_off, buf, sizeof(buf));
    if (is_http2_preface(buf, sizeof(buf))) {
        info->data_off += HTTP2_MARKER_SIZE;
    }
}

static __always_inline bool read_http2_frame_header(const char *buf, size_t buf_size, struct http2_frame *out) {
    if (buf == NULL) {
        return false;
    }

    if (buf_size < HTTP2_FRAME_HEADER_SIZE) {
        return false;
    }

    if (is_empty_frame_header(buf)) {
        return false;
    }

    // We extract the frame by its shape to fields.
    // See: https://datatracker.ietf.org/doc/html/rfc7540#section-4.1
    *out = *((struct http2_frame*)buf);
    out->length = bpf_ntohl(out->length << 8);
    out->stream_id = bpf_ntohl(out->stream_id << 1);

    return out->type <= kContinuationFrame;
}

static __always_inline grpc_status_t is_content_type_grpc(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, __u8 idx) {
    // We only care about indexed names
    if (idx != HTTP2_CONTENT_TYPE_IDX) {
        return PAYLOAD_UNDETERMINED;
    }

    string_literal_header len;
    if (skb_info->data_off + sizeof(len) > frame_end) {
        return PAYLOAD_NOT_GRPC;
    }

    bpf_skb_load_bytes(skb, skb_info->data_off, &len, sizeof(len));
    skb_info->data_off += sizeof(len);

    // Check if the content-type length allows holding *at least* "application/grpc".
    // The size *can be larger* as some implementations will for example use
    // "application/grpc+protobuf" and we want to match those.
    if (len.length < GRPC_CONTENT_TYPE_LEN) {
        return PAYLOAD_NOT_GRPC;
    }

    char content_type_buf[GRPC_CONTENT_TYPE_LEN];
    bpf_skb_load_bytes(skb, skb_info->data_off, content_type_buf, GRPC_CONTENT_TYPE_LEN);
    skb_info->data_off += len.length;

    return is_encoded_grpc_content_type(content_type_buf) ? PAYLOAD_GRPC : PAYLOAD_NOT_GRPC;
}

static __always_inline grpc_status_t scan_headers(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_length, struct grpc_package_t *pkg) {
    field_index idx;
    grpc_status_t status = PAYLOAD_UNDETERMINED;

    __u32 frame_end = skb_info->data_off + frame_length;
    // Check that frame_end does not go beyond the skb
    frame_end = frame_end < skb->len + 1 ? frame_end : skb->len + 1;

#pragma unroll(GRPC_MAX_HEADERS_TO_PROCESS)
    for (__u8 i = 0; i < GRPC_MAX_HEADERS_TO_PROCESS; ++i) {
        if (skb_info->data_off >= frame_end) {
            break;
        }

        bpf_skb_load_bytes(skb, skb_info->data_off, &idx.raw, sizeof(idx.raw));
        skb_info->data_off += sizeof(idx.raw);
        if (idx.literal.index == HTTP2_PATH_HEADER_IDX) {
            pkg->phase = P_REQUEST;
            get_path(skb, skb_info, frame_end, &idx, pkg);
        }
        if (idx.literal.index == HTTP2_STATUS_HEADER_IDX) {
            get_status(skb, skb_info, frame_end, &idx, pkg);
            pkg->phase = P_RESPONSE;
        }

        if (is_literal(idx.raw)) {
            // Having a literal, with an index pointing to a ":method" key means a
            // request method that is not POST or GET. gRPC only uses POST, so
            // finding a :method here is an indicator of non-GRPC content.
            if (idx.literal.index == kGET || idx.literal.index == kPOST) {
                status = PAYLOAD_NOT_GRPC;
                break;
            }

            status = is_content_type_grpc(skb, skb_info, frame_end, idx.literal.index);
            if (status != PAYLOAD_UNDETERMINED) {
                break;
            }

            skip_literal_header(skb, skb_info, frame_end, idx.literal.index);

            continue;
        }

        // The header is fully indexed, check if it is a :method GET header, in
        // which case we can tell that this is not gRPC, as it uses only POST
        // requests.
        if (is_indexed(idx.raw) && idx.indexed.index == kGET) {
            status = PAYLOAD_NOT_GRPC;
            break;
        }
    }

    return status;
}

static __always_inline grpc_status_t judge_grpc(const struct __sk_buff *skb, const skb_info_t *skb_info, struct grpc_package_t *pkg) {
    grpc_status_t status = PAYLOAD_UNDETERMINED;
    char frame_buf[HTTP2_FRAME_HEADER_SIZE];
    struct http2_frame current_frame;

    frame_info_t frames[GRPC_MAX_FRAMES_TO_PROCESS];
    u32 frames_count = 0;

    // Make a mutable copy of skb_info
    skb_info_t info = *skb_info;

    // Check if the skb starts with the HTTP2 magic, advance the info->data_off
    // to the first byte after it if the magic is present.
    check_and_skip_magic(skb, &info);

    // Loop through the HTTP2 frames in the packet
#pragma unroll(GRPC_MAX_FRAMES_TO_FILTER)
    for (__u8 i = 0; i < GRPC_MAX_FRAMES_TO_FILTER && frames_count < GRPC_MAX_FRAMES_TO_PROCESS; ++i) {
        if (info.data_off + HTTP2_FRAME_HEADER_SIZE > skb->len) {
            break;
        }

        bpf_skb_load_bytes(skb, info.data_off, frame_buf, HTTP2_FRAME_HEADER_SIZE);
        info.data_off += HTTP2_FRAME_HEADER_SIZE;

        if (!read_http2_frame_header(frame_buf, HTTP2_FRAME_HEADER_SIZE, &current_frame)) {
            break;
        }

        if (current_frame.type == kHeadersFrame) {
//            bpf_printk("header frame, offset: %d, length: %d\n", info.data_off, current_frame.length);
            frames[frames_count++] = (frame_info_t){ .offset = info.data_off, .length = current_frame.length };
        }
        if (current_frame.type == kDataFrame) {
            char data_buf[14];
            bpf_skb_load_bytes(skb, info.data_off+current_frame.length, data_buf, sizeof(data_buf));
//            bpf_printk("data frame, offset: %d, length: %d, data: %s\n", info.data_off, current_frame.length, data_buf);
        }

        info.data_off += current_frame.length;
    }

#pragma unroll(GRPC_MAX_FRAMES_TO_PROCESS)
    for (__u8 i = 0; i < GRPC_MAX_FRAMES_TO_PROCESS && status == PAYLOAD_UNDETERMINED; ++i) {
        if (i >= frames_count) {
            break;
        }

        info.data_off = frames[i].offset;

        status = scan_headers(skb, &info, frames[i].length, pkg);
    }

    return status;
}