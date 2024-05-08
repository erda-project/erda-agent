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
    P_UNKNOWN = 0,
	P_REQUEST = 1,
	P_RESPONSE = 2,
};

typedef enum {
    PAYLOAD_UNDETERMINED,
    PAYLOAD_GRPC,
    PAYLOAD_NOT_GRPC,
    PAYLOAD_DUBBO,
    PAYLOAD_MYSQL,
    PAYLOAD_REDIS,
} rpc_status_t;

enum dubbo_phase {
    D_REQUEST = 1,
    D_RESPONSE = 0,
};

typedef enum {
    NOT_DUBBO_EVENT = 0,
    IS_DUBBO_EVENT = 1, // Identifies whether it is an event message, for example, a heartbeat event. Set to 1 if this is an event.
} dubbo_event_t;

enum eth_ip_type {
    ETH_TYPE_IPV4 = 0,
    ETH_TYPE_IPV6 = 1,
};

#define MYSQL_ERROR_MESSAGE_MAX_SIZE 10

struct rpc_package_t {
    __u32 rpc_type; // 4
	__u32 phase; // 8
	__u32 ip_type; // 12
	__u32 dstIP; // 16
    __u32 dstPort; // 20
    __u32 srcIP; // 24
	__u32 srcPort; // 28
	__u32 seq; // 32
	//packge的产生时间
	__u32 duration; // 36
	__u32 pid; // 40
	__u8 path_len; // 41
	char path[MAX_HTTP2_PATH_CONTENT_LENGTH]; // 141
	char status[MAX_HTTP2_STATUS_HEADER_LENGTH]; // 142
	__u8 dubbo_status; // 143
	__u16 mysql_status; // 145
	char mysql_msg[MYSQL_ERROR_MESSAGE_MAX_SIZE];
};

#define IP_MF	  0x2000
#define IP_OFFSET 0x1FFF

#define HTTP2_FRAME_HEADER_SIZE 9
#define HTTP2_SETTINGS_SIZE 6

#define HTTP2_MARKER_SIZE 24
#define CLASSIFICATION_MAX_BUFFER (HTTP2_MARKER_SIZE)
#define BLK_SIZE (16)

#define STRINGIFY(a) #a

// mysql
// Each MySQL command starts with mysql_hdr, thus the minimum length is sizeof(mysql_hdr).
#define MYSQL_MIN_LENGTH 5

// Taken from https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
#define MYSQL_COMMAND_QUERY 0x3
// Taken from https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html
#define MYSQL_PREPARE_QUERY 0x16
// Taken from https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html.
#define MYSQL_SERVER_GREETING_V10 0xa
// Taken from https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v9.html.
#define MYSQL_SERVER_GREETING_V9 0x9
#define MYSQL_OK00_RESPONSE 0x0
#define MYSQL_EOF_RESPONSE 0xfe
#define MYSQL_ERR_RESPONSE 0xff
// Represents <digit><digit><dot>
#define MAX_VERSION_COMPONENT 3
// Represents <digit>
#define MIN_BUGFIX_VERSION_COMPONENT 1
// Represents <digit><dot>
#define MIN_MINOR_VERSION_COMPONENT 2
// Minium version string is <digit>.<digit>.<digit>
#define MIN_VERSION_SIZE 5
// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset_column_definition.html#sect_protocol_com_query_response_text_resultset_column_definition_41
#define MYSQL_CATALOG_LOG_SIZE 3
#define MYSQL_OK_STATUS 200

#define SQL_COMMAND_MAX_SIZE 6
#define MYSQL_RESPONSE_MAX_SIZE 10
#define MYSQL_QUERY_MAX_SIZE 30

#define SQL_ALTER "ALTER"
#define SQL_CREATE "CREATE"
#define SQL_DELETE "DELETE"
#define SQL_DROP "DROP"
#define SQL_INSERT "INSERT"
#define SQL_SELECT "SELECT"
#define SQL_UPDATE "UPDATE"
#define SQL_SHOW "SHOW"
#define CATALOG_DEF "def"

// MySQL header format. Starts with 24 bits (3 bytes) of the length of the payload, a one byte of sequence id,
// a one byte to represent the message type.
typedef struct {
    __u32 payload_length:24;
    __u8 seq_id;
    __u8 command_type;
} __attribute__((packed)) mysql_hdr;

typedef struct {
    __u32 err_code;
    __u32 sql_state;
    char msg[MYSQL_ERROR_MESSAGE_MAX_SIZE];
} __attribute__((packed)) mysql_err_hdr;

typedef struct {
    __u32 length;
    __u8 seq_id;
    char catalog[MYSQL_CATALOG_LOG_SIZE];
} __attribute__((packed)) mysql_catalog;

#define check_command(buf, command, buf_size) \
    (!bpf_memcmp((buf), &(command), sizeof(command) - 1))

static __always_inline __u32 is_version_component_helper(const char *buf, __u32 offset, __u32 buf_size, char delimiter) {
    char current_char;
#pragma unroll MAX_VERSION_COMPONENT
    for (unsigned i = 0; i < MAX_VERSION_COMPONENT; i++) {
        if (offset + i >= buf_size) {
            break;
        }
        current_char = buf[offset+i];
        if ('0' <= current_char && current_char <= '9') {
            continue;
        }
        if (current_char == delimiter && i > 0) {
            return i+1;
        }
        // Any other character is not supported.
        break;
   }
   return 0;
}

static __always_inline bool is_version(const char* buf, __u32 buf_size) {
    if (buf_size < MIN_VERSION_SIZE) {
        return false;
    }

    u32 read_size = 0;
    const __u32 major_component_size = is_version_component_helper(buf, 0, buf_size, '.');
    if (major_component_size == 0) {
        return false;
    }
    read_size += major_component_size;

    const __u32 minor_component_size = is_version_component_helper(buf, read_size, buf_size, '.');
    if (minor_component_size == 0) {
        return false;
    }
    read_size += minor_component_size;
    return is_version_component_helper(buf, read_size, buf_size, '\0') > 0;
}

static __always_inline bool is_sql_command(const char *buf, __u32 buf_size, struct rpc_package_t *pkg) {
    char tmp[SQL_COMMAND_MAX_SIZE];

    // Convert what would be the query to uppercase to match queries like
    // 'select * from table'
    #pragma unroll (SQL_COMMAND_MAX_SIZE)
    for (int i = 0; i < SQL_COMMAND_MAX_SIZE; i++) {
        if ('a' <= buf[i] && buf[i] <= 'z') {
            tmp[i] = buf[i] - 'a' +'A';
        } else {
            tmp[i] = buf[i];
        }
    }

    bool is_command = check_command(tmp, SQL_ALTER, buf_size)
        || check_command(tmp, SQL_CREATE, buf_size)
        || check_command(tmp, SQL_DELETE, buf_size)
        || check_command(tmp, SQL_DROP, buf_size)
        || check_command(tmp, SQL_INSERT, buf_size)
        || check_command(tmp, SQL_SELECT, buf_size)
        || check_command(tmp, SQL_UPDATE, buf_size)
        || check_command(tmp, SQL_SHOW, buf_size);

    if (is_command) {
        for (int i = 0; i < MYSQL_QUERY_MAX_SIZE; i++) {
            pkg->path[i] = buf[i];
        }
        pkg->phase = P_REQUEST;
    }
    return is_command;
}

static __always_inline bool is_mysql_err_response(const char *buf, __u32 buf_size, struct rpc_package_t *pkg) {
    mysql_err_hdr header = *((mysql_err_hdr *)buf);
    bool is_response = header.err_code > 0;
    if (is_response) {
        pkg->phase = P_RESPONSE;
        pkg->mysql_status = bpf_ntohs(header.err_code);
        for (int i = 0; i < MYSQL_ERROR_MESSAGE_MAX_SIZE; i++) {
            pkg->mysql_msg[i] = header.msg[i];
        }
    }
    return is_response;
}

static __always_inline bool is_mysql_catalog(const char *buf, __u32 buf_size, struct rpc_package_t *pkg) {
    mysql_catalog log = *((mysql_catalog *)buf);
    bool is_catalog = log.catalog[0] == 'd' && log.catalog[1] == 'e' && log.catalog[2] == 'f';
    if (is_catalog) {
        pkg->phase = P_RESPONSE;
        pkg->mysql_status = MYSQL_OK_STATUS;
    }
    return is_catalog;
}

// end mysql

#define GRPC_MAX_FRAMES_TO_FILTER 10
#define GRPC_MAX_FRAMES_TO_PROCESS 1
#define GRPC_MAX_HEADERS_TO_PROCESS 10

#define GRPC_ENCODED_CONTENT_TYPE "\x1d\x75\xd0\x62\x0d\x26\x3d\x4c\x4d\x65\x64"
#define GRPC_CONTENT_TYPE_LEN (sizeof(GRPC_ENCODED_CONTENT_TYPE) - 1)

#define DUBBO_MAGIC "\xda\xbb"
#define DUBBO_MAGIC_LEN 2

#define DUBBO_REQUEST_DATA_LEN 80
#define DUBBO_RESPONSE_DATA_LEN 20

#define TCP_FLAGS_OFFSET 13

#define HTTP2_CONTENT_TYPE_IDX 31
#define HTTP2_PATH_HEADER_IDX 5
#define HTTP2_STATUS_HEADER_IDX 8

typedef struct {
    char data[CLASSIFICATION_MAX_BUFFER];
    size_t size;
} classification_buffer_t;

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
        /* Calculating the remaining bytes to read. If we have none, then we abort. */                              \
        const s64 left_payload = (s64)end - (s64)offset;                                                            \
        if (left_payload < 1) {                                                                                     \
            return;                                                                                                 \
        }                                                                                                           \
                                                                                                                    \
        /* The maximum that we can read is (blk_size) - 1. Checking (to please the verifier) that we read no more */\
        /* than the allowed max size. */                                                                            \
        const s64 read_size = left_payload < (blk_size) - 1 ? left_payload : (blk_size) - 1;                        \
                                                                                                                    \
        /* Calculating the absolute size from the allocated buffer, that was left empty, again to please the */     \
        /* verifier so it can be assured we are not exceeding the memory limits. */                                 \
        const s64 left_buffer = (s64)(total_size) < (s64)(i*(blk_size)) ? 0 : total_size - i*(blk_size);            \
        if (read_size <= left_buffer) {                                                                             \
            bpf_skb_load_bytes(skb, offset, buffer, read_size);                                      \
        }                                                                                                           \
        return;                                                                                                     \
    }

READ_INTO_BUFFER(for_classification, CLASSIFICATION_MAX_BUFFER, BLK_SIZE)

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

static __always_inline void __init_buffer(struct __sk_buff *skb, skb_info_t *skb_info, classification_buffer_t* buffer) {
    bpf_memset(buffer->data, 0, sizeof(buffer->data));
    read_into_buffer_for_classification((char *)buffer->data, skb, skb_info->data_off);
    const size_t payload_length = skb->len - skb_info->data_off;
    buffer->size = payload_length < CLASSIFICATION_MAX_BUFFER ? payload_length : CLASSIFICATION_MAX_BUFFER;
}

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

static __always_inline bool is_dubbo_magic(const struct __sk_buff *skb, const skb_info_t *skb_info) {
    char dubbo_magic_buf[DUBBO_MAGIC_LEN];
    if (bpf_skb_load_bytes(skb, skb_info->data_off, dubbo_magic_buf, DUBBO_MAGIC_LEN) < 0) {
        return 0;
    }
    return !bpf_memcmp(dubbo_magic_buf, DUBBO_MAGIC, DUBBO_MAGIC_LEN);
}

static __always_inline void get_path(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, field_index *idx, struct rpc_package_t *pkg) {
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
    pkg->phase = P_REQUEST;

    return;
}

static __always_inline void get_status(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, field_index *idx, struct rpc_package_t *pkg) {
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
    pkg->phase = P_RESPONSE;

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

static __always_inline rpc_status_t is_content_type_grpc(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_end, __u8 idx) {
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

static __always_inline rpc_status_t scan_headers(const struct __sk_buff *skb, skb_info_t *skb_info, __u32 frame_length, struct rpc_package_t *pkg) {
    field_index idx;
    rpc_status_t status = PAYLOAD_UNDETERMINED;

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
            get_path(skb, skb_info, frame_end, &idx, pkg);
        }
        if (idx.literal.index == HTTP2_STATUS_HEADER_IDX) {
            get_status(skb, skb_info, frame_end, &idx, pkg);
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

static __always_inline rpc_status_t judge_rpc(const struct __sk_buff *skb, const skb_info_t *skb_info, struct rpc_package_t *pkg) {
    rpc_status_t status = PAYLOAD_UNDETERMINED;
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
    if (status == PAYLOAD_UNDETERMINED && pkg->phase != P_UNKNOWN) {
        status = PAYLOAD_GRPC;
    }

    return status;
}

static __always_inline dubbo_event_t judge_dubbo_protocol(const struct __sk_buff *skb, const skb_info_t *skb_info, struct rpc_package_t *pkg) {
    skb_info_t info = *skb_info;
    dubbo_event_t event = NOT_DUBBO_EVENT;
    info.data_off += DUBBO_MAGIC_LEN;
    __u8 req_res;
    if (bpf_skb_load_bytes(skb, info.data_off, &req_res, 1) < 0) {
        return IS_DUBBO_EVENT;
    }
    info.data_off += 1;
    pkg->phase = req_res >> 7;
    if (pkg->phase == D_REQUEST) {
        pkg->phase = P_REQUEST;
    } else if (pkg->phase == D_RESPONSE) {
        pkg->phase = P_RESPONSE;
    }

    event = req_res >> 5;
    if (event == IS_DUBBO_EVENT) {
        return event;
    }

    if (pkg->phase == P_RESPONSE) {
        __u8 stauts;
        if (bpf_skb_load_bytes(skb, info.data_off, &stauts, 1) < 0) {
            return IS_DUBBO_EVENT;
        }
        pkg->dubbo_status = stauts;
//        bpf_printk("dubbo status: %d\n", stauts);
    }
    // offset status
    info.data_off += 1;
    // offset request id
    info.data_off += 8;
    // offset data len
    info.data_off += 4;
    if (pkg->phase == P_REQUEST) {
        char req_data[DUBBO_REQUEST_DATA_LEN];
        if (bpf_skb_load_bytes(skb, info.data_off, req_data, DUBBO_REQUEST_DATA_LEN) < 0) {
            return IS_DUBBO_EVENT;
        }
        for (int i = 0; i < DUBBO_REQUEST_DATA_LEN; i++) {
            pkg->path[i] = req_data[i];
        }
        info.data_off += DUBBO_REQUEST_DATA_LEN;
//        bpf_printk("dubbo request data: %s\n", req_data);
    }
    // TODO: response data payload
//    else if (pkg->phase == P_RESPONSE) {
//        char res_data[DUBBO_RESPONSE_DATA_LEN];
//        if (bpf_skb_load_bytes(skb, info.data_off+1, res_data, DUBBO_RESPONSE_DATA_LEN) < 0) {
//            return IS_DUBBO_EVENT;
//        }
//        info.data_off += DUBBO_RESPONSE_DATA_LEN+1;
//        bpf_printk("dubbo response data: %s\n", res_data);
//    }
    return NOT_DUBBO_EVENT;
}

static __always_inline bool is_mysql(const char* buf, __u32 buf_size, const skb_info_t *skb_info, struct rpc_package_t *pkg) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, MYSQL_MIN_LENGTH);

    mysql_hdr header = *((mysql_hdr *)buf);
    if (header.payload_length == 0) {
        return false;
    }

    switch (header.command_type) {
    case MYSQL_COMMAND_QUERY:
//        bpf_printk("mysql query\n");
        return is_sql_command((char*)(buf+sizeof(mysql_hdr)), buf_size-sizeof(mysql_hdr), pkg);
//    case MYSQL_OK00_RESPONSE:
//        pkg->phase = P_RESPONSE;
//        pkg->mysql_status = MYSQL_OK_STATUS;
//        return 1;
//    case MYSQL_EOF_RESPONSE:
//        pkg->phase = P_RESPONSE;
//        pkg->mysql_status = MYSQL_OK_STATUS;
//        return 1;
    case MYSQL_ERR_RESPONSE:
//        bpf_printk("mysql err response\n");
        return is_mysql_err_response((char*)(buf+sizeof(mysql_hdr)), buf_size-sizeof(mysql_hdr), pkg);
    case MYSQL_PREPARE_QUERY:
        return is_sql_command((char*)(buf+sizeof(mysql_hdr)), buf_size-sizeof(mysql_hdr), pkg);
    case MYSQL_SERVER_GREETING_V10:
    case MYSQL_SERVER_GREETING_V9:
        return is_version((char*)(buf+sizeof(mysql_hdr)), buf_size-sizeof(mysql_hdr));
    default:
//        bpf_printk("mysql commond type: %d\n", header.command_type);
        return is_mysql_catalog((char*)(buf+sizeof(mysql_hdr)), buf_size-sizeof(mysql_hdr), pkg);
    }
}