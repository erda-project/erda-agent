#include "kafka_defs.h"
#include "kafka_types.h"
#include "big_endian.h"
#include "maps.h"

#define READ_BIG_ENDIAN_WRAPPER(type, name, skb, offset)    \
    type name = 0;                                          \
    if (!read_big_endian_##type(skb, offset, &name)) {      \
        return false;                                       \
    }                                                       \
    offset += sizeof(type);

#define STRINGIFY(a) #a

#define CHECK_STRING_COMPOSED_OF_ASCII(max_buffer_size, real_size, buffer, printable_ok)                                                \
    char ch = 0;                                                                                                                        \
_Pragma( STRINGIFY(unroll(max_buffer_size)) )                                                                                           \
    for (int j = 0; j < max_buffer_size; j++) {                                                                                         \
        if (j + 1 > real_size) {                                                                                                        \
            break;                                                                                                                      \
        }                                                                                                                               \
        ch = buffer[j];                                                                                                                 \
        if (('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-') {  \
            continue;                                                                                                                   \
        }                                                                                                                               \
        if (printable_ok && (ch >= ' ' && ch <= '~')) {                                                                                 \
            continue;                                                                                                                   \
        }                                                                                                                               \
        return false;                                                                                                                   \
    }                                                                                                                                   \
    return true;

#define CHECK_STRING_VALID_TOPIC_NAME(max_buffer_size, real_size, buffer)   \
    CHECK_STRING_COMPOSED_OF_ASCII(max_buffer_size, real_size, buffer, false)

#define CHECK_STRING_VALID_CLIENT_ID(max_buffer_size, real_size, buffer)   \
    CHECK_STRING_COMPOSED_OF_ASCII(max_buffer_size, real_size, buffer, true)

static __always_inline bool get_topic_offset_from_produce_request(const kafka_header_t *kafka_header, struct __sk_buff *skb, u32 *out_offset) {
    const s16 api_version = kafka_header->api_version;
    u32 offset = *out_offset;
    if (api_version >= 3) {
        READ_BIG_ENDIAN_WRAPPER(s16, transactional_id_size, skb, offset);
        if (transactional_id_size > 0) {
            offset += transactional_id_size;
        }
    }

    READ_BIG_ENDIAN_WRAPPER(s16, acks, skb, offset);
    if (acks > 1 || acks < -1) {
        return false;
    }

    READ_BIG_ENDIAN_WRAPPER(s32, timeout_ms, skb, offset);
    if (timeout_ms < 0) {
        return false;
    }

    *out_offset = offset;
    return true;
}

static __always_inline bool isMSBSet(uint8_t byte) {
    return (byte & 0x80) != 0;
}

static __always_inline bool skip_request_tagged_fields(struct __sk_buff *skb, u32 *offset) {
    u8 num_tagged_fields = 0;

    bpf_skb_load_bytes(skb, *offset, &num_tagged_fields, 1);
    *offset += 1;

    // We don't support parsing tagged fields for now.
    return num_tagged_fields == 0;
}

static __always_inline bool get_topic_offset_from_fetch_request(const kafka_header_t *kafka_header, struct __sk_buff *skb, u32 *offset) {
    u32 api_version = kafka_header->api_version;

    if (api_version >= 12) {
        if (!skip_request_tagged_fields(skb, offset)) {
            return false;
        }
    }

    // replica_id => INT32
    // max_wait_ms => INT32
    // min_bytes => INT32
    *offset += 3 * sizeof(s32);

    if (api_version >= 3) {
        // max_bytes => INT32
        *offset += sizeof(s32);
        if (api_version >= 4) {
            // isolation_level => INT8
            *offset += sizeof(s8);
            if (api_version >= 7) {
                // session_id => INT32
                // session_epoch => INT32
                *offset += 2 * sizeof(s32);
            }
        }
    }

    return true;
}

static __always_inline int parse_varint_u16(u16 *out, u16 in, u32 *bytes)
{
    *bytes = 1;

    u8 first = in & 0xff;
    u8 second = in >> 8;
    u16 tmp = 0;

    tmp |= first & 0x7f;
    if (isMSBSet(first)) {
        *bytes += 1;
        tmp |= ((u16)(second & 0x7f)) << 7;

        if (isMSBSet(second)) {
            // varint larger than two bytes.
            return false;
        }
    }

    // When lengths are stored as varints in the protocol, they are always
    // stored as N + 1.
    *out = tmp - 1;
    return true;
}

static __always_inline s16 read_first_topic_name_size(struct __sk_buff* skb, bool flexible, u32 *offset) {
    u16 topic_name_size_raw = 0;


//    pktbuf_load_bytes(pkt, *offset, &topic_name_size_raw, sizeof(topic_name_size_raw));
    bpf_skb_load_bytes(skb, *offset, &topic_name_size_raw, sizeof(topic_name_size_raw));

    s16 topic_name_size = 0;
    if (flexible) {
        u16 topic_name_size_tmp = 0;
        u32 varint_bytes = 0;

        if (!parse_varint_u16(&topic_name_size_tmp, topic_name_size_raw, &varint_bytes)) {
            return 0;
        }

        topic_name_size = topic_name_size_tmp;
        *offset += varint_bytes;
    } else {
        topic_name_size = bpf_ntohs(topic_name_size_raw);
        *offset += sizeof(topic_name_size_raw);
    }

    return topic_name_size;
}

static __always_inline bool is_valid_client_id(struct __sk_buff *skb, u32 offset, u16 real_client_id_size) {
    const u32 key = 0;
    char *client_id = bpf_map_lookup_elem(&kafka_client_id, &key);
    if (client_id == NULL) {
        return false;
    }
    bpf_memset(client_id, 0, CLIENT_ID_SIZE_TO_VALIDATE);
    bpf_skb_load_bytes(skb, offset, client_id, CLIENT_ID_SIZE_TO_VALIDATE);
    CHECK_STRING_VALID_CLIENT_ID(CLIENT_ID_SIZE_TO_VALIDATE, real_client_id_size, client_id);
}

static __always_inline bool is_valid_kafka_request_header(const kafka_header_t *kafka_header) {
    if (kafka_header->message_size < sizeof(kafka_header_t) || kafka_header->message_size  < 0) {
        return false;
    }

    if (kafka_header->api_version < 0) {
        return false;
    }

    switch (kafka_header->api_key) {
    case KAFKA_FETCH:
        if (kafka_header->api_version > KAFKA_MAX_SUPPORTED_FETCH_REQUEST_API_VERSION) {
            return false;
        }
        break;
    case KAFKA_PRODUCE:
        if (kafka_header->api_version == 0) {
            return false;
        } else if (kafka_header->api_version > KAFKA_MAX_SUPPORTED_PRODUCE_REQUEST_API_VERSION) {
            return false;
        }
        break;
    default:
        return false;
    }

    if (kafka_header->correlation_id < 0) {
        return false;
    }

    return kafka_header->client_id_size >= -1;
}

READ_INTO_BUFFER(topic_name, TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE, BLK_SIZE)

static __always_inline bool skip_varint_number_of_topics(struct __sk_buff *skb, u32 *offset) {
    u8 bytes[2] = {};

    bpf_skb_load_bytes(skb, *offset, bytes, sizeof(bytes));

    *offset += 1;
    if (isMSBSet(bytes[0])) {
        *offset += 1;

        if (isMSBSet(bytes[1])) {
            // More than 16383 topics?
            return false;
        }
    }

    return true;
}

//static __always_inline bool validate_first_topic_name(struct __sk_buff *skb, u32 offset) {
//    // Skipping number of entries for now
//    offset += sizeof(s32);
//
//    READ_BIG_ENDIAN_WRAPPER(s16, topic_name_size, skb, offset);
//    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
//        return false;
//    }
//
////    char topic_name[TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE];
//    const u32 key = 0;
//    char *topic_name = bpf_map_lookup_elem(&kafka_topic_name, &key);
//    if (topic_name == NULL) {
//        return false;
//    }
//    bpf_memset(topic_name, 0, TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE);
//
//    read_into_buffer_topic_name((char *)topic_name, skb, offset);
//    offset += topic_name_size;
//
//    CHECK_STRING_VALID_TOPIC_NAME(TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE, topic_name_size, topic_name);
//}

static __always_inline bool validate_first_topic_name(struct __sk_buff *skb, bool flexible, u32 offset) {
    // Skipping number of entries for now
    if (flexible) {
        if (!skip_varint_number_of_topics(skb, &offset)) {
            return false;
        }
    } else {
        offset += sizeof(s32);
    }

    s16 topic_name_size = read_first_topic_name_size(skb, flexible, &offset);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
        return false;
    }

    const u32 key = 0;
    char *topic_name = bpf_map_lookup_elem(&kafka_topic_name, &key);
    if (topic_name == NULL) {
        return false;
    }
    bpf_memset(topic_name, 0, TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE);

    read_into_buffer_topic_name((char *)topic_name, skb, offset);
    offset += topic_name_size;

    CHECK_STRING_VALID_TOPIC_NAME(TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE, topic_name_size, topic_name);
}

static __always_inline bool is_kafka_request(const kafka_header_t *kafka_header, struct __sk_buff *skb, u32 offset) {
    bool flexible = false;
    switch (kafka_header->api_key) {
    case KAFKA_PRODUCE:
        if (!get_topic_offset_from_produce_request(kafka_header, skb, &offset)) {
            return false;
        }
        break;
    case KAFKA_FETCH:
        if (!get_topic_offset_from_fetch_request(kafka_header, skb, &offset)) {
            return false;
        }
        flexible = kafka_header->api_version >= 12;
        break;
    default:
        return false;
    }
    return validate_first_topic_name(skb, flexible, offset);
}

static __always_inline bool is_kafka(struct __sk_buff *skb, skb_info_t *skb_info, const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, KAFKA_MIN_LENGTH);

    const kafka_header_t *header_view = (kafka_header_t *)buf;
    kafka_header_t kafka_header;
    bpf_memset(&kafka_header, 0, sizeof(kafka_header));
    kafka_header.message_size = bpf_ntohl(header_view->message_size);
    kafka_header.api_key = bpf_ntohs(header_view->api_key);
    kafka_header.api_version = bpf_ntohs(header_view->api_version);
    kafka_header.correlation_id = bpf_ntohl(header_view->correlation_id);
    kafka_header.client_id_size = bpf_ntohs(header_view->client_id_size);
    bpf_printk("source api_key: %d\n", kafka_header.api_key);

    if (!is_valid_kafka_request_header(&kafka_header)) {
        return false;
    }

    u32 offset = skb_info->data_off + sizeof(kafka_header_t);
    if (kafka_header.client_id_size > 0) {
        if (!is_valid_client_id(skb, offset, kafka_header.client_id_size)) {
            return false;
        }
    } else if (kafka_header.client_id_size < -1) {
        return false;
    }

    return is_kafka_request(&kafka_header, skb, offset);
}