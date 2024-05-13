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

static __always_inline u32 get_topic_offset_from_fetch_request(const kafka_header_t *kafka_header) {
    u32 offset = 3 * sizeof(s32);

    if (kafka_header->api_version >= 3) {
        offset += sizeof(s32);
        if (kafka_header->api_version >= 4) {
            offset += sizeof(s8);
            if (kafka_header->api_version >= 7) {
                offset += 2 * sizeof(s32);
            }
        }
    }

    return offset;
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

static __always_inline bool validate_first_topic_name(struct __sk_buff *skb, u32 offset) {
    // Skipping number of entries for now
    offset += sizeof(s32);

    READ_BIG_ENDIAN_WRAPPER(s16, topic_name_size, skb, offset);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
        return false;
    }

//    char topic_name[TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE];
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
    switch (kafka_header->api_key) {
    case KAFKA_PRODUCE:
        if (!get_topic_offset_from_produce_request(kafka_header, skb, &offset)) {
            return false;
        }
        break;
    case KAFKA_FETCH:
        offset += get_topic_offset_from_fetch_request(kafka_header);
        break;
    default:
        return false;
    }
    return validate_first_topic_name(skb, offset);
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