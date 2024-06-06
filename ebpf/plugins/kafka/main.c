#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <net/tcp.h>
#include <bpf/bpf_helpers.h>
#include "../../include/bpf_endian.h"
#include "../../include/common.h"
#include "../../include/sock.h"
#include "../../include/protocol.h"
#include "../../include/kafka_defs.h"
#include "../../include/kafka_types.h"
#include "../../include/map-defs.h"
#include "../../include/parsing-maps.h"
#include "../../include/port_range.h"
#include "../../include/usm-events.h"
#include "../../include/kafka_classification.h"

//struct {
//    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
//    __uint(key_size, sizeof(u32));
//    __uint(value_size, sizeof(u32));
//    __uint(max_entries, 1024);
//} tail_jmp_map SEC(".maps");

struct bpf_map_def SEC("maps/package_map") tail_jmp_map = {
  	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(u32),
	.max_entries = 16,
};

enum parser_level {
    PARSER_LEVEL_PARTITION,
    PARSER_LEVEL_RECORD_BATCH,
};

static __always_inline bool kafka_allow_packet(skb_info_t *skb_info);
static __always_inline bool kafka_process(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, u32 offset);
static __always_inline bool kafka_process_response(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, skb_info_t *skb_info);

static __always_inline void kafka_call_response_parser(conn_tuple_t *tup, struct __sk_buff *skb)
{
    bpf_tail_call(skb, &tail_jmp_map, PROG_KAFKA_RESPONSE_PARSER);

    // The only reason we would get here if the tail call failed due to too
    // many tail calls.
    bpf_printk("failed to call response parser");
    bpf_map_delete_elem(&kafka_response, tup);
}

#define CHECK_STRING_COMPOSED_OF_ASCII_FOR_PARSING(max_buffer_size, real_size, buffer)                                                      \
    char ch = 0;                                                                                                                            \
_Pragma( STRINGIFY(unroll(max_buffer_size)) )                                                                                               \
    for (int j = 0; j < max_buffer_size; j++) {                                                                                             \
        /* Verifies we are not exceeding the real client_id_size, and if we do, we finish the iteration as we reached */                    \
        /* to the end of the buffer and all checks have been successful. */                                                                 \
        if (j + 1 <= real_size) {                                                                                                           \
            ch = buffer[j];                                                                                                                 \
            if (('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ('0' <= ch && ch <= '9') || ch == '.' || ch == '_' || ch == '-') {  \
                continue;                                                                                                                   \
            }                                                                                                                               \
            return false;                                                                                                                   \
        }                                                                                                                                   \
    }

static __always_inline bool fetch_dispatching_arguments(conn_tuple_t *tup, skb_info_t *skb_info) {
    const __u32 zero = 0;
    dispatcher_arguments_t *args = bpf_map_lookup_elem(&dispatcher_arguments, &zero);
    if (args == NULL) {
        return false;
    }
    bpf_memcpy(tup, &args->tup, sizeof(conn_tuple_t));
    bpf_memcpy(skb_info, &args->skb_info, sizeof(skb_info_t));

    return true;
}

static __always_inline bool is_payload_empty(skb_info_t *skb_info) {
    return skb_info->data_off == skb_info->data_end;
}

static __always_inline bool kafka_allow_packet(skb_info_t *skb_info) {
    // if payload data is empty, we only process it if the packet represents a TCP termination
    if (is_payload_empty(skb_info)) {
        return skb_info->tcp_flags&(TCPHDR_FIN|TCPHDR_RST);
    }

    return true;
}

// Returns true if the payload represents a TCP termination by checking if the tcp flags contains TCPHDR_FIN or TCPHDR_RST.
static __always_inline bool is_tcp_termination(skb_info_t *skb_info) {
    return skb_info->tcp_flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool is_tcp_ack(skb_info_t *skb_info) {
    return skb_info->tcp_flags == TCPHDR_ACK;
}

static __always_inline u32 kafka_get_next_tcp_seq(skb_info_t *skb_info) {
    u32 data_len = skb_info->data_end - skb_info->data_off;
    u32 next_seq = skb_info->tcp_seq + data_len;

    return next_seq;
}

static __always_inline void kafka_batch_enqueue_wrapper(kafka_info_t *kafka, conn_tuple_t *tup, kafka_transaction_t *transaction) {
    kafka_event_t *event = &kafka->event;

    bpf_memcpy(&event->tup, tup, sizeof(conn_tuple_t));
    normalize_tuple(&event->tup);

    if (transaction != &event->transaction) {
        bpf_memcpy(&event->transaction, transaction, sizeof(kafka_transaction_t));
    }
    sock_key key = {0};
    key.dstIP = tup->daddr_l;
    key.dstPort = tup->dport;
    key.srcIP = tup->saddr_l;
    key.srcPort = tup->sport;
    transaction->request_started = bpf_ktime_get_ns() - transaction->request_started;
    bpf_map_update_elem(&kafka_event, &key, transaction, BPF_ANY);

//    bpf_printk("wrapper enqueue, records_count %d", event->transaction.records_count);
    kafka_batch_enqueue(event);
}

static __always_inline bool kafka_process_new_response(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, skb_info_t *skb_info) {
    u32 offset = skb_info->data_off;
    u32 orig_offset = offset;

    offset += sizeof(__s32); // Skip message size
    READ_BIG_ENDIAN_WRAPPER(s32, correlation_id, skb, offset);

    kafka_transaction_key_t key = {};
    key.correlation_id = correlation_id;
    bpf_memcpy(&key.tuple, tup, sizeof(key.tuple));
    kafka_transaction_t *request = bpf_map_lookup_elem(&kafka_in_flight, &key);
    if (!request) {
//        bpf_printk("No request found for correlation_id %d", correlation_id);
        offset = orig_offset;
        READ_BIG_ENDIAN_WRAPPER(s32, correlation_id2, skb, offset);
        key.correlation_id = correlation_id2;
        request = bpf_map_lookup_elem(&kafka_in_flight, &key);
        if (!request) {
            return false;
        }
        correlation_id = correlation_id2;
    }

    kafka->response.transaction = *request;
    bpf_map_delete_elem(&kafka_in_flight, &key);

//    kafka->response.partitions_count = number_of_partitions;
    kafka->response.state = KAFKA_FETCH_RESPONSE_PARTITION_START;
//    kafka->response.record_batches_num_bytes = 0;
    kafka->response.carry_over_offset = offset - orig_offset;
//    kafka->response.record_batch_length = 0;
    kafka->response.expected_tcp_seq = kafka_get_next_tcp_seq(skb_info);

    // Copy it to the stack since the verifier on 4.14 complains otherwise.
    kafka_response_context_t response_ctx;
    bpf_memcpy(&response_ctx, &kafka->response, sizeof(response_ctx));

    bpf_map_update_elem(&kafka_response, tup, &response_ctx, BPF_ANY);

    kafka_call_response_parser(tup, skb);
    return true;
}

struct read_with_remainder_config {
    u32 want_bytes;
    void (*convert)(void *dest, void *src);
};

static __always_inline void convert_u16(void *dest, void *src)
{
    u16 *dest16 = dest;
    u16 *src16 = src;

    *dest16 = bpf_ntohs(*src16);
}

static __always_inline void convert_u32(void *dest, void *src)
{
    u32 *dest32 = dest;
    u32 *src32 = src;

    *dest32 = bpf_ntohl(*src32);
}

static __always_inline enum parse_result __read_with_remainder(struct read_with_remainder_config config,
                                                               kafka_response_context_t *response, struct __sk_buff* skb,
                                                               u32 *offset, u32 data_end, void *val, bool first)
{
    if (*offset >= data_end) {
        response->carry_over_offset = *offset - data_end;
//        bpf_printk("carry_over_offset %d", response->carry_over_offset);
        return RET_EOP;
    }

    u32 avail = data_end - *offset;
    u32 remainder = response->remainder;
    u32 want = config.want_bytes;

    if (!first) {
        remainder = 0;
    }

    if (avail < want) {
        // We have less than `want` bytes left in the packet.

        if (remainder) {
            return RET_ERR;
        }

        // This is negative and so kafka_continue_parse_response() will save
        // remainder.
        response->carry_over_offset = *offset - data_end;
        return RET_EOP;
    }

    if (!remainder) {
        // No remainder, and 4 or more bytes more in the packet, so just
        // do a normal read.
        bpf_skb_load_bytes(skb, *offset, val, want);
        *offset += want;
        config.convert(val, val);
        return RET_DONE;
    }

    // We'll be using up the remainder so clear it.
    response->remainder = 0;

    // The remainder_buf contains up to 3 head bytes of the value we
    // need to read, saved from the previous packet. Read the tail
    // bytes of the value from the current packet and reconstruct
    // the value to be read.
//    char *reconstruct = response->remainder_buf;
    char reconstruct[4] = {0};
    u8 tail[4] = {0};

    bpf_skb_load_bytes(skb, *offset, &tail, want);

    switch (remainder) {
    case 1:
        reconstruct[1] = tail[0];
        if (want > 2) {
            reconstruct[2] = tail[1];
            reconstruct[3] = tail[2];
        }
        break;
    case 2:
        if (want > 2) {
            reconstruct[2] = tail[0];
            reconstruct[3] = tail[1];
        }
        break;
    case 3:
        if (want > 2) {
            reconstruct[3] = tail[0];
        }
        break;
    }

    *offset += want - remainder;
    config.convert(val, reconstruct);

    return RET_DONE;
}

static __always_inline enum parse_result read_with_remainder_s16(kafka_response_context_t *response, struct __sk_buff* skb,
                                                             u32 *offset, u32 data_end, u16 *val, bool first)
{
    struct read_with_remainder_config config = {
        .want_bytes = sizeof(u16),
        .convert = convert_u16,
    };

    return __read_with_remainder(config, response, skb, offset, data_end, val, first);
}

static __always_inline enum parse_result skip_tagged_fields(kafka_response_context_t *response,
                                                            struct __sk_buff* skb,
                                                            u32 *offset,
                                                            u32 data_end,
                                                            bool verify)
{
    if (*offset >= data_end) {
        response->carry_over_offset = *offset - data_end;
        return RET_EOP;
    }

    if (verify) {
        u8 num_tagged_fields = 0;

        bpf_skb_load_bytes(skb, *offset, &num_tagged_fields, 1);

        if (num_tagged_fields != 0) {
            // We don't support parsing tagged fields for now.
            return RET_ERR;
        }
    }

    *offset += 1;

    return RET_DONE;
}

static __always_inline enum parse_result read_varint(kafka_response_context_t *response,
                                                    struct __sk_buff* skb, u64 *out, u32 *offset,
                                                    u32 data_end,
                                                    bool first,
                                                    u32 max_bytes)
{
    uint32_t shift_amount = 0;
    uint64_t value = 0;
    uint32_t i = 0;
    uint32_t startpos = 0;

    if (response != NULL && first) {
        value = response->varint_value;
        startpos = response->varint_position;
        shift_amount = startpos * 7;


        response->varint_value = 0;
        response->varint_position = 0;
    }

    u8 current_byte = 0;

    #pragma unroll
    for (; i < max_bytes; i++) {
        // This check works better than setting i = startpos initially which leads
        // to complaints from the verifier about too much complexity.
        if (i < startpos) {
            continue;
        }

        if (*offset >= data_end) {
            if (response != NULL) {
                response->varint_position = i;
                response->varint_value = value;
                response->carry_over_offset = *offset - data_end;
            }
            return RET_EOP;
        }

        bpf_skb_load_bytes(skb, *offset, &current_byte, sizeof(current_byte));
        *offset += sizeof(current_byte);

        value |= (uint64_t)(current_byte & 0x7F) << shift_amount;
        shift_amount += 7;

        if (!isMSBSet(current_byte)) {
            break;
        }
    }

    if ((i == max_bytes - 1) && isMSBSet(current_byte)) {
        // The last byte in the unsigned varint contains a continuation bit,
        // this shouldn't happen if MAX_VARINT_BYTES = 10, but if it is lesser,
        // then we could be hitting a number we don't support.
        return RET_ERR;
    }

    // When lengths are stored as varints in the protocol, they are always
    // stored as N + 1.
    *out = value - 1;
    return RET_DONE;
}

static __always_inline bool kafka_process_response(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, skb_info_t *skb_info) {
    kafka_response_context_t *response = bpf_map_lookup_elem(&kafka_response, tup);
    if (response) {
        if (skb_info->tcp_seq == response->expected_tcp_seq) {
            response->expected_tcp_seq = kafka_get_next_tcp_seq(skb_info);
            kafka_call_response_parser(tup, skb);
            return true;
        }
        bpf_printk("Out of order packet, expected %u, got %u", response->expected_tcp_seq, skb_info->tcp_seq);

        s32 diff = skb_info->tcp_seq - response->expected_tcp_seq;
        if (diff < 0) {
            return true;
        }

        if (response->transaction.records_count) {
            kafka_batch_enqueue_wrapper(kafka, tup, &response->transaction);
        }

        bpf_map_delete_elem(&kafka_response, tup);
    }

    return kafka_process_new_response(tup, kafka, skb, skb_info);
}

static enum parser_level parser_state_to_level(kafka_response_state state)
{
    switch (state) {
    case KAFKA_FETCH_RESPONSE_START:
    case KAFKA_FETCH_RESPONSE_NUM_TOPICS:
    case KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE:
    case KAFKA_FETCH_RESPONSE_NUM_PARTITIONS:
    case KAFKA_FETCH_RESPONSE_PARTITION_START:
    case KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START:
        return PARSER_LEVEL_PARTITION;
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_START:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_END:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END:
        return PARSER_LEVEL_RECORD_BATCH;
    case KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS:
    case KAFKA_FETCH_RESPONSE_PARTITION_END:
        return PARSER_LEVEL_PARTITION;
    }
}

static __always_inline enum parse_result read_with_remainder(kafka_response_context_t *response, const struct __sk_buff *skb,
                                                             u32 *offset, u32 data_end, s32 *val, bool first)
{
    struct read_with_remainder_config config = {
        .want_bytes = sizeof(u32),
        .convert = convert_u32,
    };

    return __read_with_remainder(config, response, skb, offset, data_end, val, first);
}

static __always_inline enum parse_result read_varint_or_s16(
                                                            bool flexible,
                                                            kafka_response_context_t *response,
                                                            struct __sk_buff* skb,
                                                            u32 *offset,
                                                            u32 data_end,
                                                            s64 *val,
                                                            bool first,
                                                            u32 max_varint_bytes)
{
    enum parse_result ret;

    if (flexible) {
        u64 tmp = 0;
        ret = read_varint(response, skb, &tmp, offset, data_end, first, max_varint_bytes);
        *val = tmp;
    } else {
        u16 tmp = 0;
        ret = read_with_remainder_s16(response, skb, offset, data_end, &tmp, first);
        *val = tmp;
    }

    return ret;
}

static __always_inline enum parse_result read_varint_or_s32(
                                                            bool flexible,
                                                            kafka_response_context_t *response,
                                                            struct __sk_buff* skb,
                                                            u32 *offset,
                                                            u32 data_end,
                                                            s64 *val,
                                                            bool first,
                                                            u32 max_varint_bytes)
{
    enum parse_result ret;

    if (flexible) {
        u64 tmp = 0;
        ret = read_varint(response, skb, &tmp, offset, data_end, first, max_varint_bytes);
        *val = tmp;
    } else {
        s32 tmp = 0;
        ret = read_with_remainder(response, skb, offset, data_end, &tmp, first);
        *val = tmp;
    }

    return ret;
}

static __always_inline enum parse_result kafka_continue_parse_response_record_batches_loop(kafka_info_t *kafka,
                                                                            conn_tuple_t *tup,
                                                                            kafka_response_context_t *response,
                                                                            struct __sk_buff* skb, u32 offset,
                                                                            u32 data_end,
                                                                            u32 api_version)
{
    u32 orig_offset = offset;
    // u32 carry_over_offset = response->carry_over_offset;
    enum parse_result ret;

    if (response->carry_over_offset < 0) {
        return RET_ERR;
    }

    offset += response->carry_over_offset;
    response->carry_over_offset = 0;


#pragma unroll(KAFKA_RESPONSE_PARSER_MAX_ITERATIONS)
    for (int i = 0; i < KAFKA_RESPONSE_PARSER_MAX_ITERATIONS; i++) {
        bool first = i == 0;

        switch (response->state) {
        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_START:
            offset += sizeof(s64); // baseOffset
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH:
            ret = read_with_remainder(response, skb, &offset, data_end, &response->record_batch_length, first);
            if (ret != RET_DONE) {
                return ret;
            }

            if (response->record_batch_length <= 0) {
                return RET_ERR;
            }
            // The batchLength excludes the baseOffset (u64) and the batchLength (s32) itself,
            // so those need to be be added separately.
            if (response->record_batch_length + sizeof(s32) + sizeof(u64) > response->record_batches_num_bytes) {

                // Kafka fetch responses can have some partial, unparseable records in the record
                // batch block which are truncated due to the maximum response size specified in
                // the request.  If there are no more partitions left, assume we've reached such
                // a block and report what we have.
                if (response->transaction.records_count > 0 && response->partitions_count <= 1 &&
                        response->record_batches_arrays_count - response->record_batches_arrays_idx == 1) {
                    response->record_batch_length = 0;
                    response->record_batches_num_bytes = 0;
                    response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END;
                    continue;
                }

                return RET_ERR;
            }

            offset += sizeof(s32); // Skip partitionLeaderEpoch
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC:
            if (offset + sizeof(s8) > data_end) {
                response->carry_over_offset = offset - data_end;
                return RET_EOP;
            }

            READ_BIG_ENDIAN_WRAPPER(s8, magic, skb, offset);
            if (magic != 2) {
                return RET_ERR;
            }

            offset += sizeof(u32); // Skipping crc
            offset += sizeof(s16); // Skipping attributes
            offset += sizeof(s32); // Skipping last offset delta
            offset += sizeof(s64); // Skipping base timestamp
            offset += sizeof(s64); // Skipping max timestamp
            offset += sizeof(s64); // Skipping producer id
            offset += sizeof(s16); // Skipping producer epoch
            offset += sizeof(s32); // Skipping base sequence
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT:
            {
                s32 records_count = 0;
                ret = read_with_remainder(response, skb, &offset, data_end, &records_count, first);
                if (ret != RET_DONE) {
                    return ret;
                }

                if (records_count <= 0) {
                    return RET_ERR;
                }

                // All the records have to fit inside the record batch, so guard against
                // unreasonable values in corrupt packets.
                if (records_count >= response->record_batch_length) {
                    return RET_ERR;
                }

                response->transaction.records_count += records_count;
            }

            offset += response->record_batch_length
            - sizeof(s32) // Skip partitionLeaderEpoch
            - sizeof(s8) // Skipping magic
            - sizeof(u32) // Skipping crc
            - sizeof(s16) // Skipping attributes
            - sizeof(s32) // Skipping last offset delta
            - sizeof(s64) // Skipping base timestamp
            - sizeof(s64) // Skipping max timestamp
            - sizeof(s64) // Skipping producer id
            - sizeof(s16) // Skipping producer epoch
            - sizeof(s32) // Skipping base sequence
            - sizeof(s32); // Skipping records count
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_END;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_END:
            if (offset > data_end) {
                response->carry_over_offset = offset - data_end;
                return RET_EOP;
            }

            response->record_batches_num_bytes -= response->record_batch_length + sizeof(u32) + sizeof(u64);
            response->record_batch_length = 0;

            if (response->record_batches_num_bytes > 0) {
                response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_START;
                break;
            }

        case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END:
        {
            u64 idx = response->record_batches_arrays_idx + 1;
            if (idx >= response->record_batches_arrays_count) {
                response->record_batches_arrays_idx = idx;
                response->carry_over_offset = offset - orig_offset;
                return RET_DONE;
            }

            if (idx >= KAFKA_MAX_RECORD_BATCHES_ARRAYS) {
                return RET_ERR;
            }

            response->record_batches_num_bytes = kafka->record_batches_arrays[idx].num_bytes;
            offset = kafka->record_batches_arrays[idx].offset + orig_offset;
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_START;
            response->record_batches_arrays_idx = idx;
        }
            break;

        case KAFKA_FETCH_RESPONSE_START:
        case KAFKA_FETCH_RESPONSE_NUM_TOPICS:
        case KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE:
        case KAFKA_FETCH_RESPONSE_NUM_PARTITIONS:
        case KAFKA_FETCH_RESPONSE_PARTITION_START:
        case KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START:
        case KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS:
        case KAFKA_FETCH_RESPONSE_PARTITION_END:
            break;
        }
    }

    response->carry_over_offset = offset - orig_offset;
    return RET_LOOP_END;
}

static __always_inline enum parse_result kafka_continue_parse_response_partition_loop(kafka_info_t *kafka,
                                                                            conn_tuple_t *tup,
                                                                            kafka_response_context_t *response,
                                                                            struct __sk_buff *skb, u32 offset,
                                                                            u32 data_end,
                                                                            u32 api_version)
{
    u32 orig_offset = offset;
    bool flexible = api_version >= 12;
    enum parse_result ret;

    if (response->carry_over_offset < 0) {
        return RET_ERR;
    }

    offset += response->carry_over_offset;
    response->carry_over_offset = 0;
//    bpf_printk("Partition loop, state %d", response->state);

    switch (response->state) {
    case KAFKA_FETCH_RESPONSE_START:
        if (flexible) {
            ret = skip_tagged_fields(response, skb, &offset, data_end, true);
            if (ret != RET_DONE) {
                return ret;
            }
        }

        if (api_version >= 1) {
            offset += sizeof(s32); // Skip throttle_time_ms
        }
        if (api_version >= 7) {
            offset += sizeof(s16); // Skip error_code
            offset += sizeof(s32); // Skip session_id
        }
        response->state = KAFKA_FETCH_RESPONSE_NUM_TOPICS;
        // fallthrough

    case KAFKA_FETCH_RESPONSE_NUM_TOPICS:
        {
            s64 num_topics = 0;
            ret = read_varint_or_s32(flexible, response, skb, &offset, data_end, &num_topics, true,
                                     VARINT_BYTES_NUM_TOPICS);
            if (ret != RET_DONE) {
                return ret;
            }
            if (num_topics <= 0) {
                return RET_ERR;
            }
        }
        response->state = KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE;
        // fallthrough

    case KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE:
        {
            s64 topic_name_size = 0;
            ret = read_varint_or_s16(flexible, response, skb, &offset, data_end, &topic_name_size, true,
                                     VARINT_BYTES_TOPIC_NAME_SIZE);
            if (ret != RET_DONE) {
                return ret;
            }
            if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
                return RET_ERR;
            }

            // Should we check that topic name matches the topic we expect?
            offset += topic_name_size;
        }
        response->state = KAFKA_FETCH_RESPONSE_NUM_PARTITIONS;
        // fallthrough

    case KAFKA_FETCH_RESPONSE_NUM_PARTITIONS:
        {
            s64 number_of_partitions = 0;
            ret = read_varint_or_s32(flexible, response, skb, &offset, data_end, &number_of_partitions, true,
                                     VARINT_BYTES_NUM_PARTITIONS);
            if (ret != RET_DONE) {
                return ret;
            }
            if (number_of_partitions <= 0) {
                return RET_ERR;
            }

            response->partitions_count = number_of_partitions;
            response->state = KAFKA_FETCH_RESPONSE_PARTITION_START;
            response->record_batches_num_bytes = 0;
            response->record_batch_length = 0;
        }
        break;
    case KAFKA_FETCH_RESPONSE_PARTITION_START:
    case KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_START:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCH_END:
    case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END:
    case KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS:
    case KAFKA_FETCH_RESPONSE_PARTITION_END:
        break;
    }

#pragma unroll(KAFKA_RESPONSE_PARSER_MAX_ITERATIONS)
    for (int i = 0; i < KAFKA_RESPONSE_PARSER_MAX_ITERATIONS; i++) {
        bool first = i == 0;

        switch (response->state) {
        case KAFKA_FETCH_RESPONSE_START:
        case KAFKA_FETCH_RESPONSE_NUM_TOPICS:
        case KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE:
        case KAFKA_FETCH_RESPONSE_NUM_PARTITIONS:
            // Never happens. Only present to supress a compiler warning.
            break;
        case KAFKA_FETCH_RESPONSE_PARTITION_START:
            offset += sizeof(s32); // Skip partition_index
            offset += sizeof(s16); // Skip error_code
            offset += sizeof(s64); // Skip high_watermark

            if (api_version >= 4) {
                offset += sizeof(s64); // Skip last_stable_offset

                if (api_version >= 5) {
                    offset += sizeof(s64); // log_start_offset
                }
            }

            response->state = KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS:
            if (api_version >= 4) {
                s64 aborted_transactions = 0;
                ret = read_varint_or_s32(flexible, response, skb, &offset, data_end, &aborted_transactions, first,
                                         VARINT_BYTES_NUM_ABORTED_TRANSACTIONS);
                if (ret != RET_DONE) {
                    return ret;
                }


                // Note that -1 is a valid value which means that the list is empty.
                if (aborted_transactions < -1) {
                    bpf_printk("Invalid aborted transactions %d", aborted_transactions);
                    return RET_ERR;
                }

//                if (aborted_transactions >= KAFKA_MAX_ABORTED_TRANSACTIONS) {
//                    bpf_printk("Too many aborted transactions %d", aborted_transactions);
//                    return RET_ERR;
//                }
                if (aborted_transactions >= 0) {
                    // producer_id and first_offset in each aborted transaction
                    u32 transaction_size = sizeof(s64) * 2;

                    if (flexible) {
                        transaction_size += sizeof(u8);
                    }

                    offset += transaction_size * aborted_transactions;
                }

                if (api_version >= 11) {
                    offset += sizeof(s32); // preferred_read_replica
                }
            }

            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START:
            if (response->record_batches_arrays_count >= KAFKA_MAX_RECORD_BATCHES_ARRAYS) {
                goto exit;
            }

            s64 tmp = 0;
            ret = read_varint_or_s32(flexible, response, skb, &offset, data_end, &tmp, first,
                                     VARINT_BYTES_RECORD_BATCHES_NUM_BYTES);
            if (ret != RET_DONE) {
                return ret;
            }

            response->record_batches_num_bytes = tmp;


            if (response->record_batches_num_bytes != 0) {
                u32 idx = response->record_batches_arrays_count;

                if (idx >= KAFKA_MAX_RECORD_BATCHES_ARRAYS) {
                    return RET_ERR;
                }

                kafka->record_batches_arrays[idx].num_bytes = response->record_batches_num_bytes;
                kafka->record_batches_arrays[idx].offset = offset - orig_offset;
                response->record_batches_arrays_count++;
            }

            offset += response->record_batches_num_bytes;
            response->state = KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS:
            if (flexible) {
                ret = skip_tagged_fields(response, skb, &offset, data_end, false);
                if (ret != RET_DONE) {
                    return ret;
                }
            }
            response->state = KAFKA_FETCH_RESPONSE_PARTITION_END;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_PARTITION_END:
            if (offset > data_end) {
                response->carry_over_offset = offset - data_end;
                return RET_EOP;
            }

            response->partitions_count--;
            if (response->partitions_count == 0) {
                return RET_DONE;
            }

            response->state = KAFKA_FETCH_RESPONSE_PARTITION_START;
            break;

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_START:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_END:
        case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END:
            return RET_ERR;
            break;
        }
    }

exit:
    response->carry_over_offset = offset - orig_offset;
    return RET_LOOP_END;
}

static __always_inline enum parse_result kafka_continue_parse_response(kafka_info_t *kafka,
                                                                       conn_tuple_t *tup,
                                                                       kafka_response_context_t *response,
                                                                       struct __sk_buff *skb, u32 offset,
                                                                       u32 data_end,
                                                                       enum parser_level level,
                                                                       u32 api_version)
{
    enum parse_result ret;

    if (level == PARSER_LEVEL_PARTITION) {
        response->record_batches_arrays_count = 0;
        response->record_batches_arrays_idx = 0;

        ret = kafka_continue_parse_response_partition_loop(kafka, tup, response, skb, offset, data_end, api_version);

        if (ret != RET_ERR && response->record_batches_arrays_count) {
            response->varint_value = 0;
            response->varint_position = 0;
            response->partition_state = response->state;
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_START;
            response->record_batches_num_bytes = kafka->record_batches_arrays[0].num_bytes;
            response->carry_over_offset = kafka->record_batches_arrays[0].offset;
            return RET_LOOP_END;
        }

        if (ret == RET_DONE) {
            kafka_batch_enqueue_wrapper(kafka, tup, &response->transaction);
            return ret;
        }
    } else {

        ret = kafka_continue_parse_response_record_batches_loop(kafka, tup, response, skb, offset, data_end, api_version);
        bpf_printk("Record batches loop returned %d", ret);

        // When we're done with parsing the record batch arrays, we either need
        // to return to the partition parser (if there are partitions left to
        // parse), or exit.
        if (ret == RET_DONE) {
            if (response->partitions_count == 0) {
                kafka_batch_enqueue_wrapper(kafka, tup, &response->transaction);
                return ret;
            }

            if (response->partition_state <= KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START) {
                response->partitions_count++;
            }
            response->state = KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS;

            return RET_LOOP_END;
        }

        if (ret == RET_EOP) {
            u32 idx = response->record_batches_arrays_idx;
            u32 size = response->record_batches_arrays_count;

            if (idx != size - 1) {
                return RET_ERR;
            }

            response->record_batches_arrays_idx = 0;
            response->record_batches_arrays_count = 1;
        }
    }

    if (ret != RET_EOP) {
        return ret;
    }

    if (response->carry_over_offset < 0) {

        switch (response->carry_over_offset) {
        case -1:
            bpf_skb_load_bytes(skb, data_end - 1, &response->remainder_buf, 1);
            break;
        case -2:
            bpf_skb_load_bytes(skb, data_end - 2, &response->remainder_buf, 2);
            break;
        case -3:
            bpf_skb_load_bytes(skb, data_end - 3, &response->remainder_buf, 3);
            break;
        default:
            return RET_ERR;
        }

        response->remainder = -1 * response->carry_over_offset;
        response->carry_over_offset = 0;
    }

    return ret;
}

SEC("socket/kafka_filter")
int socket__kafka_filter(struct __sk_buff* skb) {
    const u32 zero = 0;
    kafka_info_t *kafka = bpf_map_lookup_elem(&kafka_heap, &zero);
    if (kafka == NULL) {
        return 0;
    }
    bpf_memset(&kafka->event.transaction, 0, sizeof(kafka_transaction_t));
    kafka->event.transaction.request_started = bpf_ktime_get_ns();

    conn_tuple_t tup = {0};
    skb_info_t skb_info = {0};
    if (!read_conn_tuple_skb(skb, &skb_info, &tup)) {
        return 0;
    }
    if (!kafka_allow_packet(&skb_info)) {
        return 0;
    }

    if (is_tcp_termination(&skb_info)) {
        bpf_map_delete_elem(&kafka_response, &tup);
        flip_tuple(&tup);
        bpf_map_delete_elem(&kafka_response, &tup);
        return 0;
    }

    if (kafka_process_response(&tup, kafka, skb, &skb_info)) {
        return 0;
    }

    (void)kafka_process(&tup, kafka, skb, skb_info.data_off);
    return 0;
}

READ_INTO_BUFFER(topic_name_parser, TOPIC_NAME_MAX_STRING_SIZE, BLK_SIZE)
//READ_INTO_BUFFER(client_id, CLIENT_ID_MAX_STRING_SIZE, BLK_SIZE)

static __always_inline bool kafka_process(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, u32 offset) {

    kafka_transaction_t *kafka_transaction = &kafka->event.transaction;
    kafka_header_t kafka_header;
    bpf_memset(&kafka_header, 0, sizeof(kafka_header));
    bpf_skb_load_bytes(skb, offset, (char *)&kafka_header, sizeof(kafka_header));
    kafka_header.message_size = bpf_ntohl(kafka_header.message_size);
    kafka_header.api_key = bpf_ntohs(kafka_header.api_key);
    kafka_header.api_version = bpf_ntohs(kafka_header.api_version);
    kafka_header.correlation_id = bpf_ntohl(kafka_header.correlation_id);
    kafka_header.client_id_size = bpf_ntohs(kafka_header.client_id_size);


    if (!is_valid_kafka_request_header(&kafka_header)) {
        return false;
    }

    kafka_transaction->request_api_key = kafka_header.api_key;
    kafka_transaction->request_api_version = kafka_header.api_version;

    offset += sizeof(kafka_header_t);

    if (kafka_header.client_id_size > 0) {
        if (!is_valid_client_id(skb, offset, kafka_header.client_id_size)) {
            return false;
        }
//        bpf_memset(kafka_transaction->client_id, 0, CLIENT_ID_MAX_STRING_SIZE);
//        read_into_buffer_client_id((char *)kafka_transaction->client_id, skb, offset);
        offset += kafka_header.client_id_size;
//        bpf_printk("kafka: client id is %s", kafka_transaction->client_id);
    } else if (kafka_header.client_id_size < -1) {
        return false;
    }

    bool flexible = false;

    switch (kafka_header.api_key) {
    case KAFKA_PRODUCE:
        if (!get_topic_offset_from_produce_request(&kafka_header, skb, &offset)) {
            return false;
        }
        offset += sizeof(s32);
        break;
    case KAFKA_FETCH:
        if (!get_topic_offset_from_fetch_request(&kafka_header, skb, &offset)) {
            return false;
        }
        if (kafka_header.api_version >= 12) {
            flexible = true;
            if (!skip_varint_number_of_topics(skb, &offset)) {
                return false;
            }
        } else {
            offset += sizeof(s32);
        }
        break;
    default:
        return false;
    }

    s16 topic_name_size = read_first_topic_name_size(skb, flexible, &offset);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
        return false;
    }
//    READ_BIG_ENDIAN_WRAPPER(s16, topic_name_size, skb, offset);
//    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
//        return false;
//    }
    bpf_memset(kafka_transaction->topic_name, 0, TOPIC_NAME_MAX_STRING_SIZE);
    read_into_buffer_topic_name_parser((char *)kafka_transaction->topic_name, skb, offset);
    offset += topic_name_size;
    kafka_transaction->topic_name_size = topic_name_size;

    CHECK_STRING_COMPOSED_OF_ASCII_FOR_PARSING(TOPIC_NAME_MAX_STRING_SIZE_TO_VALIDATE, topic_name_size, kafka_transaction->topic_name);


    switch (kafka_header.api_key) {
    case KAFKA_PRODUCE:
    {
        READ_BIG_ENDIAN_WRAPPER(s32, number_of_partitions, skb, offset);
        if (number_of_partitions <= 0) {
            return false;
        }
        if (number_of_partitions > 1) {
            return false;
        }
        offset += sizeof(s32);

        offset += sizeof(s32);
        offset += sizeof(s64);
        offset += sizeof(s32);
        offset += sizeof(s32);
        READ_BIG_ENDIAN_WRAPPER(s8, magic_byte, skb, offset);
        if (magic_byte != 2) {
            return false;
        }
        offset += sizeof(u32);
        offset += sizeof(s16);
        offset += sizeof(s32);
        offset += sizeof(s64);
        offset += sizeof(s64);
        offset += sizeof(s64);
        offset += sizeof(s16);
        offset += sizeof(s32);
        READ_BIG_ENDIAN_WRAPPER(s32, records_count, skb, offset);
        if (records_count <= 0) {
            return false;
        }
        kafka_transaction->records_count = records_count;
        break;
    }
    case KAFKA_FETCH:
        kafka_transaction->records_count = 0;
        break;
    default:
        return false;
     }

    if (kafka_header.api_key == KAFKA_FETCH) {
        kafka_transaction_t transaction;
        kafka_transaction_key_t key;
        bpf_memset(&key, 0, sizeof(key));
        bpf_memcpy(&transaction, kafka_transaction, sizeof(transaction));
        key.correlation_id = kafka_header.correlation_id;
        bpf_memcpy(&key.tuple, tup, sizeof(key.tuple));
        flip_tuple(&key.tuple);
        bpf_map_update_elem(&kafka_in_flight, &key, &transaction, BPF_NOEXIST);
        return true;
    }

    kafka_batch_enqueue_wrapper(kafka, tup, kafka_transaction);
    return true;
}

SEC("socket/kafka_response_parser")
int socket__kafka_response_parser(struct __sk_buff *skb) {
//    bpf_printk("response parser");
    const u32 zero = 0;
    kafka_info_t *kafka = bpf_map_lookup_elem(&kafka_heap, &zero);
    if (!kafka) {
        return 0;
    }

    conn_tuple_t tup = {0};
    skb_info_t skb_info = {0};
    if (!read_conn_tuple_skb(skb, &skb_info, &tup)) {
        return 0;
    }

    kafka_response_context_t *response = bpf_map_lookup_elem(&kafka_response, &tup);
    if (!response) {
        bpf_printk("response not found");
        return 0;
    }
    enum parser_level level = parser_state_to_level(response->state);

    sock_key key = {0};
    key.dstIP = tup.daddr_l;
    key.dstPort = tup.dport;
    key.srcIP = tup.saddr_l;
    key.srcPort = tup.sport;
    enum parse_result result = kafka_continue_parse_response(kafka, &tup, response, skb, skb_info.data_off, skb_info.data_end, level, response->transaction.request_api_version);
    bpf_printk("result: %d", result);
    switch (result) {
    case RET_EOP:
        bpf_printk("eop, records_count %d", response->transaction.records_count);
        break;
    case RET_ERR:
        bpf_map_delete_elem(&kafka_response, &tup);
        break;
    case RET_DONE:
        bpf_printk("done, records_count %d", response->transaction.records_count);
        bpf_map_delete_elem(&kafka_response, &tup);
        bpf_map_update_elem(&kafka_event, &key, &response->transaction, BPF_ANY);
        break;
    case RET_LOOP_END:
        bpf_printk("loop end, records_count %d", response->transaction.records_count);
        kafka_call_response_parser(&tup, skb);

        if (response->transaction.records_count) {
            bpf_printk("enqueue (loop exceeded), records_count %d", response->transaction.records_count);
            kafka_batch_enqueue_wrapper(kafka, &tup, &response->transaction);
        }
        bpf_map_update_elem(&kafka_event, &key, &response->transaction, BPF_ANY);
        break;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";