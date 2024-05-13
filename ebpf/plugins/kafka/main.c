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
    key.dstIP = tup->saddr_l;
    key.dstPort = tup->sport;
    key.srcIP = tup->daddr_l;
    key.srcPort = tup->dport;
    bpf_map_update_elem(&kafka_event, &key, transaction, BPF_ANY);

    bpf_printk("wrapper enqueue, records_count %d", event->transaction.records_count);
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
        return false;
    }

    kafka->response.transaction = *request;
    bpf_map_delete_elem(&kafka_in_flight, &key);

    request = &kafka->response.transaction;


    if (request->request_api_version >= 1) {
        offset += sizeof(s32); // Skip throttle_time_ms
    }
    if (request->request_api_version >= 7) {
        offset += sizeof(s16); // Skip error_code
        offset += sizeof(s32); // Skip session_id
    }

    READ_BIG_ENDIAN_WRAPPER(s32, num_topics, skb, offset);
    if (num_topics <= 0) {
        bpf_printk("Invalid number of topics %d", num_topics);
        return false;
    }

    READ_BIG_ENDIAN_WRAPPER(s16, topic_name_size, skb, offset);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
        bpf_printk("Invalid topic name size %d", topic_name_size);
        return false;
    }

    // Should we check that topic name matches the topic we expect?
    offset += topic_name_size;

    READ_BIG_ENDIAN_WRAPPER(s32, number_of_partitions, skb, offset);
    if (number_of_partitions <= 0) {
        bpf_printk("Invalid number of partitions %d", number_of_partitions);
        return false;
    }

    kafka->response.partitions_count = number_of_partitions;
    kafka->response.state = KAFKA_FETCH_RESPONSE_PARTITION_START;
    kafka->response.record_batches_num_bytes = 0;
    kafka->response.carry_over_offset = offset - orig_offset;
    kafka->response.record_batch_length = 0;
    kafka->response.expected_tcp_seq = kafka_get_next_tcp_seq(skb_info);

    // Copy it to the stack since the verifier on 4.14 complains otherwise.
    kafka_response_context_t response_ctx;
    bpf_memcpy(&response_ctx, &kafka->response, sizeof(response_ctx));

    bpf_map_update_elem(&kafka_response, tup, &response_ctx, BPF_ANY);

    kafka_call_response_parser(tup, skb);
    return true;
}

static __always_inline bool kafka_process_response(conn_tuple_t *tup, kafka_info_t *kafka, struct __sk_buff* skb, skb_info_t *skb_info) {
    kafka_response_context_t *response = bpf_map_lookup_elem(&kafka_response, tup);
    if (response) {
        if (skb_info->tcp_seq == response->expected_tcp_seq) {
            response->expected_tcp_seq = kafka_get_next_tcp_seq(skb_info);
            kafka_call_response_parser(tup, skb);
            return true;
        }

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

static __always_inline enum parse_result read_with_remainder(kafka_response_context_t *response, const struct __sk_buff *skb,
                                                             u32 *offset, u32 data_end, s32 *val, bool first)
{
    if (*offset >= data_end) {
        response->carry_over_offset = *offset - data_end;
        return RET_EOP;
    }

    u32 avail = data_end - *offset;
    u32 remainder = response->remainder;
    u32 want = sizeof(s32);

    bpf_printk("avail %u want %u remainder %u", avail, want, remainder);

    if (!first) {
        remainder = 0;
    }

    if (avail < want) {

        if (remainder) {
            bpf_printk("Continuation packet less than 4 bytes?");
            return RET_ERR;
        }

        response->carry_over_offset = *offset - data_end;
        return RET_EOP;
    }

    if (!remainder) {
        bpf_skb_load_bytes(skb, *offset, val, sizeof(*val));
        *offset += sizeof(*val);
        *val = bpf_ntohl(*val);
        bpf_printk("read without remainder: %d", *val);
        return RET_DONE;
    }

    response->remainder = 0;
    char *reconstruct = response->remainder_buf;
    u8 tail[4] = {0};

    bpf_skb_load_bytes(skb, *offset, &tail, 4);

    switch (remainder) {
    case 1:
        reconstruct[1] = tail[0];
        reconstruct[2] = tail[1];
        reconstruct[3] = tail[2];
        break;
    case 2:
        reconstruct[2] = tail[0];
        reconstruct[3] = tail[1];
        break;
    case 3:
        reconstruct[3] = tail[0];
        break;
    }

    *offset += want - remainder;
    *val = bpf_ntohl(*(u32 *)reconstruct);
    bpf_printk("read with remainder: %d", *val);

    return RET_DONE;
}

static __always_inline enum parse_result kafka_continue_parse_response_loop(kafka_info_t *kafka,
                                                                            conn_tuple_t *tup,
                                                                            kafka_response_context_t *response,
                                                                            struct __sk_buff *skb, u32 offset,
                                                                            u32 data_end)
{
    u32 orig_offset = offset;
    kafka_transaction_t *request = &response->transaction;
    enum parse_result ret;

    bpf_printk("carry_over_offset %d", response->carry_over_offset);

    if (response->carry_over_offset < 0) {
        return RET_ERR;
    }

    offset += response->carry_over_offset;
    response->carry_over_offset = 0;

#pragma unroll(KAFKA_RESPONSE_PARSER_MAX_ITERATIONS)
    for (int i = 0; i < KAFKA_RESPONSE_PARSER_MAX_ITERATIONS; i++) {
        bool first = i == 0;

        bpf_printk("state: %d", response->state);
        switch (response->state) {
        case KAFKA_FETCH_RESPONSE_PARTITION_START:
            offset += sizeof(s32); // Skip partition_index
            offset += sizeof(s16); // Skip error_code
            offset += sizeof(s64); // Skip high_watermark

            if (request->request_api_version >= 4) {
                offset += sizeof(s64); // Skip last_stable_offset

                if (request->request_api_version >= 5) {
                    offset += sizeof(s64); // log_start_offset
                }
            }

            response->state = KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS:
            if (request->request_api_version >= 4) {
                s32 aborted_transactions = 0;
                ret = read_with_remainder(response, skb, &offset, data_end, &aborted_transactions, first);
                if (ret != RET_DONE) {
                    return ret;
                }

                if (aborted_transactions < -1) {
                    return RET_ERR;
                }
                if (aborted_transactions >= KAFKA_MAX_ABORTED_TRANSACTIONS) {
                    bpf_printk("Possibly invalid aborted_transactions %d", aborted_transactions);
                    return RET_ERR;
                }
                if (aborted_transactions >= 0) {
                    offset += sizeof(s64) * 2 * aborted_transactions;
                }

                if (request->request_api_version >= 11) {
                    offset += sizeof(s32); // preferred_read_replica
                }
            }

            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START:
            ret = read_with_remainder(response, skb, &offset, data_end, &response->record_batches_num_bytes, first);
            if (ret != RET_DONE) {
                return ret;
            }

            bpf_printk("record_batches_num_bytes: %d", response->record_batches_num_bytes);

            if (response->record_batches_num_bytes == 0) {
                response->state = KAFKA_FETCH_RESPONSE_PARTITION_END;
                break;
            }

            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_START;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_START:
            offset += sizeof(s64); // baseOffset
            response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH:
            ret = read_with_remainder(response, skb, &offset, data_end, &response->record_batch_length, first);
            if (ret != RET_DONE) {
                return ret;
            }

            bpf_printk("batchLength %d", response->record_batch_length);
            if (response->record_batch_length <= 0) {
                bpf_printk("batchLength too small %d", response->record_batch_length);
                return RET_ERR;
            }
            // The batchLength excludes the baseOffset (u64) and the batchLength (s32) itself,
            // so those need to be be added separately.
            if (response->record_batch_length + sizeof(s32) + sizeof(u64) > response->record_batches_num_bytes) {
                bpf_printk("batchLength too large %d (record_batches_num_bytes: %d)", response->record_batch_length,
                            response->record_batches_num_bytes);

                // Kafka fetch responses can have some partial, unparseable records in the record
                // batch block which are truncated due to the maximum response size specified in
                // the request.  If there are no more partitions left, assume we've reached such
                // a block and report what we have.
                if (response->transaction.records_count > 0 && response->partitions_count == 1) {
                    bpf_printk("assuming truncated data due to maxsize");
                    response->record_batch_length = 0;
                    response->record_batches_num_bytes = 0;
                    response->state = KAFKA_FETCH_RESPONSE_PARTITION_END;
                    continue;
                }

                bpf_printk("assuming corrupt packet");
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
                bpf_printk("Invalid magic byte");
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

                bpf_printk("records_count: %d", records_count);
                if (records_count <= 0) {
                    bpf_printk("Invalid records count: %d", records_count);
                    return RET_ERR;
                }

                // All the records have to fit inside the record batch, so guard against
                // unreasonable values in corrupt packets.
                if (records_count >= response->record_batch_length) {
                    bpf_printk("Bogus records count %d (batch_length %d)",
                                records_count, response->record_batch_length);
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

            // Record batch batchLength does not include batchOffset and batchLength.
            response->record_batches_num_bytes -= response->record_batch_length + sizeof(u32) + sizeof(u64);
            response->record_batch_length = 0;

            if (response->record_batches_num_bytes > 0) {
                response->state = KAFKA_FETCH_RESPONSE_RECORD_BATCH_START;
                break;
            }

            response->state = KAFKA_FETCH_RESPONSE_PARTITION_END;
            // fallthrough

        case KAFKA_FETCH_RESPONSE_PARTITION_END:
            response->partitions_count--;
            if (response->partitions_count == 0) {
                bpf_printk("loop enqueue, records_count %d",  response->transaction.records_count);
                kafka_batch_enqueue_wrapper(kafka, tup, &response->transaction);
                return RET_DONE;
            }

            response->state = KAFKA_FETCH_RESPONSE_PARTITION_START;
            break;
        }
    }

    response->carry_over_offset = offset - orig_offset;
    return RET_LOOP_END;
}

static __always_inline enum parse_result kafka_continue_parse_response(kafka_info_t *kafka,
                                                                       conn_tuple_t *tup,
                                                                       kafka_response_context_t *response,
                                                                       struct __sk_buff *skb, u32 offset,
                                                                       u32 data_end)
{
    enum parse_result ret;

    ret = kafka_continue_parse_response_loop(kafka, tup, response, skb, offset, data_end);
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

    kafka_transaction->request_started = bpf_ktime_get_ns();
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

    switch (kafka_header.api_key) {
    case KAFKA_PRODUCE:
        if (!get_topic_offset_from_produce_request(&kafka_header, skb, &offset)) {
            return false;
        }
        break;
    case KAFKA_FETCH:
        offset += get_topic_offset_from_fetch_request(&kafka_header);
        break;
    default:
        return false;
    }

    offset += sizeof(s32);
    READ_BIG_ENDIAN_WRAPPER(s16, topic_name_size, skb, offset);
    if (topic_name_size <= 0 || topic_name_size > TOPIC_NAME_MAX_ALLOWED_SIZE) {
        return false;
    }
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
    bpf_printk("response parser");
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

    sock_key key = {0};
    key.dstIP = tup.saddr_l;
    key.dstPort = tup.sport;
    key.srcIP = tup.daddr_l;
    key.srcPort = tup.dport;
    enum parse_result result = kafka_continue_parse_response(kafka, &tup, response, skb, skb_info.data_off, skb_info.data_end);
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