#ifndef __KAFKA_TYPES_H
#define __KAFKA_TYPES_H

#include "kafka_defs.h"

typedef enum {
    KAFKA_PRODUCE = 0,
    KAFKA_FETCH
} __attribute__ ((packed)) kafka_operation_t;

typedef enum {
    PROG_UNKNOWN = 0,
    PROG_KAFKA_RESPONSE_PARSER,
} protocol_prog_t;

enum parse_result {
    // End of packet. This packet parsed successfully, but more data is needed
    // for the response to be completed.
    RET_EOP = 0,
    // Response parsed fully.
    RET_DONE = 1,
    // Error during processing response.
    RET_ERR = -1,
    // Ran out of iterations in the packet processing loop.
    RET_LOOP_END = -2,
};

typedef struct {
    __s32 message_size;
    __s16 api_key;
    __s16 api_version;
    __s32 correlation_id;
    __s16 client_id_size;
} __attribute__ ((packed)) kafka_header_t;

#define KAFKA_MIN_LENGTH (sizeof(kafka_header_t))

typedef struct kafka_transaction_t {
    __u64 request_started;
    __u32 records_count;
    __u8 request_api_key;
    __u8 request_api_version;
    __u8 topic_name_size;
    char topic_name[TOPIC_NAME_MAX_STRING_SIZE];
} kafka_transaction_t;

typedef struct kafka_event_t {
    conn_tuple_t tup;
    kafka_transaction_t transaction;
} kafka_event_t;

typedef struct kafka_transaction_key_t {
    conn_tuple_t tuple;
    __s32 correlation_id;
} kafka_transaction_key_t;

typedef enum {
    KAFKA_FETCH_RESPONSE_START = 0,
    KAFKA_FETCH_RESPONSE_NUM_TOPICS,
    KAFKA_FETCH_RESPONSE_TOPIC_NAME_SIZE,
    KAFKA_FETCH_RESPONSE_NUM_PARTITIONS,
    KAFKA_FETCH_RESPONSE_PARTITION_START,
    KAFKA_FETCH_RESPONSE_PARTITION_ABORTED_TRANSACTIONS,
    KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_START,
    KAFKA_FETCH_RESPONSE_RECORD_BATCH_START,
    KAFKA_FETCH_RESPONSE_RECORD_BATCH_LENGTH,
    KAFKA_FETCH_RESPONSE_RECORD_BATCH_MAGIC,
    KAFKA_FETCH_RESPONSE_RECORD_BATCH_RECORDS_COUNT,
    KAFKA_FETCH_RESPONSE_RECORD_BATCH_END,
    KAFKA_FETCH_RESPONSE_RECORD_BATCHES_ARRAY_END,
    KAFKA_FETCH_RESPONSE_PARTITION_TAGGED_FIELDS,
    KAFKA_FETCH_RESPONSE_PARTITION_END,
} __attribute__ ((packed)) kafka_response_state;

typedef struct kafka_response_context_t {
    kafka_response_state state;
    __u8 remainder;
    __u8 varint_position;
    kafka_response_state partition_state;
    char remainder_buf[4];
    __s32 record_batches_num_bytes;
    __s32 record_batch_length;
    __u32 expected_tcp_seq;
    __s32 carry_over_offset;
    __u32 partitions_count;
    __u32 varint_value;
    __u32 record_batches_arrays_idx;
    __u32 record_batches_arrays_count;
    kafka_transaction_t transaction;
} kafka_response_context_t;

typedef struct kafka_fetch_response_record_batches_array_t {
    __u32 num_bytes;
    __u32 offset;
} kafka_fetch_response_record_batches_array_t;

#define KAFKA_MAX_RECORD_BATCHES_ARRAYS 50u

typedef struct kafka_info_t {
    kafka_response_context_t response;
    kafka_event_t event;
    kafka_fetch_response_record_batches_array_t record_batches_arrays[KAFKA_MAX_RECORD_BATCHES_ARRAYS];
} kafka_info_t;

typedef struct {
    __u64 topic_name_size_buckets[KAFKA_TELEMETRY_TOPIC_NAME_NUM_OF_BUCKETS];
} kafka_telemetry_t;

#endif
