#ifndef __KAFKA_PARSING_MAPS_H
#define __KAFKA_PARSING_MAPS_H

typedef struct {
    conn_tuple_t tup;
    skb_info_t skb_info;
} dispatcher_arguments_t;

BPF_PERCPU_ARRAY_MAP(dispatcher_arguments, dispatcher_arguments_t, 1)

BPF_PERCPU_ARRAY_MAP(kafka_heap, kafka_info_t, 1)

BPF_HASH_MAP(kafka_in_flight, kafka_transaction_key_t, kafka_transaction_t, 4096)
BPF_HASH_MAP(kafka_response, conn_tuple_t, kafka_response_context_t, 4096)
BPF_HASH_MAP(kafka_event, sock_key, kafka_transaction_t, 4096)

#endif
