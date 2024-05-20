#include "amqp_defs.h"

struct bpf_map_def SEC("maps/package_map") amqp_filter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conn_tuple_t),
    .value_size = sizeof(amqp_data),
    .max_entries = 1024,
};

static __always_inline bool is_amqp_protocol_header(const char* buf, __u32 buf_size) {
    CHECK_PRELIMINARY_BUFFER_CONDITIONS(buf, buf_size, AMQP_MIN_FRAME_LENGTH);

    bool match = !bpf_memcmp(buf, AMQP_PREFACE, sizeof(AMQP_PREFACE)-1);

    return match;
}

static __always_inline bool is_amqp(const conn_tuple_t *skb_tup,const char* buf, __u32 buf_size) {
    if (is_amqp_protocol_header(buf, buf_size)) {
        return true;
    }

    if (buf_size < AMQP_MIN_PAYLOAD_LENGTH) {
       return false;
    }

    __u8 frame_type = buf[0];
    if (frame_type != AMQP_FRAME_METHOD_TYPE) {
        return false;
    }

    amqp_header hdr = *((amqp_header *)buf);

    bool is_amqp_protocol = false;
    switch (hdr.class_id) {
    case AMQP_CONNECTION_CLASS:
        switch (hdr.method_id) {
//        case AMQP_METHOD_CONNECTION_START:
        case AMQP_METHOD_CONNECTION_CLOSE:
            is_amqp_protocol = true;
        case AMQP_METHOD_CONNECTION_CLOSE_OK:
            is_amqp_protocol = true;
        case AMQP_METHOD_CONNECTION_START_OK:
            is_amqp_protocol = true;
        }
    case AMQP_BASIC_CLASS:
        switch (hdr.method_id) {
        case AMQP_METHOD_PUBLISH:
            is_amqp_protocol = true;
        case AMQP_METHOD_DELIVER:
            is_amqp_protocol = true;
        case AMQP_METHOD_CONSUME:
            is_amqp_protocol = true;
        }
    case AMPQ_QUEUE_CLASS:
        switch (hdr.method_id) {
        case AMQP_METHOD_BIND:
            is_amqp_protocol = true;
        }
    }
    if (is_amqp_protocol) {
        amqp_data *data = bpf_map_lookup_elem(&amqp_filter_map, skb_tup);
        if (!data) {
            amqp_data new_data = {0};
            new_data.hdr = hdr;
            bpf_map_update_elem(&amqp_filter_map, skb_tup, &new_data, BPF_ANY);
        } else {
            data->hdr = hdr;
            bpf_map_update_elem(&amqp_filter_map, skb_tup, data, BPF_ANY);
        }
    }
    return is_amqp_protocol;
}