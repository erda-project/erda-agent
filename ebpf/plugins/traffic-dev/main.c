// #include <bpf/bpf_helpers.h>
// TODO: find load_half source include

#include "./protocols/http/http.h"

struct package_t {
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u32 ack_seq;
	__u32 seq;
};

struct bpf_map_def SEC("maps/package_map") filter_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct package_t),
	.max_entries = 1024 * 16,
};

SEC("socket/http_filter")
int socket__filter_package(struct __sk_buff *skb) {
    http_event_t event = {};
    skb_reader_t reader = {};

    read_conn_info(skb, &reader, &event.conn_info);

    if (!is_http_process_package(&event.conn_info)) {
        return 0;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";