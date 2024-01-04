#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/string.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/types.h>

#include "./protocols/http/http.h"

static __always_inline bool is_drop_packet(conn_tuple_t *conn_tuple) {
    // not tcp
    if (!(conn_tuple->metadata & 0x1)) {
        return true;
    }

    return false;
}

SEC("socket")
int socket__filter_package(struct __sk_buff *skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t conn_tuple = {0};

    // read conn_tuple and skb_info
    if (!read_conn_tuple_skb(skb, &skb_info, &conn_tuple)) {
        return 0;
    }

    // drop packet
    if (is_drop_packet(&conn_tuple)) {
        return 0;
    }

    // read http info
    read_http_info(skb, &conn_tuple, skb_info.data_off);
    return 0;
}

char _license[] SEC("license") = "GPL";