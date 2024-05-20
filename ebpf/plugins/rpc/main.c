#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../include/bpf_endian.h"
#include "../../include/common.h"
#include "../../include/sock.h"
#include "../../include/protocol.h"
#include "../../include/redis.h"
#include "../../include/amqp.h"

struct bpf_map_def SEC("maps/package_map") grpc_trace_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct rpc_package_t),
	.max_entries = 1024 * 10,
};

struct bpf_map_def SEC("maps/package_map") amqp_trace_map = {
  	.type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct amqp_trace),
    .max_entries = 1024,
};

struct bpf_map_def SEC("maps/package_map") grpc_request_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(sock_key),
	.value_size = sizeof(struct rpc_package_t),
	.max_entries = 1024 * 10,
};

struct bpf_map_def SEC("maps/package_map") filter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps/package_map") tail_jmp_map = {
  	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(u32),
	.max_entries = 16,
};

int __get_target_ip() {
    __u32 filter_ip_key = 1;
    __u32 *us_ipAddress;
    us_ipAddress = bpf_map_lookup_elem(&filter_map, &filter_ip_key);
    if (!us_ipAddress) {
        return 0;
    }
    return *us_ipAddress;
}


SEC("socket")
int rpc__filter_package(struct __sk_buff *skb)
{
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    classification_buffer_t buffer = {0};
    struct rpc_package_t pkg = {0};
    pkg.phase = P_UNKNOWN;
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return 0;
    }
    __init_buffer(skb, &skb_info, &buffer);
    const char *buf = &buffer.data[0];
    if (is_dubbo_magic(skb, &skb_info)) {
        dubbo_event_t event = judge_dubbo_protocol(skb, &skb_info, &pkg);
        if (event == IS_DUBBO_EVENT) {
            return 0;
        }
        pkg.rpc_type = PAYLOAD_DUBBO;
    } else if (is_mysql(buf, buffer.size, &skb_info, &pkg)) {
        pkg.rpc_type = PAYLOAD_MYSQL;
    } else if (is_redis(buf, buffer.size, &skb_info, &pkg)) {
        pkg.rpc_type = PAYLOAD_REDIS;
    }  else if (is_amqp(&skb_tup, buf, buffer.size)) {
        bpf_tail_call(skb, &tail_jmp_map, PROG_AMQP_FILTER);
        return 0;
    } else {
        rpc_status_t status = judge_rpc(skb, &skb_info, &pkg);
        if (status != PAYLOAD_GRPC) {
            return 0;
        }
        pkg.rpc_type = PAYLOAD_GRPC;
    }

    __u64 srcip = 0;
    __u64 dstip = 0;
    if (skb_tup.l3_proto == ETH_P_IP) {
        pkg.srcIP = skb_tup.saddr_l;
        pkg.dstIP = skb_tup.daddr_l;
        srcip = skb_tup.saddr_l;
        dstip = skb_tup.daddr_l;
        pkg.ip_type = ETH_TYPE_IPV4;
    } else if (skb_tup.l3_proto == ETH_P_IPV6) {
        pkg.srcIP = skb_tup.saddr_h;
        pkg.dstIP = skb_tup.daddr_h;
        srcip = skb_tup.saddr_h;
        dstip = skb_tup.daddr_h;
        pkg.ip_type = ETH_TYPE_IPV6;
    } else {
        return 0;
    }
    pkg.dstPort = bpf_ntohs(skb_tup.dport);
    pkg.srcPort = bpf_ntohs(skb_tup.sport);
    pkg.seq = bpf_ntohs(skb_info.tcp_seq);
    connection_pid_info_t *pid_info = get_pid_info(srcip, dstip, pkg.srcPort, pkg.dstPort);
    if (pid_info) {
        pkg.pid = pid_info->pid;
    }
    if (pkg.phase == P_REQUEST) {
        __u32 ip;
        ip = __get_target_ip();
        if (ip != 0 && ip != pkg.srcIP) {
            return 0;
        }
        sock_key req_conn = {0};
        req_conn.srcIP = pkg.srcIP;
        req_conn.dstIP = pkg.dstIP;
        req_conn.srcPort = pkg.srcPort;
        req_conn.dstPort = pkg.dstPort;
        pkg.duration = bpf_ktime_get_ns();
        bpf_map_update_elem(&grpc_request_map, &req_conn, &pkg, BPF_ANY);
    } else if (pkg.phase == P_RESPONSE) {
        sock_key req_conn = {0};
        req_conn.srcIP = pkg.dstIP;
        req_conn.dstIP = pkg.srcIP;
        req_conn.srcPort = pkg.dstPort;
        req_conn.dstPort = pkg.srcPort;

        struct rpc_package_t *request_pkg = bpf_map_lookup_elem(&grpc_request_map, &req_conn);
        if (request_pkg) {
            pkg.duration = bpf_ktime_get_ns() - request_pkg->duration;
            pkg.path_len = request_pkg->path_len;
            for (int i = 0; i < MAX_HTTP2_PATH_CONTENT_LENGTH; i++) {
                pkg.path[i] = request_pkg->path[i];
            }
            bpf_map_delete_elem(&grpc_request_map, &req_conn);
            bpf_map_update_elem(&grpc_trace_map, &skb_info.tcp_seq, &pkg, BPF_ANY);
        }
    } else {
        return -1;
    }

    return 0;
}

SEC("socket/amqp_filter")
int socket__amqp_filter(struct __sk_buff* skb) {
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return 0;
    }
    amqp_data *data = bpf_map_lookup_elem(&amqp_filter_map, &skb_tup);
    if (!data) {
        return 0;
    }

    struct amqp_trace pkg = {0};
    switch (data->hdr.class_id) {
    case AMPQ_QUEUE_CLASS:
        switch (data->hdr.method_id) {
        case AMQP_METHOD_BIND:
            bpf_skb_load_bytes(skb, skb_info.data_off+sizeof(amqp_header)+2, data->event.queue, AMQP_QUEUE_MAX_LENGTH);
        }
    case AMQP_BASIC_CLASS:
        switch (data->hdr.method_id) {
        case AMQP_METHOD_PUBLISH:
            data->event.type = AMQP_PUBLISH;
            bpf_skb_load_bytes(skb, skb_info.data_off+sizeof(amqp_header)+2, data->event.exchange, AMQP_QUEUE_MAX_LENGTH);
        case AMQP_METHOD_CONSUME:
            if (data->event.type != AMQP_PUBLISH) {
                data->event.type = AMQP_CONSUME;
            }
        case AMQP_METHOD_DELIVER:
            data->event.count += 1;
        default:
            break;
        }
    case AMQP_CONNECTION_CLASS:
        switch (data->hdr.method_id) {
        case AMQP_METHOD_CONNECTION_START_OK:
            data->event.duration = bpf_ktime_get_ns();
        case AMQP_METHOD_CONNECTION_CLOSE:
        case AMQP_METHOD_CONNECTION_CLOSE_OK:
            if (skb_tup.l3_proto == ETH_P_IP) {
                pkg.srcIP = skb_tup.saddr_l;
                pkg.dstIP = skb_tup.daddr_l;
            } else if (skb_tup.l3_proto == ETH_P_IPV6) {
                pkg.srcIP = skb_tup.saddr_h;
                pkg.dstIP = skb_tup.daddr_h;
            } else {
                return 0;
            }
            pkg.dstPort = bpf_ntohs(skb_tup.dport);
            pkg.srcPort = bpf_ntohs(skb_tup.sport);
            data->event.duration = bpf_ktime_get_ns() - data->event.duration;
            pkg.event.type = data->event.type;
            pkg.event.count = data->event.count;
            pkg.event.duration = data->event.duration;
            for (int i = 0; i < AMQP_QUEUE_MAX_LENGTH; i++) {
                pkg.event.exchange[i] = data->event.exchange[i];
                pkg.event.queue[i] = data->event.queue[i];
            }
            if (pkg.event.type != AMQP_UNKNOWN) {
                bpf_map_update_elem(&amqp_trace_map, &skb_info.tcp_seq, &pkg, BPF_ANY);
                bpf_map_delete_elem(&amqp_filter_map, &skb_tup);
            }
            bpf_printk("amqp type: %d", pkg.event.type);
            bpf_printk("exchange bind: %s", pkg.event.exchange);
            bpf_printk("queue bind: %s", pkg.event.queue);
            bpf_printk("count: %d", pkg.event.count);
            bpf_printk("duration: %lld", pkg.event.duration);
        default:
            break;
        }
    }
    return 0;
}
char _license[] SEC("license") = "GPL";
