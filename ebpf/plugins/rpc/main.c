#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../include/bpf_endian.h"
#include "../../include/common.h"
#include "../../include/sock.h"
#include "../../include/protocol.h"

struct bpf_map_def SEC("maps/package_map") grpc_trace_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct grpc_package_t),
	.max_entries = 1024 * 10,
};


SEC("socket")
int rpc__filter_package(struct __sk_buff *skb)
{
    skb_info_t skb_info = {0};
    conn_tuple_t skb_tup = {0};
    struct grpc_package_t pkg = {0};
    pkg.phase = 0;
    if (!read_conn_tuple_skb(skb, &skb_info, &skb_tup)) {
        return 0;
    }

    grpc_status_t status = judge_grpc(skb, &skb_info, &pkg);
    if (status != PAYLOAD_GRPC) {
        return 0;
    }
    pkg.dstip = skb_tup.daddr_l;
    pkg.dstport = bpf_ntohs(skb_tup.dport);
    pkg.srcip = skb_tup.saddr_l;
    pkg.srcport = bpf_ntohs(skb_tup.sport);
    pkg.seq = bpf_ntohs(skb_info.tcp_seq);
    connection_pid_info_t *pid_info = get_pid_info(pkg.srcip, pkg.dstip, pkg.srcport, pkg.dstport);
    if (pid_info) {
        pkg.pid = pid_info->pid;
        bpf_printk("found associated pid info! pid: %d\n", pkg.pid);
    }
    bpf_map_update_elem(&grpc_trace_map, &skb_info.tcp_seq, &pkg, BPF_ANY);

    return 0;
}
char _license[] SEC("license") = "GPL";
