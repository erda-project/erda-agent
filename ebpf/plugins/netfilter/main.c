#include <linux/kconfig.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <uapi/linux/netfilter/nf_conntrack_tuple_common.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../../include/common.h"
#include "../../include/libiptables.h"

struct bpf_map_def SEC("maps/package_map") event_buf = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct event_t),
    .max_entries = 1024 * 10,
};

static __always_inline bool fill_event_info(struct event_t *event, struct sk_buff *skb) {
    unsigned char *l3_header;
    u8 ip_version, l4_proto;
    event->flags |= NETFILTER_EVENT_IF;
    set_event_info(skb, event);
    set_pkt_info(skb, &event->pkt_info);
    set_ether_info(skb, &event->l2_info);

    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        event->l2_info.l3_proto = ETH_P_IP;
        set_ipv4_info(skb, &event->l3_info);
    } else if (ip_version == 6) {
        event->l2_info.l3_proto = ETH_P_IPV6;
        set_ipv6_info(skb, &event->l3_info);
    } else {
        return false;
    }

    l4_proto = event->l3_info.l4_proto;
    if (l4_proto == IPPROTO_TCP) {
        set_tcp_info(skb, &event->l4_info);
    } else {
        return false;
    }
//    else if (l4_proto == IPPROTO_UDP) {
//        set_udp_info(skb, &event->l4_info);
//    } else if (l4_proto == IPPROTO_ICMP) {
//        set_icmp_info(skb, &event->icmp_info);
//    } else {
//        return false;
//    }
    return true;
}

SEC("kprobe/nf_nat_setup_info")
int kprobe_nf_nat_setup_info(struct pt_regs *ctx) {
    u64 pid_tgid;
    struct nf_conn *conn = (struct nf_conn *)PT_REGS_PARM1(ctx);
    pid_tgid = bpf_get_current_pid_tgid();
    struct nf_conn_info_t args = {
        .conn_ptr = (u64)conn,
    };
    bpf_map_update_elem(&conn_maps, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/nf_nat_setup_info")
int kretprobe_nf_nat_setup_info(uint ret) {
    u64 pid_tgid;
    pid_tgid = bpf_get_current_pid_tgid();
    struct nf_conn_info_t *args = bpf_map_lookup_elem(&conn_maps, &pid_tgid);
    if (args == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&conn_maps, &pid_tgid);
    struct nf_conn *conn = (struct nf_conn *)args->conn_ptr;
    struct nf_conntrack_tuple originTuple;
    struct nf_conntrack_tuple replyTuple;
    BPF_PROBE_READ_INTO(&originTuple, conn, tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    BPF_PROBE_READ_INTO(&replyTuple, conn, tuplehash[IP_CT_DIR_REPLY].tuple);
    // ignore dns
    if (originTuple.src.u.tcp.port == 53 || bpf_ntohs(originTuple.dst.u.tcp.port) == 53) {
        return 0;
    }
    // ignore same ip
    if (originTuple.dst.u3.ip == replyTuple.src.u3.ip) {
        return 0;
    }
    struct nf_tuple conn_ev = {
        .sport = bpf_ntohs(replyTuple.src.u.tcp.port),
        .dport = bpf_ntohs(replyTuple.dst.u.tcp.port),
        .ori_sport = bpf_ntohs(originTuple.src.u.tcp.port),
        .ori_dport = bpf_ntohs(originTuple.dst.u.tcp.port),
    };
    conn_ev.src.v4addr = replyTuple.src.u3.ip;
    conn_ev.dst.v4addr = replyTuple.dst.u3.ip;
    conn_ev.ori_src.v4addr = originTuple.src.u3.ip;
    conn_ev.ori_dst.v4addr = originTuple.dst.u3.ip;
    bpf_map_update_elem(&nf_conn_maps, &pid_tgid, &conn_ev, BPF_ANY);
    return 0;
}
//
//SEC("kprobe/ip_forward")
//int kprobe_ip_forward(struct pt_regs *ctx) {
//    u64 pid_tgid;
//    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
//    pid_tgid = bpf_get_current_pid_tgid();
//
//    unsigned char *l3_header;
//    u8 ip_version, l4_proto;
//    l3_header = get_l3_header(skb);
//    ip_version = get_ip_version(l3_header);
//    struct ipt_rcv_args_t args = {0};
//    if (ip_version == 4) {
//        set_ipv4_info(skb, &args.l3_info);
//    } else if (ip_version == 6) {
//        set_ipv6_info(skb, &args.l3_info);
//    } else {
//        return false;
//    }
//
//    l4_proto = args.l3_info.l4_proto;
//    if (l4_proto == IPPROTO_TCP) {
//        set_tcp_info(skb, &args.l4_info);
//    } else {
//        return false;
//    }
////    else if (l4_proto == IPPROTO_UDP) {
////        set_udp_info(skb, &args.l4_info);
////    } else {
////        return false;
////    }
//
////    bpf_printk("ip_rcv set ack: %d\n", args.l4_info.ack);
////    struct ipt_rcv_key_t key = {0};
////    key.saddr = args.l3_info.saddr;
////    key.sport = args.l4_info.sport;
//    bpf_map_update_elem(&ip_rcv_maps, &pid_tgid, &args, BPF_ANY);
//    return 0;
//}
//
//SEC("kretprobe/ip_forward")
//int kretprobe_ip_forward(struct pt_regs *ctx) {
//    u64 pid_tgid;
//    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
//    if (skb == NULL) {
////        bpf_printk("skb is null\n");
//        return 0;
//    }
//    pid_tgid = bpf_get_current_pid_tgid();
//
//    struct event_t event = {0};
//    if (!fill_event_info(&event, skb)) {
////        bpf_printk("fill event info failed\n");
//        return 0;
//    }
//    event.flags |= SKBTRACER_EVENT_IPTABLE;
////    else if (l4_proto == IPPROTO_UDP) {
////        set_udp_info(skb, &args.l4_info);
////    } else {
////        return false;
////    }
//
////    bpf_printk("ip_rcv set ack: %d\n", args.l4_info.ack);
////    struct ipt_rcv_key_t key = {0};
////    key.saddr = args.l3_info.saddr;
////    key.sport = args.l4_info.sport;
//    bpf_printk("kreprobe ip forward dport: %d\n", event.l4_info.dport);
//    bpf_map_update_elem(&event_buf, &pid_tgid, &event, BPF_ANY);
//    return 0;
//}

SEC("kprobe/ipt_do_table")
int kprobe_ipt_do_table(struct pt_regs *ctx) {
    u64 pid_tgid;
//    unsigned char *l3_header;
//    u8 ip_version, l4_proto;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    const struct nf_hook_state *state = (const struct nf_hook_state *)PT_REGS_PARM2(ctx);
    struct xt_table *table = (struct xt_table *)PT_REGS_PARM3(ctx);
    pid_tgid = bpf_get_current_pid_tgid();
    struct ipt_do_table_args_t args = {
        .skb_ptr = (u64)skb,
        .state_ptr = (u64)state,
        .table_ptr = (u64)table,
    };
    args.start_ns = bpf_ktime_get_ns();
//    l3_header = get_l3_header(skb);
//    ip_version = get_ip_version(l3_header);
//    if (ip_version == 4) {
//        set_ipv4_info(skb, &args.src_l3_info);
//    } else if (ip_version == 6) {
//        set_ipv6_info(skb, &args.src_l3_info);
//    } else {
//        return false;
//    }

//    l4_proto = args.src_l3_info.l4_proto;
//    if (l4_proto == IPPROTO_TCP) {
//        set_tcp_info(skb, &args.src_l4_info);
//    } else if (l4_proto == IPPROTO_UDP) {
//        set_udp_info(skb, &args.src_l4_info);
//    } else {
//        return false;
//    }
    bpf_map_update_elem(&ipt_maps, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/ipt_do_table")
int kretprobe_ipt_do_table(uint ret) {
    u64 pid_tgid;
    pid_tgid = bpf_get_current_pid_tgid();
    struct ipt_do_table_args_t *args = bpf_map_lookup_elem(&ipt_maps, &pid_tgid);
    if (args == NULL) {
        return 0;
    }
    bpf_map_delete_elem(&ipt_maps, &pid_tgid);

    struct event_t event = {0};
    u64 ipt_delay;
    ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    event.ipt_info.delay = ipt_delay;
    struct xt_table *table = (struct xt_table *)args->table_ptr;
    struct nf_hook_state *state = (struct nf_hook_state *)args->state_ptr;
    if (!fill_event_info(&event, (struct sk_buff *)args->skb_ptr)) {
        return 0;
    }
    event.flags |= SKBTRACER_EVENT_IPTABLE;
    set_iptables_info(table, state, ipt_delay, &event.ipt_info);

//    struct ipt_rcv_key_t key = {0};
//    key.saddr = event.l3_info.saddr;
//    key.sport = event.l4_info.sport;
//    struct ipt_rcv_args_t *rcv_args = bpf_map_lookup_elem(&ip_rcv_maps, &event.l4_info.ack);
//    if (rcv_args == NULL) {
//        return 0;
//    }
//    bpf_map_delete_elem(&ip_rcv_maps, &event.l4_info.ack);

//    event.src_l3_info = rcv_args->l3_info;
//    event.src_l4_info = rcv_args->l4_info;
    bpf_map_update_elem(&event_buf, &pid_tgid, &event, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";