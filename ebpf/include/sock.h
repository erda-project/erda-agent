#include <net/sock.h>
#include <bpf/bpf_helpers.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

typedef struct tcp_connection_info {
    __u16 s_port;
    __u16 d_port;
    __u32  s_addr;
    __u32  d_addr;
} connection_info_t;

typedef struct connection_pid_info {
    u32 pid;
    char fcomm[TASK_COMM_LEN];
    u64 tgid;
} connection_pid_info_t;

#define MAX_CONCURRENT_REQUESTS 1000
#define MAX_CONCURRENT_SHARED_REQUESTS 10000
#define EPHEMERAL_PORT_MIN 32768

typedef struct recv_args {
    u64 sock_ptr;
    u64 iovec_ptr;
} recv_args_t;

struct bpf_map_def SEC("maps/active_connections") active_recv_args = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(recv_args_t),
    .max_entries = 1024 * 16,
};

struct bpf_map_def SEC("maps/tcp_connections") filtered_connections = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_info_t),
    .value_size = sizeof(connection_pid_info_t),
    .max_entries = 1024 * 16,
};

struct bpf_map_def SEC("maps/grpc_connections") grpc_connections = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_info_t),
    .value_size = sizeof(bool),
    .max_entries = 1024 * 16,
};

static __always_inline bool parse_sock_info(struct sock *s, connection_info_t *info) {
    u16 family;
    BPF_PROBE_READ_INTO(&family, s, __sk_common.skc_family);

    if (family == AF_INET) {
        BPF_PROBE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_PROBE_READ_INTO(&info->s_addr, s, __sk_common.skc_rcv_saddr);
        BPF_PROBE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_PROBE_READ_INTO(&info->d_addr, s, __sk_common.skc_daddr);

        return true;
    } else if (family == AF_INET6) {
        BPF_PROBE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_PROBE_READ_INTO(&info->s_addr, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        if (info->s_addr == 0) {
            BPF_PROBE_READ_INTO(&info->s_addr, s, __sk_common.skc_rcv_saddr);
        }
        BPF_PROBE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_PROBE_READ_INTO(&info->d_addr, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        if (info->d_addr == 0) {
            BPF_PROBE_READ_INTO(&info->d_addr, s, __sk_common.skc_daddr);
        }

        return true;
    }

    return false;
}

static __always_inline bool likely_ephemeral_port(u16 port) {
    return port >= EPHEMERAL_PORT_MIN;
}

static __always_inline void *find_msghdr_buf(struct msghdr *msg) {
    unsigned int m_flags;
    struct iov_iter msg_iter;

    bpf_probe_read_kernel(&m_flags, sizeof(unsigned int), &(msg->msg_flags));
    bpf_probe_read_kernel(&msg_iter, sizeof(struct iov_iter), &(msg->msg_iter));

    u8 msg_iter_type = 0;

    bpf_probe_read(&msg_iter_type, sizeof(u8), &(msg_iter.iter_type));

    struct iovec *iov = NULL;

    bpf_probe_read(&iov, sizeof(struct iovec *), &(msg_iter.iov));

    if (!iov) {
        return NULL;
    }

    if (msg_iter_type == 6) {// Direct char buffer
        bpf_printk("direct char buffer type=6 iov %llx", iov);
        return iov;
    }

    struct iovec vec;
    bpf_probe_read(&vec, sizeof(struct iovec), iov);

    return vec.iov_base;
}

static __always_inline void handle_tcp_connection(connection_info_t *conn, void *u_buf, int bytes_len) {
    connection_pid_info_t *exist_info = bpf_map_lookup_elem(&filtered_connections, conn);
    if (exist_info) {
//        bpf_printk("pid info existed!\n");
        return;
    }
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    connection_pid_info_t info = {};
    info.pid = pid;
    info.tgid = id;
    bpf_get_current_comm(&info.fcomm, sizeof(info.fcomm));
    bpf_map_update_elem(&filtered_connections, conn, &info, BPF_NOEXIST);
}

static __always_inline void *get_pid_info(u32 s_addr,u32 d_addr, u16 s_port, u16 d_port) {
    connection_info_t conn = {};
	conn.s_port = bpf_ntohs(s_port);
	conn.d_port = bpf_ntohs(d_port);
	conn.s_addr = s_addr;
	conn.d_addr = d_addr;
	connection_pid_info_t *pid_info = bpf_map_lookup_elem(&filtered_connections, &conn);
    if (pid_info) {
        return pid_info;
    }
    return NULL;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
//    bpf_printk("=== tcp_sendmsg ret id=%d ===\n", id);

    if (id == 0) {
        return 0;
    }
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

//    bpf_printk("=== kprobe tcp_sendmsg=%d sock=%llx size %d===\n", id, sk, size);

    connection_info_t info = {};

    if (parse_sock_info(sk, &info)) {

        if (size > 0) {
            void *iovec_ptr = find_msghdr_buf(msg);
            if (iovec_ptr) {
                  handle_tcp_connection(&info, iovec_ptr, size);
            } else {
//                bpf_printk("can't find iovec ptr in msghdr, not tracking sendmsg\n");
            }
        }
    }

    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (id == 0) {
        return 0;
    }

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

//    bpf_printk("=== tcp_recvmsg id=%d sock=%llx ===\n", id, sk);

    // Important: We must work here to remember the iovec pointer, since the msghdr structure
    // can get modified in non-reversible way if the incoming packet is large and broken down in parts.
    recv_args_t args = {
        .sock_ptr = (u64)sk,
        .iovec_ptr = (u64)find_msghdr_buf(msg)
    };

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
//    bpf_printk("=== tcp_recvmsg ret id=%d ===\n", id);

    if (id == 0) {
        return 0;
    }

    int copied_len = PT_REGS_RC(ctx);

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);
    bpf_map_delete_elem(&active_recv_args, &id);

    if (!args || (copied_len <= 0)) {
//        bpf_printk("failed to find args or copied_len <= 0, ignoring this tcp_recvmsg\n");
        return 0;
    }

//    bpf_printk("=== tcp_recvmsg ret id=%d sock=%llx copied_len %d ===\n", id, args->sock_ptr, copied_len);

    connection_info_t info = {};

    if (parse_sock_info((struct sock *)args->sock_ptr, &info)) {
          handle_tcp_connection(&info, (void *)args->iovec_ptr, copied_len);
    }

    return 0;
}

SEC("kprobe/tcp_close")
int kprobe_tcp_close(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (id == 0) {
        return 0;
    }

    bpf_map_delete_elem(&active_recv_args, &id);

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    connection_info_t info = {};
    if (parse_sock_info(sk, &info)) {
        bpf_map_delete_elem(&filtered_connections, &info);
        bpf_map_delete_elem(&grpc_connections, &info);
    }

    return 0;
}
