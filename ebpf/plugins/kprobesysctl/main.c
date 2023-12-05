#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define POD_UID_LEN 36
#define CONTAINER_ID_LEN 64

struct kprobe_sysctl_stat {
    __u32 pid;
    __u32 cgroupid;
    char poduid[POD_UID_LEN];
    char containerid[CONTAINER_ID_LEN];
};

struct bpf_map_def SEC("maps") kprobe_sysctl_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct kprobe_sysctl_stat),
    .max_entries = 1024,
};

SEC("kprobe/sys_clone")
int kprobe_sysctl_prog(struct pt_regs *ctx) {
    struct kprobe_sysctl_stat stat = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&kprobe_sysctl_map, &pid, &stat, BPF_NOEXIST);
    struct kprobe_sysctl_stat *s = bpf_map_lookup_elem(&kprobe_sysctl_map, &pid);
    if (!s) {
        bpf_map_update_elem(&kprobe_sysctl_map, &pid, &stat, BPF_ANY);
        return 0;
    }

    s->pid = pid;
    __u32 cgroupid = bpf_get_current_cgroup_id();
    s->cgroupid = cgroupid;
    return 0;
}

char _license[] SEC("license") = "GPL";