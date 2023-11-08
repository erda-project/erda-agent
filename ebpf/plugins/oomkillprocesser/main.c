#include <linux/kconfig.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/oom.h>
#include <linux/cgroup.h>
#include <linux/kernfs.h>
#include <stdio.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define SYM_LEN 50

struct oom_stats {
    // Pid of triggering process
    __u32 pid;
    // Total number of pages
     long pages;
    __u64 knid;
    char fcomm[TASK_COMM_LEN];
    char cgroup_path[129];
};

union kernfs_node_id {
	struct {
		/*
		 * blktrace will export this struct as a simplified 'struct
		 * fid' (which is a big data struction), so userspace can use
		 * it to find kernfs node. The layout must match the first two
		 * fields of 'struct fid' exactly.
		 */
		u32		ino;
		u32		generation;
	};
	u64			id;
};

struct kernfs_node___old {
	union kernfs_node_id id;
};

static inline __attribute__((always_inline)) const char *
__get_cgroup_kn_name(const struct kernfs_node *kn)
{
	const char *name = NULL;

	if (kn)
		bpf_probe_read(&name, sizeof(name), (void *)&kn->name);

	return name;
}


struct bpf_map_def SEC("maps/package_map") oom_map = {
  	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct oom_stats),
	.max_entries = 1024 * 16,
};

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

//static int get_dir_by_knid(int kn_id, char *buf, unsigned int size)
//{
//	FILE *fp = NULL;
//	char cmd[SYM_LEN];
//
//	sprintf(cmd, "find /sys/fs/cgroup/memory/ -inum %d", kn_id);
//
//	fp = popen(cmd, "r");
//	if (fp == NULL) {
//		return -1;
//	}
//
//	fgets(buf, size, fp);
//
//	pclose(fp);
////	bpf_trace_printk(cmd, sizeof(cmd));
//
//	return 0;
//}

SEC("kprobe/oom_kill_process")
int kprobe_oom_kill_process(struct pt_regs *ctx) {
    struct oom_control *oc = (struct oom_control *)PT_REGS_PARM1(ctx);
    struct task_struct *p;
    bpf_probe_read(&p, sizeof(p), &oc->chosen);
    if (!p) {
        return 0;
    }
    struct oom_stats data = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&oom_map, &pid, &data, BPF_NOEXIST);
    struct oom_stats *s = bpf_map_lookup_elem(&oom_map, &pid);
    if (!s) {
        bpf_map_update_elem(&oom_map, &pid, &data, BPF_ANY);
        return 0;
    }

    s->pid = pid;
//    get_cgroup_name(s->.cgroup_path, sizeof(s->cgroup_path));
    bpf_probe_read(&s->pages, sizeof(s->pages), &oc->totalpages);
    bpf_get_current_comm(&s->fcomm, sizeof(s->fcomm));

    struct task_struct *cur_tsk;
    cur_tsk = (struct task_struct *)bpf_get_current_task();
    if (cur_tsk == NULL) {
        bpf_printk("failed to get cur task\n");
        return 1;
    }
    struct css_set *cur_cgroups;
    if (bpf_probe_read(&cur_cgroups, sizeof(cur_cgroups), (void *)&cur_tsk->cgroups) < 0) {
        bpf_printk("failed to get task cgroups\n");
        return 1;
    }

    struct cgroup_subsys_state *cur_subsys;
    int cgrp_id = 0;
    if (bpf_probe_read(&cur_subsys, sizeof(cur_subsys), (void *)&cur_cgroups->subsys[cgrp_id]) < 0 ) {
        bpf_printk("failed to get cgroup subsys\n");
        return 1;
    }

    struct cgroup *cur_cgroup;
    if (bpf_probe_read(&cur_cgroup, sizeof(cur_cgroup), (void *)&cur_subsys->cgroup) < 0 ) {
        bpf_printk("failed to get cgroup\n");
        return 1;
    }

    struct kernfs_node *cur_kn;
    if (bpf_probe_read(&cur_kn, sizeof(cur_kn), (void *)&cur_cgroup->kn) < 0 ) {
        bpf_printk("failed to get kernfs node\n");
        return 1;
    }

    union kernfs_node_id id;
    if (bpf_probe_read(&id, sizeof(union kernfs_node_id), (void *)&cur_kn->id) < 0) {
        bpf_printk("failed to get kernfs node id\n");
        return 1;
    }

    if (bpf_probe_read_kernel_str(s->cgroup_path, sizeof(s->cgroup_path), &cur_kn->name) < 0) {
        bpf_printk("failed to get kernfs node name: %s\n", s->cgroup_path);
        return 1;
    }

//    char idfmt[] = "oom process cgroup knid: %d, pages: %d, name: %s\n";
//    bpf_trace_printk(idfmt, sizeof(idfmt), s->knid, s->pages, s->cgroup_path);
    return 0;
}


char _license[] SEC("license") = "GPL";