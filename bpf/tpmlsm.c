// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct digest { u8 b[32]; };

// SHA-256 hashes of allowed binaries. Filled from Go, then frozen.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct digest);
    __type(value, u8);
} allowed_hashes SEC(".maps");

// Which devices count as "the TPM". Filled from Go, then frozen.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u8);
} tpm_devs SEC(".maps");

// Per-task "may use the TPM" answer.
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u8);
} task_ok SEC(".maps");

struct event {
    u32 pid;
    u32 dev;
    u8  comm[16];
    u8  allowed;
};
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// 1. At exec: hash the new binary, set or clear the answer.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(on_exec, struct linux_binprm *bprm)
{
    struct digest h = {};
    long algo = bpf_ima_file_hash(bprm->file, h.b, sizeof(h.b));

    u8 *ok = bpf_task_storage_get(&task_ok, bpf_get_current_task_btf(), 0,
                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ok)
        return 0;

    // Only trust a real SHA-256 that is on the list.
    *ok = (algo == HASH_ALGO_SHA256 &&
           bpf_map_lookup_elem(&allowed_hashes, &h)) ? 1 : 0;
    return 0;
}

// 2. At fork/thread creation: child inherits the parent's answer.
SEC("lsm/task_alloc")
int BPF_PROG(on_fork, struct task_struct *task, unsigned long clone_flags, int ret)
{
    if (ret)
        return ret;

    u8 *parent = bpf_task_storage_get(&task_ok, bpf_get_current_task_btf(), 0, 0);
    if (!parent || !*parent)
        return 0;

    u8 *child = bpf_task_storage_get(&task_ok, task, 0,
                                     BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (child)
        *child = 1;
    return 0;
}

// 3. At open: only allowed tasks may open the TPM.
SEC("lsm/file_open")
int BPF_PROG(tpm_open, struct file *file, int ret)
{
    if (ret)
        return ret;

    u32 dev = BPF_CORE_READ(file, f_inode, i_rdev);
    if (!bpf_map_lookup_elem(&tpm_devs, &dev))
        return 0;

    u8 *ok = bpf_task_storage_get(&task_ok, bpf_get_current_task_btf(), 0, 0);
    int allow = ok && *ok;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->dev = dev;
        e->allowed = allow;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    return allow ? 0 : -EPERM;
}
