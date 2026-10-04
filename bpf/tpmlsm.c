// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct digest { u8 b[32]; };

// The SHA-256 of every allowed binary. The loader fills this in and then
// locks it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct digest);
    __type(value, u8);
} allowed_hashes SEC(".maps");

// The allowed files themselves, by device and inode number. Exec looks here
// first, so it only has to hash files that are on the list. Also filled in by
// the loader and then locked.
struct file_id {
    u64 ino;
    u32 dev;
    u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct file_id);
    __type(value, u8);
} allowed_files SEC(".maps");

// The device numbers of /dev/tpm0 and /dev/tpmrm0. Filled in by the loader
// and then locked.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u8);
} tpm_devs SEC(".maps");

// For each process: may it use the TPM? 1 for yes, 0 for no. A process
// without an entry counts as no.
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
// Makes bpf2go generate a Go type for struct event.
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// 1. Exec. When a process starts a program from one of the listed files, hash
//    the file and remember whether it matched. Any other program costs just
//    one map lookup.
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(on_exec, struct linux_binprm *bprm)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *inode = bprm->file->f_inode;
    struct file_id id = {
        .ino = inode->i_ino,
        .dev = inode->i_sb->s_dev,
    };

    if (!bpf_map_lookup_elem(&allowed_files, &id)) {
        // Not on the list. If the parent was allowed, this process isn't
        // anymore.
        u8 *ok = bpf_task_storage_get(&task_ok, task, 0, 0);
        if (ok)
            *ok = 0;
        return 0;
    }

    struct digest h = {};
    long algo = bpf_ima_file_hash(bprm->file, h.b, sizeof(h.b));

    u8 *ok = bpf_task_storage_get(&task_ok, task, 0,
                                  BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ok)
        return 0;

    // Only a SHA-256 that is on the list counts.
    *ok = (algo == HASH_ALGO_SHA256 &&
           bpf_map_lookup_elem(&allowed_hashes, &h)) ? 1 : 0;
    return 0;
}

// 2. Fork and new threads. The child gets a yes if its parent had one.
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

// 3. Open. Only processes with a yes may open the TPM.
SEC("lsm/file_open")
int BPF_PROG(tpm_open, struct file *file, int ret)
{
    if (ret)
        return ret;

    // Read the field directly. BPF_CORE_READ would go through bpf_probe_read,
    // and lockdown=confidentiality doesn't allow that.
    u32 dev = file->f_inode->i_rdev;
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
