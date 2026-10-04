// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct digest { u8 b[32]; };

// allowed_hashes holds the SHA-256 digests from the compiled-in allowlist.
// The loader fills it before attaching and then freezes it.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct digest);
    __type(value, u8);
} allowed_hashes SEC(".maps");

// allowed_files holds the (dev, ino) of every allowlisted path. on_exec checks
// it before hashing, so only allowlisted files pay for bpf_ima_file_hash.
// Filled by the loader, then frozen.
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

// tpm_devs holds the kernel dev_t of /dev/tpm0 and /dev/tpmrm0. Filled by the
// loader, then frozen.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u8);
} tpm_devs SEC(".maps");

// task_ok is the per-task verdict: 1 if the task may open the TPM. A task
// without storage is denied.
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
// Referenced so that bpf2go emits a Go type for struct event.
const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

// on_exec sets the verdict for the new program image. Non-allowlisted files
// cost one map lookup; allowlisted ones must also match on their IMA hash.
//
// bprm_committed_creds runs past the point of no return in begin_new_exec, so
// a failed exec can't leave a stale verdict behind. The program is sleepable
// (lsm.s) because bpf_ima_file_hash may sleep.
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
        // Not allowlisted: revoke any verdict inherited from the parent.
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

    // Accept SHA-256 only; IMA may be configured with another algorithm.
    *ok = (algo == HASH_ALGO_SHA256 &&
           bpf_map_lookup_elem(&allowed_hashes, &h)) ? 1 : 0;
    return 0;
}

// on_fork copies an allow verdict to new tasks, which start with empty task
// storage. Threads need it too: the Go runtime, for one, opens files from
// whichever OS thread it picks.
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

// tpm_open denies opens of the TPM devices by tasks without an allow verdict,
// and reports every attempt on the events ring buffer.
SEC("lsm/file_open")
int BPF_PROG(tpm_open, struct file *file, int ret)
{
    if (ret)
        return ret;

    // Direct read rather than BPF_CORE_READ, which uses bpf_probe_read and is
    // rejected under lockdown=confidentiality.
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
