/*
 * dlp.bpf.c — kernel-side Data Loss Prevention enforcer (eBPF LSM).
 *
 * Design in one line: a process that reads a registered secret file is
 * "tainted"; the taint follows it (and its fork() children) through per-task
 * storage; a tainted process is denied outbound network connections. The
 * kernel therefore enforces the data boundary without trusting userspace.
 *
 * Hooks (all LSM, so returning a negative errno vetoes the operation):
 *   lsm/file_open      — cheap {major,minor,ino} gate, then taint via task_storage
 *   lsm/task_alloc     — copy taint parent -> child before the child runs
 *   lsm/socket_connect — family gate, then taint check, then -EPERM + ringbuf audit
 *   lsm/socket_sendmsg — same enforcement point for already-connected sockets
 *
 * Kernel assumptions: BPF LSM enabled (CONFIG_BPF_LSM=y, "bpf" in
 * /sys/kernel/security/lsm), BTF present, task-local storage (>= 5.11).
 */

/* Kernel data types generated from BTF (vmlinux). */
#include "vmlinux.h"
/* BPF helper prototypes and the SEC() attribute macro. */
#include <bpf/bpf_helpers.h>
/* BPF_PROG() — unpacks LSM hook context arguments automatically. */
#include <bpf/bpf_tracing.h>
/* CO-RE field-read macros (bpf_core_read / BPF_CORE_READ). */
#include <bpf/bpf_core_read.h>

/* GPL required for LSM attachment and GPL-only BPF helpers. */
char LICENSE[] SEC("license") = "GPL";

/* vmlinux.h supplies types, not macros like EPERM. */
#define EPERM 1

/* Set when clone() creates a new thread in the same thread group (vs a new process). */
#define CLONE_THREAD 0x00010000

/* Kernel 32-bit dev_t: low 20 bits minor, high 12 bits major (20 + 12 = 32). */
#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)
#define MAJOR(dev) ((__u32)((dev) >> MINORBITS))
#define MINOR(dev) ((__u32)((dev) & MINORMASK))

/* Which action a ring-buffer record describes. */
enum event_kind
{
    EVENT_FILE_OPEN = 1,
    EVENT_NET_BLOCK = 2,
    EVENT_NET_ALERT = 3,
};

/* Audit record streamed to the userspace loader. */
struct nightfall_event
{
    __u32 pid;
    __u32 kind;
    char path[128];
    __u8 level;
};

/* Sensitivity at or above which we deny the network operation (PAN and up). */
#define BLOCK_LEVEL 2

/* Per-process taint, attached to the task_struct via BPF local storage. */
struct taint_val
{
    char file_path_inside_task[128];
    __u8 level;
};

/*
 * Task-local storage: one taint_val per task_struct. Freed automatically when
 * the task exits, which sidesteps PID-reuse races that a PID-keyed hash has.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct taint_val);
} nightfall_payload SEC(".maps");

/* Ring buffer for streaming audit events to userspace. */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} event_map_of_path_kind SEC(".maps");

/*
 * Physical file identity: superblock {major, minor} plus inode number.
 * Symlinks/hardlinks/relative paths all resolve to the same inode, so this is
 * the identity the loader registers and the kernel matches on.
 */
struct file_id
{
    __u32 major;
    __u32 minor;
    __u64 ino;
};

/* Set of protected files, populated from userspace by the loader. */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct file_id);
    __type(value, __u8);
} map_of_fileid_without_paths SEC(".maps");

/*
 * socket_connect — enforcement point.
 *
 * Order matters and each step is a guard against bricking the host:
 *   1. Honor the LSM chain: if an earlier module already denied, return its ret.
 *   2. Family gate FIRST — only inspect AF_INET(2)/AF_INET6(10). Inspecting
 *      AF_UNIX would block X11/DBus/systemd IPC and freeze the desktop.
 *   3. No taint payload => process never touched a secret => ALLOW. Default-deny
 *      here would cut apt/curl/systemd off the network and brick the box.
 *   4. Tainted at/above BLOCK_LEVEL => audit + -EPERM (deny). Below => alert only.
 */
SEC("lsm/socket_connect")
int BPF_PROG(dlp_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret)
        return ret;

    short family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family != 2 && family != 10)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    /* Per-PROCESS taint: key on the thread-group leader so every thread of the
     * process shares one taint — including threads that existed before the read. */
    struct task_struct *leader = task->group_leader;
    struct taint_val *t = bpf_task_storage_get(&nightfall_payload, leader, 0, 0);

    if (!t)
        return 0;

    __u32 kind = t->level >= BLOCK_LEVEL ? EVENT_NET_BLOCK : EVENT_NET_ALERT;

    struct nightfall_event *e = bpf_ringbuf_reserve(&event_map_of_path_kind, sizeof(*e), 0);

    /* reserve() returns NULL when the buffer is full; writing through NULL is
     * rejected by the verifier, so the record is best-effort. */
    if (e)
    {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->kind = kind;
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), t->file_path_inside_task);
        e->level = t->level;
        bpf_ringbuf_submit(e, 0);
    }

    return kind == EVENT_NET_BLOCK ? -EPERM : 0;
}

/*
 * file_open — taint source.
 *
 *   1. Honor the LSM chain (SELinux/AppArmor may have already denied).
 *   2. Regular files only: mask all four type bits (0170000) and require
 *      S_IFREG (0100000). Skips symlinks/sockets/devices cheaply.
 *   3. Build the {major,minor,ino} key zero-initialized ({0}) so struct
 *      padding is not compared as garbage by the kernel's memcmp lookup.
 *   4. Not in the protected set => ALLOW (never default-deny file opens).
 *   5. Protected => attach/raise task taint (F_CREATE makes the payload on
 *      first touch). We deliberately do NOT block the read: blocking here
 *      tips off the attacker. Observe silently, deny later at the network.
 */
SEC("lsm/file_open")
int BPF_PROG(dlp_open, struct file *file, int ret)
{
    if (ret)
        return ret;

    unsigned short mode = 0;
    bpf_core_read(&mode, sizeof(mode), &file->f_inode->i_mode);
    if ((mode & 0170000) != 0100000)
        return 0; /* not S_IFREG */

    struct file_id id = {0};
    bpf_core_read(&id.ino, sizeof(id.ino), &file->f_inode->i_ino);

    __u32 dev = 0;
    bpf_core_read(&dev, sizeof(dev), &file->f_inode->i_sb->s_dev);
    id.major = MAJOR(dev);
    id.minor = MINOR(dev);

    __u8 *is_protected = bpf_map_lookup_elem(&map_of_fileid_without_paths, &id);
    if (!is_protected)
        return 0;
    __u8 level = *is_protected;

    struct task_struct *task = bpf_get_current_task_btf();
    /* Taint the PROCESS (group leader), not just this thread. */
    struct task_struct *leader = task->group_leader;

    /* F_CREATE: the payload does not exist until the first protected open. */
    struct taint_val *t = bpf_task_storage_get(&nightfall_payload, leader, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (t)
    {
        bpf_d_path(&file->f_path, t->file_path_inside_task, sizeof(t->file_path_inside_task));
        if (level > t->level)
            t->level = level;
    }

    return 0;
}

/*
 * task_alloc — taint propagation across fork().
 *
 * A tainted parent can fork a child that inherits the already-open file
 * descriptor in RAM and never calls open() itself (the "fork bypass"). We copy
 * the parent's taint into the brand-new child before it runs. The current task
 * at task_alloc is the PARENT; `task` is the new child. We never block fork()
 * itself — plenty of benign programs fork workers after reading files.
 */
SEC("lsm/task_alloc")
int BPF_PROG(dlp_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret)
{
    if (ret)
        return ret;

    struct task_struct *nightfall_parent = bpf_get_current_task_btf();
    /* Read the parent's taint from its group leader (per-process key). */
    struct task_struct *parent_leader = nightfall_parent->group_leader;
    struct taint_val *parent_taint = bpf_task_storage_get(&nightfall_payload, parent_leader, 0, 0);

    if (!parent_taint)
        return 0; /* clean parent -> clean child */

    /* CLONE_THREAD: the new thread shares the parent's group leader, whose taint
     * already covers it via the per-process key — nothing to copy. */
    if (clone_flags & CLONE_THREAD)
        return 0;

    /* A new PROCESS becomes its own group leader once it runs, so store the taint
     * on the child task directly (child->group_leader is not wired up yet here). */
    struct taint_val *child_taint = bpf_task_storage_get(&nightfall_payload, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (child_taint)
    {
        bpf_probe_read_kernel_str(child_taint->file_path_inside_task,
                                  sizeof(child_taint->file_path_inside_task),
                                  parent_taint->file_path_inside_task);
        child_taint->level = parent_taint->level;
    }

    return 0;
}

/*
 * socket_sendmsg — same enforcement as socket_connect, for sockets that are
 * already connected (e.g. UDP, or a connection opened before taint). Family
 * gate first, then taint check; deny with audit at/above BLOCK_LEVEL, alert
 * (allow) for a lower non-zero level.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(dlp_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    short family = 0;
    bpf_core_read(&family, sizeof(family), &sock->sk->__sk_common.skc_family);
    if (family != 2 && family != 10)
        return 0;

    struct task_struct *task = bpf_get_current_task_btf();
    /* Per-PROCESS taint: check the thread-group leader. */
    struct task_struct *leader = task->group_leader;

    struct taint_val *t = bpf_task_storage_get(&nightfall_payload, leader, 0, 0);
    if (!t)
    {
        return 0;
    }

    if (t->level >= BLOCK_LEVEL)
    {
        struct nightfall_event *e = bpf_ringbuf_reserve(&event_map_of_path_kind, sizeof(*e), 0);
        if (!e)
            return 0;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->kind = EVENT_NET_BLOCK;
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), t->file_path_inside_task);
        e->level = t->level;
        bpf_ringbuf_submit(e, 0);
        return -EPERM;
    }
    else if (t->level > 0)
    {
        struct nightfall_event *e = bpf_ringbuf_reserve(&event_map_of_path_kind, sizeof(*e), 0);
        if (!e)
            return 0;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->kind = EVENT_NET_ALERT;
        bpf_probe_read_kernel_str(e->path, sizeof(e->path), t->file_path_inside_task);
        e->level = t->level;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    return 0;
}
