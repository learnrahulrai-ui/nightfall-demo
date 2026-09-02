/*
 * loader.c — userspace agent for the Nightfall DLP enforcer.
 *
 * Responsibilities:
 *   1. Load and attach the eBPF LSM programs from bpf/dlp.bpf.o.
 *   2. Classify every file under /tmp/dlp-lab/secrets and, for anything that
 *      contains regulated content, register its {major,minor,inode} identity
 *      in the kernel's protected-file hash map.
 *   3. Drain the ring buffer and print BLOCK/ALERT audit events.
 *
 * The kernel never reads file contents; this process does the classification
 * (see src/classify.c) and hands the kernel only the physical file identity.
 */
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "classify.h"

#define EVENT_NET_BLOCK 2
#define EVENT_NET_ALERT 3

/* Must match struct nightfall_event in bpf/dlp.bpf.c byte-for-byte. */
struct nightfall_event
{
    __u32 pid;
    __u32 kind;
    char path[128];
    __u8 level;
};

/*
 * Physical file identity: superblock {major, minor} + inode. Paths lie
 * (symlinks, hardlinks, relative paths); the inode is the physical truth, so
 * this — not a path string — is what the kernel matches on. Must match struct
 * file_id in bpf/dlp.bpf.c.
 */
struct file_id
{
    __u32 major;
    __u32 minor;
    __u64 ino;
};

/* Read a file and return its sensitivity level via the shared classifier. */
static __u8 classify_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    static char buf[1 << 20];

    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n <= 0)
        return 0;

    return (__u8)classify(buf, (int)n);
}

static int register_secret(int map_fd, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
    {
        fprintf(stderr, "stat(%s) failed: %s\n", path, strerror(errno));
        return -1;
    }

    /* Zero-initialize: the kernel looks up this key with a raw memcmp, so any
     * uninitialized struct padding would make the lookup miss. */
    struct file_id key = {0};

    /* glibc's dev_t layout differs from the kernel's. Rebuild the kernel's
     * 20-bit split (minor low, major high) so userspace and kernel keys agree
     * even when a device's minor number exceeds 255. */
    __u32 u_major = major(st.st_dev);
    __u32 u_minor = minor(st.st_dev);
    __u32 raw_dev = (u_major << 20) | u_minor;

    key.major = raw_dev >> 20;
    key.minor = raw_dev & ((1U << 20) - 1);
    key.ino = st.st_ino;

    __u8 level = classify_file(path);
    if (level == 0)
    {
        printf("%s skip no regulated content\n", path);
        return 0;
    }

    if (bpf_map_update_elem(map_fd, &key, &level, BPF_ANY) != 0)
    {
        fprintf(stderr, "map update failed: %s\n", strerror(errno));
        return -1;
    }
    printf("Registered %s (level %u)\n", path, level);
    return 0;
}

/* Ring-buffer callback: one record per BLOCK/ALERT decision in the kernel. */
static int on_event(void *ctx, void *data, size_t len)
{
    (void)ctx;
    (void)len;
    struct nightfall_event *e = data;

    if (e->kind == EVENT_NET_BLOCK)
        printf("[DLP] BLOCK pid %u exfil %s (level %u)\n", e->pid, e->path, e->level);
    else if (e->kind == EVENT_NET_ALERT)
        printf("[DLP] ALERT pid %u touched %s (level %u) — allowed\n", e->pid, e->path, e->level);
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* bpf_object is the container parsed from the ELF; individual maps/programs
     * are found by name once it is loaded into the kernel. */
    struct bpf_object *obj = bpf_object__open_file("bpf/dlp.bpf.o", NULL);
    if (!obj || bpf_object__load(obj))
    {
        fprintf(stderr, "Failed to load BPF.\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "map_of_fileid_without_paths");
    if (map_fd < 0)
    {
        fprintf(stderr, "find map_of_fileid_without_paths: %s\n", strerror(errno));
        return 1;
    }

    DIR *nightfall_dir = opendir("/tmp/dlp-lab/secrets");
    if (nightfall_dir)
    {
        struct dirent *dir;
        while ((dir = readdir(nightfall_dir)) != NULL)
        {
            if (dir->d_name[0] == '.')
                continue;

            char path[512];
            snprintf(path, sizeof(path), "/tmp/dlp-lab/secrets/%s", dir->d_name);
            register_secret(map_fd, path);
        }
        closedir(nightfall_dir);
    }
    else
    {
        fprintf(stderr, "Could not open /tmp/dlp-lab/secrets directory.\n");
    }

    /* Attach every program in the object and pin the links so enforcement
     * survives if this process is restarted. */
    struct bpf_program *prog;
    struct bpf_link *links[8] = {};
    int nlinks = 0;
    bpf_object__for_each_program(prog, obj)
    {
        if (nlinks >= 8)
            return 1;
        struct bpf_link *l = bpf_program__attach(prog);
        if (!l)
        {
            const char *name = bpf_program__name(prog);
            fprintf(stderr, "Failed to attach %s: %s\n", name, strerror(errno));
            return 1;
        }
        links[nlinks++] = l;
        const char *name = bpf_program__name(prog);
        printf("Attached %s to kernel\n", name);
    }
    mkdir("/sys/fs/bpf/dlp", 0755);
    bpf_object__pin_maps(obj, "/sys/fs/bpf/dlp");
    for (int i = 0; i < nlinks; i++)
    {
        char pin[128];
        snprintf(pin, sizeof(pin), "/sys/fs/bpf/dlp/link_%d", i);
        bpf_link__pin(links[i], pin);
    }

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "event_map_of_path_kind");
    if (rb_fd < 0)
    {
        fprintf(stderr, "find event_map_of_path_kind: %s\n", strerror(errno));
        return 1;
    }
    struct ring_buffer *rb = ring_buffer__new(rb_fd, on_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "ring_buffer__new failed: %s\n", strerror(errno));
        return 1;
    }

    printf("Nightfall DLP Active. Enforcing kernel boundary...\n");
    while (ring_buffer__poll(rb, 100) >= 0)
    {
        /* Poll the ring buffer forever, dispatching to on_event(). */
    }

    return 0;
}
