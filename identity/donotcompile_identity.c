#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static void read_link_value(const char *path, char *buffer, int size)
{
    ssize_t n = readlink(path, buffer, size - 1);
    if (n < 0) {
        strcpy(buffer, "unknown");
        return;
    }
    buffer[n] = '\0';
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s PID\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    char path[256];
    char exe[512];
    char pid_ns[128];
    char mnt_ns[128];
    char net_ns[128];
    /* YOU TYPE 1: exe link /proc/%d/exe */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    read_link_value(path, exe, sizeof(exe));
    /* YOU TYPE 2: pid_ns /proc/%d/ns/pid */
    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);
    read_link_value(path, pid_ns, sizeof(pid_ns));
    /* YOU TYPE 3: mnt_ns /proc/%d/ns/mnt */
    snprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    read_link_value(path, mnt_ns, sizeof(mnt_ns));
    /* YOU TYPE 4: net_ns /proc/%d/ns/net */
    snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
    read_link_value(path, net_ns, sizeof(net_ns));
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *file = fopen(path, "r");
    char cgroup[512] = {};
    if (file) {
        if (fgets(cgroup, sizeof(cgroup), file)) {
            cgroup[strcspn(cgroup, "\n")] = '\0';
        }
        fclose(file);
    }
    printf("pid=%d\n", pid);
    printf("exe=%s\n", exe);
    printf("pid_ns=%s\n", pid_ns);
    printf("mnt_ns=%s\n", mnt_ns);
    printf("net_ns=%s\n", net_ns);
    printf("cgroup=%s\n", cgroup);
    return 0;
}
