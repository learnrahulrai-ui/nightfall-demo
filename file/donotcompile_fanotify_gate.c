#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define WATCH_DIR "/tmp/dlp-protected"
#define MAX_BYTES 4096

struct dlp_event {
    int source;
    int pid;
    int uid;
    char bytes[MAX_BYTES];
    int byte_count;
    int level;
    int action;
};

static int luhn(const char *d, int n) {
    int sum = 0, alt = 0;
    for (int i = n - 1; i >= 0; i--) {
        if (d[i] < '0' || d[i] > '9') return 0;
        int v = d[i] - '0';
        if (alt) { v *= 2; if (v > 9) v -= 9; }
        sum += v;
        alt = !alt;
    }
    return (sum % 10) == 0;
}

int classify(const char *bytes, int n)
{
    int level = 0;
    if (memmem(bytes, n, "AKIA", 4))
        level = 3;
    for (int i = 0; i + 16 <= n; i++) {
        int digits = 1;
        for (int j = 0; j < 16; j++) if (bytes[i+j] < '0' || bytes[i+j] > '9') { digits = 0; break; }
        if (digits && luhn(bytes+i, 16) && level < 2) level = 2;
    }
    for (int i = 0; i + 11 <= n; i++) {
        if (bytes[i] >= '0' && bytes[i] <= '9' && bytes[i+1] >= '0' && bytes[i+1] <= '9' && bytes[i+2] >= '0' && bytes[i+2] <= '9' && bytes[i+3] == '-' && bytes[i+4] >= '0' && bytes[i+4] <= '9' && bytes[i+5] >= '0' && bytes[i+5] <= '9' && bytes[i+6] == '-' && bytes[i+7] >= '0' && bytes[i+7] <= '9' && bytes[i+8] >= '0' && bytes[i+8] <= '9' && bytes[i+9] >= '0' && bytes[i+9] <= '9' && bytes[i+10] >= '0' && bytes[i+10] <= '9') {
            if (level < 1) level = 1;
            break;
        }
    }
    return level;
}

int main(void)
{
    /* YOU TYPE 1: fanotify_init FAN_CLASS_CONTENT O_RDONLY */
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
    if (fan_fd < 0) {
        perror("fanotify_init");
        return 1;
    }
    /* YOU TYPE 2: fanotify_mark FAN_MARK_ADD FAN_OPEN_PERM|FAN_EVENT_ON_CHILD */
    int mark_result = fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, WATCH_DIR);
    if (mark_result < 0) {
        perror("fanotify_mark");
        return 2;
    }
    printf("watching %s\n", WATCH_DIR);
    fflush(stdout);
    char event_buffer[4096];
    for (;;) {
        ssize_t bytes_read = read(fan_fd, event_buffer, sizeof(event_buffer));
        struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)event_buffer;
        while (FAN_EVENT_OK(metadata, bytes_read)) {
            if (metadata->fd >= 0) {
                /* YOU TYPE 3: self-deadlock check — if pid == getpid() → FAN_ALLOW */
                // if (metadata->pid == (int)getpid()) { ... }
                if (metadata->pid == (int)getpid()) {
                    struct fanotify_response resp;
                    resp.fd = metadata->fd;
                    resp.response = FAN_ALLOW;
                    write(fan_fd, &resp, sizeof(resp));
                    close(metadata->fd);
                    continue;
                }


                struct dlp_event event;
                memset(&event, 0, sizeof(event));
                event.source = 2;
                event.pid = metadata->pid;
                lseek(metadata->fd, 0, SEEK_SET);
                event.byte_count = (int)read(metadata->fd, event.bytes, sizeof(event.bytes));
                event.level = classify(event.bytes, event.byte_count);
                struct fanotify_response response;
                response.fd = metadata->fd;
                if (event.level >= 2) {
                    event.action = 2;
                    response.response = FAN_DENY;
                } else {
                    event.action = 0;
                    response.response = FAN_ALLOW;
                }
                printf("pid=%d bytes=%d level=%d action=%d\n", event.pid, event.byte_count, event.level, event.action);
                fflush(stdout);
                write(fan_fd, &response, sizeof(response));
                close(metadata->fd);
            }
            metadata = FAN_EVENT_NEXT(metadata, bytes_read);
        }
    }
}
