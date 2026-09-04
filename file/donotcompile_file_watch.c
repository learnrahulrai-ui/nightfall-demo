#define _GNU_SOURCE
#include <sys/inotify.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define WATCH_DIR "/tmp/dlp-test"
#define MAX_BYTES 4096

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
    /* boring: init */
    int inotify_fd = inotify_init1(0); // YOU TYPE 1: inotify_init1(0)
    if (inotify_fd < 0)
        return 1;
    int watch_id = inotify_add_watch(inotify_fd, WATCH_DIR, IN_CLOSE_WRITE | IN_MOVED_TO);
    if (watch_id < 0)
        return 2;
    char event_buffer[4096];
    for (;;) {
        ssize_t event_bytes =  read(inotify_fd, event_buffer, sizeof(event_buffer)); // YOU TYPE 3: read(inotify_fd, event_buffer, sizeof(event_buffer))
        char *position = event_buffer;
        while (position < event_buffer + event_bytes) {
            struct inotify_event *event = (struct inotify_event *)position;
            char path[4096];
            snprintf(path, sizeof(path), "%s/%s", WATCH_DIR, event->name); // YOU TYPE 4: event->name
            int file_fd = open(path, O_RDONLY);
            char bytes[MAX_BYTES];
            int byte_count = (int)read(file_fd, bytes, sizeof(bytes));
            close(file_fd);
            int level = classify(bytes, byte_count);
            printf("file=%s bytes=%d level=%d\n", path, byte_count, level);
            fflush(stdout);
            position += sizeof(struct inotify_event) + event->len;
        }
    }
}
