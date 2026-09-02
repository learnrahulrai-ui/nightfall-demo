#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../common/classify.h"
#include "../common/dlp_event.h"
#include "../common/policy.h"

typedef int (*real_SSL_write_t)(void *ssl, const void *buf, int num);
static real_SSL_write_t real_SSL_write;

static void process_event(struct dlp_event *event)
{
    event->level = classify(event->bytes, event->byte_count);
    event->action = policy_action(event->level);

    fprintf(stderr,
            "source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n",
            event->source, event->pid, event->uid, event->byte_count,
            event->level, event->action);
}

__attribute__((constructor))
static void init(void) { real_SSL_write = (real_SSL_write_t)dlsym(RTLD_NEXT, "SSL_write"); }

int SSL_write(void *ssl, const void *buf, int num)
{
    if (!real_SSL_write) init();

    struct dlp_event event;
    memset(&event, 0, sizeof(event));
    event.source = DLP_NETWORK;
    event.pid = (int)getpid();
    event.uid = (int)getuid();
    event.byte_count = num > DLP_BYTES ? DLP_BYTES : num;
    if (event.byte_count < 0)
        event.byte_count = 0;
    if (event.byte_count > 0)
        memcpy(event.bytes, buf, event.byte_count);
    process_event(&event);

    return real_SSL_write(ssl, buf, num);
}
