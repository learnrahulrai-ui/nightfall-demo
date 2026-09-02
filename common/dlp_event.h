#ifndef DLP_EVENT_H
#define DLP_EVENT_H

#define DLP_BYTES 4096

enum {
    DLP_CLIPBOARD = 1,
    DLP_FILE      = 2,
    DLP_NETWORK   = 3
};

enum {
    DLP_ALLOW = 0,
    DLP_AUDIT = 1,
    DLP_DENY  = 2
};

struct dlp_event {
    int source;
    int pid;
    int uid;
    char bytes[DLP_BYTES];
    int byte_count;
    int level;
    int action;
};

#endif
