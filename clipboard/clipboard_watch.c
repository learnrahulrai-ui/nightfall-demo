#define _GNU_SOURCE
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/extensions/Xfixes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct dlp_event {
    int source;
    int pid;
    int uid;
    char bytes[4096];
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
    Display *d = XOpenDisplay(NULL);
    if (!d)
        return 1;
    Window root = DefaultRootWindow(d);
    Window win = XCreateSimpleWindow(d, root, 0, 0, 1, 1, 0, 0, 0);
    Atom clip = XInternAtom(d, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(d, "UTF8_STRING", False);
    Atom prop = XInternAtom(d, "DLP_CLIP", False);
    int ev_base = 0, err_base = 0;
    if (!XFixesQueryExtension(d, &ev_base, &err_base))
        return 2;
    XFixesSelectSelectionInput(d, root, clip, XFixesSetSelectionOwnerNotifyMask);
    for (;;) {
        XEvent e;
        XNextEvent(d, &e);
        if (e.type == ev_base + XFixesSelectionNotify) {
            printf("clipboard changed\n");
            XConvertSelection(d, clip, utf8, prop, win, CurrentTime);
            XFlush(d);
        }
        if (e.type == SelectionNotify) {
            if (e.xselection.property == None)
                continue;
            Atom actual_type;
            int actual_format;
            unsigned long count = 0, bytes_after = 0;
            unsigned char *data = NULL;
            XGetWindowProperty(d, win, prop, 0, 4096 / 4, True, AnyPropertyType, &actual_type, &actual_format, &count, &bytes_after, &data);
            struct dlp_event event;
            memset(&event, 0, sizeof(event));
            event.source = 1;
            event.pid = (int)getpid();
            event.uid = (int)getuid();
            memcpy(event.bytes, data, count);
            event.byte_count = (int)count;
            event.level = classify(event.bytes, event.byte_count);
            printf("source=%d pid=%d uid=%d bytes=%d level=%d text=[%.*s]\n", event.source, event.pid, event.uid, event.byte_count, event.level, event.byte_count, event.bytes);
            fflush(stdout);
            XFree(data);
        }
    }
}
