#include <X11/Xlib.h>
#include <X11/extensions/Xfixes.h>
#include <bpf/libbpf.h>
#include "../common/dlp_event.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <unistd.h>


#include "../common/classify.h"
#include "../common/policy.h"

enum {
  NIGHTFALL_EVENT_NET_BLOCK = 2,
  NIGHTFALL_EVENT_NET_ALERT = 3,
};

struct nightfall_event {
  uint32_t pid;
  uint32_t kind;
  char path[128];
  uint8_t level;
};

_Static_assert(sizeof(struct nightfall_event) == 140,
               "nightfall_event ABI must match the BPF program");

static void emit_event(const struct dlp_event *e) {
  printf("source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n", e->source,
         e->pid, e->uid, e->byte_count, e->level, e->action);
}

static void process_event(struct dlp_event *e) {
  e->level = classify(e->bytes, e->byte_count);
  e->action = policy_action(e->level);
  emit_event(e);
}

static int send_fanotify_response(int fan_fd, int event_fd,
                                  uint32_t response_value) {
  struct fanotify_response response = {
      .fd = event_fd,
      .response = response_value,
  };
  ssize_t written;

  do {
    written = write(fan_fd, &response, sizeof(response));
  } while (written < 0 && errno == EINTR);

  if (written != (ssize_t)sizeof(response)) {
    perror("fanotify response");
    return -1;
  }
  return 0;
}

static int process_bpf_event(void *ctx, void *data, size_t sz) {
  (void)ctx;

  if (sz != sizeof(struct nightfall_event)) {
    fprintf(stderr, "invalid BPF event size: got %zu expected %zu\n", sz,
            sizeof(struct nightfall_event));
    return 0;
  }

  struct nightfall_event kernel_event;
  memcpy(&kernel_event, data, sizeof(kernel_event));

  if (kernel_event.kind != NIGHTFALL_EVENT_NET_BLOCK &&
      kernel_event.kind != NIGHTFALL_EVENT_NET_ALERT) {
    fprintf(stderr, "unknown BPF event kind: %u\n", kernel_event.kind);
    return 0;
  }

  struct dlp_event event = {0};
  event.source = DLP_NETWORK;
  event.pid = (int)kernel_event.pid;
  event.uid = -1;
  event.byte_count = (int)strnlen(kernel_event.path, sizeof(kernel_event.path));
  memcpy(event.bytes, kernel_event.path, event.byte_count);
  event.level = kernel_event.level;
  event.action = policy_action(event.level);
  emit_event(&event);
  return 0;
}

int main(void) {
  Display *display = XOpenDisplay(NULL);
  if (!display)
    return 1;
  Window win = XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1,
                                   1, 0, 0, 0);
  Atom clip = XInternAtom(display, "CLIPBOARD", False);
  Atom targets = XInternAtom(display, "TARGETS", False);
  Atom utf8 = XInternAtom(display, "UTF8_STRING", False);
  Atom targets_property = XInternAtom(display, "DLP_TARGETS", False);
  Atom data_property = XInternAtom(display, "DLP_CLIPBOARD_DATA", False);
  int ev_base = 0, err_base = 0;
  if (!XFixesQueryExtension(display, &ev_base, &err_base))
    return 2;
  XFixesSelectSelectionInput(display, DefaultRootWindow(display), clip,
                             XFixesSetSelectionOwnerNotifyMask);
  XFlush(display);
  int clip_fd = ConnectionNumber(display);
  printf("clip_fd=%d\n", clip_fd);
  int inotify_fd = inotify_init1(0);
  if (inotify_fd < 0) {
    perror("inotify_init1");
    return 10;
  }
  int wd = inotify_add_watch(inotify_fd, "/tmp/dlp-test",
                             IN_CLOSE_WRITE | IN_MOVED_TO);
  if (wd < 0) {
    perror("inotify_add_watch");
    return 11;
  }
  printf("inotify_fd=%d wd=%d\n", inotify_fd, wd);
  int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
  if (fan_fd < 0) {
    perror("fanotify_init");
    return 12;
  }
  int fan_mark =
      fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
                    AT_FDCWD, "/tmp/dlp-protected");
  if (fan_mark < 0) {
    perror("fanotify_mark");
    return 13;
  }
  printf("fan_fd=%d fan_mark=%d\n", fan_fd, fan_mark);
  struct bpf_object *obj = bpf_object__open_file(
      "bpf/dlp.bpf.o", NULL);
  if (!obj) {
    fprintf(stderr, "open dlp.bpf.o: %s\n", strerror(errno));
    return 3;
  }
  if (bpf_object__load(obj)) {
    fprintf(stderr, "load dlp.bpf.o: %s\n", strerror(errno));
    return 4;
  }
  struct bpf_program *prog;
  struct bpf_link *links[4] = {};
  int nlinks = 0;
  (void)links;
  bpf_object__for_each_program(prog, obj) {
    if (nlinks >= (int)(sizeof(links) / sizeof(links[0]))) {
      fprintf(stderr, "too many BPF programs for links array\n");
      return 5;
    }
    struct bpf_link *l = bpf_program__attach(prog);
    if (!l) {
      fprintf(stderr, "attach %s: %s\n", bpf_program__name(prog),
              strerror(errno));
      return 5;
    }
    links[nlinks++] = l;
    printf("attached %s\n", bpf_program__name(prog));
  }
  int map_fd =
      bpf_object__find_map_fd_by_name(obj, "map_of_fileid_without_paths");
  if (map_fd < 0) {
    fprintf(stderr, "find map_of_fileid_without_paths: %s\n", strerror(errno));
    return 6;
  }
  int rb_fd = bpf_object__find_map_fd_by_name(obj, "event_map_of_path_kind");
  if (rb_fd < 0) {
    fprintf(stderr, "find event_map_of_path_kind: %s\n", strerror(errno));
    return 7;
  }
  struct ring_buffer *rb =
      ring_buffer__new(rb_fd, process_bpf_event, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
    return 8;
  }
  int rb_epoll_fd = ring_buffer__epoll_fd(rb);
  printf("bpf_fd map=%d ring=%d epoll=%d\n", map_fd, rb_fd, rb_epoll_fd);
  int epfd = epoll_create1(0);
  if (epfd < 0) {
    fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
    return 9;
  }
  struct epoll_event ev = {.events = EPOLLIN};
  ev.data.fd = clip_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, clip_fd, &ev) < 0) {
    perror("epoll_ctl clipboard");
    return 14;
  }
  ev.data.fd = inotify_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, inotify_fd, &ev) < 0) {
    perror("epoll_ctl inotify");
    return 15;
  }
  ev.data.fd = fan_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fan_fd, &ev) < 0) {
    perror("epoll_ctl fanotify");
    return 16;
  }
  ev.data.fd = rb_epoll_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, rb_epoll_fd, &ev) < 0) {
    perror("epoll_ctl BPF ring buffer");
    return 17;
  }
  printf("epoll fd=%d watching 4 fds\n", epfd);
  struct epoll_event ready[4];
  for (;;) {
    int n = epoll_wait(epfd, ready, 4, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      perror("epoll_wait");
      return 19;
    }
    for (int i = 0; i < n; i++) {
      int fd = ready[i].data.fd;
      if (fd == clip_fd) {
        XEvent e;
        while (XPending(display)) {
          XNextEvent(display, &e);
          if (e.type == ev_base + XFixesSelectionNotify) {
            XConvertSelection(display, clip, targets, targets_property, win,
                              CurrentTime);
            XFlush(display);
          } else if (e.type == SelectionNotify &&
                     e.xselection.target == targets &&
                     e.xselection.property == targets_property) {
            XConvertSelection(display, clip, utf8, data_property, win,
                              CurrentTime);
            XFlush(display);
          } else if (e.type == SelectionNotify &&
                     e.xselection.target == utf8 &&
                     e.xselection.property == data_property) {
            Atom type; int format; unsigned long nitems, bytes_after;
            unsigned char *data = NULL;
            XGetWindowProperty(display, win, data_property, 0, DLP_BYTES / 4,
                               True, AnyPropertyType, &type, &format, &nitems,
                               &bytes_after, &data);
            if (data) {
              struct dlp_event ev2 = {0};
              ev2.source = DLP_CLIPBOARD;
              ev2.byte_count = nitems < 4096 ? nitems : 4096;
              memcpy(ev2.bytes, data, ev2.byte_count);
              process_event(&ev2);
              XFree(data);
            }
          }
        }
      } else if (fd == inotify_fd) {
        char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
          perror("read inotify");
          continue;
        }
        for (char *p = buf; p < buf + len; ) {
          struct inotify_event *ev = (struct inotify_event *)p;
          if (ev->len) {
            char path[512];
            snprintf(path, sizeof(path), "/tmp/dlp-test/%s", ev->name);
            int f = open(path, O_RDONLY);
            if (f >= 0) {
              char bytes[4096];
              int n = read(f, bytes, sizeof(bytes));
              close(f);
              struct dlp_event e2 = {0};
              e2.source = DLP_FILE;
              e2.pid = 0;
              e2.uid = getuid();
              e2.byte_count = n > 0 ? n : 0;
              if (e2.byte_count > 4096) e2.byte_count = 4096;
              memcpy(e2.bytes, bytes, e2.byte_count);
              process_event(&e2);
            }
          }
          p += sizeof(struct inotify_event) + ev->len;
        }
      } else if (fd == fan_fd) {
        char fbuf[4096];
        ssize_t flen = read(fan_fd, fbuf, sizeof(fbuf));
        if (flen < 0) {
          perror("read fanotify");
          continue;
        }
        struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)fbuf;
        while (FAN_EVENT_OK(meta, flen)) {
          if (meta->vers != FANOTIFY_METADATA_VERSION) {
            fprintf(stderr, "fanotify metadata version mismatch\n");
            return 18;
          }
          if (meta->fd == FAN_NOFD) {
            if (meta->mask & FAN_Q_OVERFLOW)
              fprintf(stderr,
                      "fanotify queue overflow; permission coverage degraded\n");
            else
              fprintf(stderr, "fanotify event has no file descriptor\n");
          } else if (meta->fd < 0) {
            fprintf(stderr, "fanotify event file descriptor error: %d\n",
                    meta->fd);
          } else {
            if (meta->pid == (int)getpid()) {
              int response_result =
                  send_fanotify_response(fan_fd, meta->fd, FAN_ALLOW);
              close(meta->fd);
              if (response_result < 0)
                return 20;
            } else {
              char bytes[4096];
              lseek(meta->fd, 0, SEEK_SET);
              int n = read(meta->fd, bytes, sizeof(bytes));
              struct dlp_event e2 = {0};
              e2.source = DLP_FILE;
              e2.pid = meta->pid;
              e2.uid = 0;
              e2.byte_count = n > 0 ? n : 0;
              memcpy(e2.bytes, bytes, e2.byte_count);
              process_event(&e2);
              int response_result = send_fanotify_response(
                  fan_fd, meta->fd,
                  (e2.level >= 2) ? FAN_DENY : FAN_ALLOW);
              close(meta->fd);
              if (response_result < 0)
                return 20;
            }
          }
          meta = FAN_EVENT_NEXT(meta, flen);
        }
      } else if (fd == rb_epoll_fd) {
        ring_buffer__consume(rb);
      }
    }
  }
  return 0;
}
