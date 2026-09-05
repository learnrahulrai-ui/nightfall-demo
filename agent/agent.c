/*
 * agent.c — the whole Nightfall DLP userspace agent, in one file.
 *
 * Consolidated from: src/loader.c, clipboard/clipboard_watch.c,
 * common/classify.c, common/policy.c, common/dlp_event.h, common/classify.h,
 * common/policy.h. No project headers — only libc, libbpf and X11.
 *
 * Two source files exist in this project and that is the floor:
 *   bpf/dlp.bpf.c   clang -target bpf  -> kernel bytecode, verified at load
 *   agent/agent.c   gcc               -> x86-64 userspace
 * They are two different machines and cannot merge.
 *
 * What this process does:
 *   1. load + attach the eBPF LSM programs from bpf/dlp.bpf.o
 *   2. classify every file under /tmp/dlp-lab/secrets and register the ones
 *      with regulated content by {major,minor,inode} in the kernel hash map
 *   3. watch four fds under one epoll loop:
 *        BPF ring buffer   BLOCK/ALERT decisions made in the kernel
 *        X11 clipboard     copy events (observe only; cannot block)
 *        inotify           /tmp/dlp-test
 *        fanotify          /tmp/dlp-protected, FAN_OPEN_PERM, can deny
 *
 * The kernel never reads file contents. This process classifies and hands the
 * kernel only physical file identity.
 */
#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <X11/Xlib.h>
#include <X11/extensions/Xfixes.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ config */

#define SECRETS_DIR   "/tmp/dlp-lab/secrets"
#define INOTIFY_DIR   "/tmp/dlp-test"
#define FANOTIFY_DIR  "/tmp/dlp-protected"
#define PIN_DIR       "/sys/fs/bpf/dlp"

/* --------------------------------------------- was common/dlp_event.h ----- */

enum { DLP_CLIPBOARD = 1, DLP_FILE = 2, DLP_NETWORK = 3 };
enum { DLP_ALLOW = 0, DLP_AUDIT = 1, DLP_DENY = 2 };

struct dlp_event {
  int source;
  int pid;
  int uid;
  char bytes[4096];
  int byte_count;
  int level;
  int action;
};

/* --------------------------------------------- was common/classify.c ------ */

static int luhn(const char *digits, int n) {
  int sum = 0;
  int alternate = 0;
  for (int i = n - 1; i >= 0; i--) {
    if (digits[i] < '0' || digits[i] > '9')
      return 0;
    int value = digits[i] - '0';
    if (alternate) {
      value *= 2;
      if (value > 9)
        value -= 9;
    }
    sum += value;
    alternate = !alternate;
  }
  return (sum % 10) == 0;
}

static int classify(const char *bytes, int n) {
  int level = 0;
  if (memmem(bytes, n, "AKIA", 4))
    level = 3;
  for (int i = 0; i + 16 <= n; i++) {
    if (luhn(bytes + i, 16)) {
      if (level < 2)
        level = 2;
      break;
    }
  }
  for (int i = 0; i + 11 <= n; i++) {
    if (bytes[i + 0] >= '0' && bytes[i + 0] <= '9' && bytes[i + 1] >= '0' &&
        bytes[i + 1] <= '9' && bytes[i + 2] >= '0' && bytes[i + 2] <= '9' &&
        bytes[i + 3] == '-' && bytes[i + 4] >= '0' && bytes[i + 4] <= '9' &&
        bytes[i + 5] >= '0' && bytes[i + 5] <= '9' && bytes[i + 6] == '-' &&
        bytes[i + 7] >= '0' && bytes[i + 7] <= '9' && bytes[i + 8] >= '0' &&
        bytes[i + 8] <= '9' && bytes[i + 9] >= '0' && bytes[i + 9] <= '9' &&
        bytes[i + 10] >= '0' && bytes[i + 10] <= '9') {
      if (level < 1)
        level = 1;
      break;
    }
  }
  return level;
}

/* ------------------------------------- ABI shared with bpf/dlp.bpf.c ------ */

enum {
  NIGHTFALL_EVENT_NET_BLOCK = 2,
  NIGHTFALL_EVENT_NET_ALERT = 3,
};

/* Must match struct nightfall_event in bpf/dlp.bpf.c byte-for-byte. */
struct nightfall_event {
  uint32_t pid;
  uint32_t kind;
  char path[128];
  uint8_t level;
};

_Static_assert(sizeof(struct nightfall_event) == 140,
               "nightfall_event ABI must match the BPF program");

/*
 * Physical file identity: superblock {major, minor} + inode. Paths lie
 * (symlinks, hardlinks, rename); the inode is the physical truth, so this —
 * not a path string — is what the kernel matches on. Must match struct
 * file_id in bpf/dlp.bpf.c. Zero padding: two u32 fill the 8-byte slot.
 */
struct file_id {
  __u32 major;
  __u32 minor;
  __u64 ino;
};

/* ------------------------------------------- registration ------------------ */

static int register_secret(int map_fd, const char *path) {
  struct stat st;
  if (stat(path, &st) != 0) {
    fprintf(stderr, "stat(%s) failed: %s\n", path, strerror(errno));
    return -1;
  }

  /* Zero-initialize: the kernel looks up this key with a raw memcmp, so any
   * uninitialized struct padding would make the lookup miss. */
  struct file_id key = {0};

  /* glibc's dev_t layout differs from the kernel's. Rebuild the kernel's
   * 20-bit split (minor low, major high) so userspace and kernel keys agree
   * even when a device's minor number exceeds 255. */
  __u32 raw_dev = ((__u32)major(st.st_dev) << 20) | (__u32)minor(st.st_dev);

  key.major = raw_dev >> 20;
  key.minor = raw_dev & ((1U << 20) - 1);
  key.ino = st.st_ino;

  /* Classify file content inline — open, read up to 4096, run classifier. */
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return 0;
  char buf[4096];
  ssize_t nr = read(fd, buf, sizeof(buf));
  close(fd);
  if (nr <= 0)
    return 0;
  __u8 level = (__u8)classify(buf, (int)nr);

  if (level == 0) {
    printf("%s skip no regulated content\n", path);
    return 0;
  }

  if (bpf_map_update_elem(map_fd, &key, &level, BPF_ANY) != 0) {
    fprintf(stderr, "map update failed: %s\n", strerror(errno));
    return -1;
  }
  printf("Registered %s (level %u) ino=%llu\n", path, level,
         (unsigned long long)key.ino);
  return 0;
}

/* --------------------------------------------------- BPF ring buffer ----- */

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

  if (kernel_event.kind == NIGHTFALL_EVENT_NET_BLOCK)
    printf("[DLP] BLOCK pid %u exfil %s (level %u)\n", kernel_event.pid,
           kernel_event.path, kernel_event.level);
  else
    printf("[DLP] ALERT pid %u touched %s (level %u) - allowed\n",
           kernel_event.pid, kernel_event.path, kernel_event.level);
  fflush(stdout);
  return 0;
}

struct file_entry { 
    char path[512];
    struct file_id key;
}file_map[64];


/* ---------------------------------------------------------------- main --- */

int main(void) {
  /*
   * Order matters. The BPF work needs root; the X11 connection needs the
   * user's session. Do the privileged, load-bearing work first so that a
   * missing display degrades the clipboard sensor instead of killing the
   * whole agent. Under plain sudo, XAUTHORITY is usually not preserved --
   * run `sudo -E` if you want the clipboard sensor too.
   */
  struct bpf_object *obj = bpf_object__open_file("bpf/dlp.bpf.o", NULL);
  if (!obj) {
    fprintf(stderr, "open dlp.bpf.o: %s\n", strerror(errno));
    return 3;
  }
  if (bpf_object__load(obj)) {
    fprintf(stderr, "load dlp.bpf.o: %s\n", strerror(errno));
    return 4;
  }

  int map_fd =
      bpf_object__find_map_fd_by_name(obj, "map_of_fileid_without_paths");
  if (map_fd < 0) {
    fprintf(stderr, "find map_of_fileid_without_paths: %s\n", strerror(errno));
    return 6;
  }

  /* Register the protected files BEFORE attaching, so no window exists where
   * the hooks are live but the policy map is still empty.
   * Inlined from register_secrets_dir — just opendir + readdir + register. */
  {
    DIR *d = opendir(SECRETS_DIR);
    if (!d) {
      fprintf(stderr, "Could not open %s\n", SECRETS_DIR);
    } else {
      struct dirent *ent;
      while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
          continue;
        char path[512];
        snprintf(path, sizeof(path), SECRETS_DIR "/%s", ent->d_name);
        register_secret(map_fd, path);
        struct stat st;
        if (stat(path, &st) == 0) {
          for (int j = 0; j < 64; j++) {
            if (file_map[j].path[0] == '\0') {
              snprintf(file_map[j].path, sizeof(file_map[j].path), "%s", path);
              __u32 raw_dev = ((__u32)major(st.st_dev) << 20) | (__u32)minor(st.st_dev);
              file_map[j].key.major = raw_dev >> 20;
              file_map[j].key.minor = raw_dev & ((1U << 20) - 1);
              file_map[j].key.ino = st.st_ino;
              break;
            }
          }
        }
      }
      closedir(d);
    }
  }

  struct bpf_program *prog;
  struct bpf_link *links[8] = {};
  int nlinks = 0;
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

  /* Pinning decouples the objects from THIS process, so an agent restart does
   * not drop enforcement. /sys/fs/bpf is memory-backed: pins do NOT survive a
   * reboot. Failures here are non-fatal (a stale pin dir is common). */
  mkdir(PIN_DIR, 0755);
  bpf_object__pin_maps(obj, PIN_DIR);
  for (int i = 0; i < nlinks; i++) {
    char pin[128];
    snprintf(pin, sizeof(pin), PIN_DIR "/link_%d", i);
    bpf_link__pin(links[i], pin);
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

  /* --- optional X11 clipboard sensor ------------------------------------ */
  Display *display = XOpenDisplay(NULL);
  Window win = 0;
  Atom clip = 0, targets = 0, utf8 = 0, targets_property = 0,
       data_property = 0;
  int ev_base = 0, err_base = 0;
  int clip_fd = -1;

  if (!display) {
    fprintf(stderr,
            "no X display (DISPLAY/XAUTHORITY) - clipboard sensor DISABLED, "
            "everything else runs. use `sudo -E` to keep it.\n");
  } else if (!XFixesQueryExtension(display, &ev_base, &err_base)) {
    fprintf(stderr, "XFixes missing - clipboard sensor DISABLED\n");
    XCloseDisplay(display);
    display = NULL;
  } else {
    win = XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1, 1,
                              0, 0, 0);
    clip = XInternAtom(display, "CLIPBOARD", False);
    targets = XInternAtom(display, "TARGETS", False);
    utf8 = XInternAtom(display, "UTF8_STRING", False);
    targets_property = XInternAtom(display, "DLP_TARGETS", False);
    data_property = XInternAtom(display, "DLP_CLIPBOARD_DATA", False);
    XFixesSelectSelectionInput(display, DefaultRootWindow(display), clip,
                               XFixesSetSelectionOwnerNotifyMask);
    XFlush(display);
    clip_fd = ConnectionNumber(display);
  }

  /* --- inotify ---------------------------------------------------------- */
  int inotify_fd = inotify_init1(0);
  if (inotify_fd < 0) {
    perror("inotify_init1");
    return 10;
  }
  int inotify_dir = inotify_init1(0);
  if (inotify_dir < 0) {
    perror("inotify_init1 secrets");
    return 21;
  }
  int wd2 = inotify_add_watch(inotify_dir, SECRETS_DIR, IN_CLOSE_WRITE | IN_MOVED_TO);
  if (wd2 < 0) {
    perror("inotify_add_watch " SECRETS_DIR);
    return 22;
  }
  int wd = inotify_add_watch(inotify_fd, INOTIFY_DIR,
                             IN_CLOSE_WRITE | IN_MOVED_TO);
  if (wd < 0) {
    perror("inotify_add_watch " INOTIFY_DIR);
    return 11;
  }

  /* --- fanotify --------------------------------------------------------- */
  int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
  if (fan_fd < 0) {
    perror("fanotify_init");
    return 12;
  }
  if (fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD,
                    AT_FDCWD, FANOTIFY_DIR) < 0) {
    perror("fanotify_mark " FANOTIFY_DIR);
    return 13;
  }

  /* --- one epoll over every sensor -------------------------------------- */
  int epfd = epoll_create1(0);
  if (epfd < 0) {
    fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
    return 9;
  }
  struct epoll_event ev = {.events = EPOLLIN};
  if (clip_fd >= 0) {
    ev.data.fd = clip_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, clip_fd, &ev) < 0) {
      perror("epoll_ctl clipboard");
      return 14;
    }
  }
  ev.data.fd = inotify_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, inotify_fd, &ev) < 0) {
    perror("epoll_ctl inotify");
    return 15;
  }
  ev.data.fd = inotify_dir;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, inotify_dir, &ev) < 0) {
    perror("epoll_ctl inotify secrets");
    return 23;
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

  printf("Nightfall DLP Active. clipboard=%s inotify=%s fanotify=%s\n",
         clip_fd >= 0 ? "on" : "OFF", INOTIFY_DIR, FANOTIFY_DIR);
  fflush(stdout);

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

      if (clip_fd >= 0 && fd == clip_fd) {
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
            Atom type;
            int format;
            unsigned long nitems, bytes_after;
            unsigned char *data = NULL;
            XGetWindowProperty(display, win, data_property, 0, 4096 / 4,
                               True, AnyPropertyType, &type, &format, &nitems,
                               &bytes_after, &data);
            if (data) {
              if (type != utf8) {
                printf("clip non-text bytes=%lu\n", nitems);
                fflush(stdout);
                XFree(data);
              } else if (bytes_after > 0) {
                printf("clip TRUNCATED read=%lu unread=%lu level=UNKNOWN\n", nitems, bytes_after);
                fflush(stdout);
                XFree(data);
              } else {
                int clevel = classify((const char *)data, (int)nitems);
                printf("source=1 pid=0 uid=0 bytes=%lu level=%d action=%d\n",
                       nitems, clevel, clevel == 0 ? 0 : clevel >= 2 ? 2 : 1);
                fflush(stdout);
                XFree(data);
              }
            }
          }
        }

      } else if (fd == inotify_fd) {
        char buf[4096]
            __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t len = read(inotify_fd, buf, sizeof(buf));
        if (len < 0) {
          perror("read inotify");
          continue;
        }
        for (char *p = buf; p < buf + len;) {
          struct inotify_event *iev = (struct inotify_event *)p;
          if (iev->len) {
            char path[512];
            snprintf(path, sizeof(path), INOTIFY_DIR "/%s", iev->name);
            int f = open(path, O_RDONLY);
            if (f >= 0) {
              char bytes[4096];
              int rn = read(f, bytes, sizeof(bytes));
              close(f);
              int bc = rn > 0 ? rn : 0;
              if (bc > 4096)
                bc = 4096;
              /* classify + policy + print inlined */
              int clevel = classify(bytes, bc);
              int caction = (clevel == 0) ? 0 : (clevel >= 2) ? 2 : 1;
              printf("source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n",
                     DLP_FILE, 0, (int)getuid(), bc, clevel, caction);
              fflush(stdout);
            }
          }
          p += sizeof(struct inotify_event) + iev->len;
        }
      } else if (fd == inotify_dir) {
        char sbuf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t slen = read(inotify_dir, sbuf, sizeof(sbuf));
        if (slen < 0) {
          perror("read inotify secrets");
          continue;
        }
        for (char *sp = sbuf; sp < sbuf + slen;) {
          struct inotify_event *iev = (struct inotify_event *)sp;
          if (iev->len) {
            char path[512];
            snprintf(path, sizeof(path), SECRETS_DIR "/%s", iev->name);
            struct stat st;
            if (stat(path, &st) != 0) {
              sp += sizeof(struct inotify_event) + iev->len;
              continue;
            }

            struct file_id new_key = {0};
            __u32 raw_dev = ((__u32)major(st.st_dev) << 20) | (__u32)minor(st.st_dev);
            new_key.major = raw_dev >> 20;
            new_key.minor = raw_dev & ((1U << 20) - 1);
            new_key.ino = st.st_ino;

            int found = -1;
            for (int j = 0; j < 64; j++) {
              if (file_map[j].path[0] && strcmp(file_map[j].path, path) == 0) {
                found = j;
                break;
              }
            }

            if (found >= 0 && file_map[found].key.ino != new_key.ino) {
              bpf_map_delete_elem(map_fd, &file_map[found].key);
              register_secret(map_fd, path);
              printf("REKEY %s ino %llu -> %llu, old key deleted\n", path,
                     (unsigned long long)file_map[found].key.ino,
                     (unsigned long long)new_key.ino);
              file_map[found].key = new_key;
            } else if (found < 0) {
              register_secret(map_fd, path);
              for (int j = 0; j < 64; j++) {
                if (file_map[j].path[0] == '\0') {
                  snprintf(file_map[j].path, sizeof(file_map[j].path), "%s", path);
                  file_map[j].key = new_key;
                  break;
                }
              }
            }
          }
          sp += sizeof(struct inotify_event) + iev->len;
        }
      } else if (fd == fan_fd) {
        char fbuf[4096];
        ssize_t flen = read(fan_fd, fbuf, sizeof(fbuf));
        if (flen < 0) {
          perror("read fanotify");
          continue;
        }
        struct fanotify_event_metadata *meta =
            (struct fanotify_event_metadata *)fbuf;
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
            /* Never gate our own reads: FAN_OPEN_PERM on a file this process
             * opens would deadlock against the response we have not sent. */
            if (meta->pid == (int)getpid()) {
              /* fanotify response inlined — write + retry on EINTR */
              struct fanotify_response resp = {.fd = meta->fd,
                                               .response = FAN_ALLOW};
              ssize_t w;
              do {
                w = write(fan_fd, &resp, sizeof(resp));
              } while (w < 0 && errno == EINTR);
              if (w != (ssize_t)sizeof(resp)) {
                perror("fanotify response");
                close(meta->fd);
                return 20;
              }
              close(meta->fd);
            } else {
              char bytes[4096];
              lseek(meta->fd, 0, SEEK_SET);
              int rn = read(meta->fd, bytes, sizeof(bytes));
              int bc = rn > 0 ? rn : 0;
              /* classify + policy inlined */
              int clevel = classify(bytes, bc);
              int caction = (clevel == 0) ? 0 : (clevel >= 2) ? 2 : 1;
              printf("source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n",
                     DLP_FILE, (int)meta->pid, 0, bc, clevel, caction);
              fflush(stdout);
              /* fanotify response inlined — deny if level >= 2 */
              struct fanotify_response resp = {
                  .fd = meta->fd,
                  .response = (clevel >= 2) ? FAN_DENY : FAN_ALLOW};
              ssize_t w;
              do {
                w = write(fan_fd, &resp, sizeof(resp));
              } while (w < 0 && errno == EINTR);
              if (w != (ssize_t)sizeof(resp)) {
                perror("fanotify response");
                close(meta->fd);
                return 20;
              }
              close(meta->fd);
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
