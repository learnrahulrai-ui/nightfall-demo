
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

#include <stdlib.h>
struct secret_record { uint32_t hash; uint64_t doc_id; };
int use_bloom = 1; struct secret_record known_fps[8192]; int num_known_fps = 0; uint32_t bloom_bits[256];
uint32_t bloom_mix32(uint32_t fp) { fp ^= fp>>16; fp *= 0x85ebca6bU; fp ^= fp>>13; fp *= 0xc2b2ae35U; fp ^= fp>>16; return fp; }
void bloom_add(uint32_t hash) { uint32_t b1 = bloom_mix32(hash) % 8192; uint32_t b2 = bloom_mix32(hash * 0x9e3779b9) % 8192; bloom_bits[b1 / 32] |= (1U << (b1 % 32)); bloom_bits[b2 / 32] |= (1U << (b2 % 32)); }
int bloom_may_be_has(uint32_t hash) { uint32_t b1 = bloom_mix32(hash) % 8192; uint32_t b2 = bloom_mix32(hash * 0x9e3779b9) % 8192; return ((bloom_bits[b1 / 32] & (1U << (b1 % 32))) != 0) && ((bloom_bits[b2 / 32] & (1U << (b2 % 32))) != 0); }







struct dlp_event {
  int source;
  int pid;
  int uid;
  char bytes[4096];
  int byte_count;
  int level;
  int action;
};



int luhn(const char *digits, int n) {
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

static int classify_internal(const char *bytes, int n, uint64_t doc_id) {

  int level = 0;
  if (memmem(bytes, n, "AKIA", 4)) level = 3;
  for (int i = 0; i + 16 <= n; i++) {
    if (luhn(bytes + i, 16)) { if (level < 2) level = 2; break; }
  }
  for (int i = 0; i + 11 <= n; i++) {
    if (bytes[i+0]>='0' && bytes[i+0]<='9' && bytes[i+1]>='0' && bytes[i+1]<='9' &&
        bytes[i+2]>='0' && bytes[i+2]<='9' && bytes[i+3]=='-' && bytes[i+4]>='0' &&
        bytes[i+4]<='9' && bytes[i+5]>='0' && bytes[i+5]<='9' && bytes[i+6]=='-' &&
        bytes[i+7]>='0' && bytes[i+7]<='9' && bytes[i+8]>='0' && bytes[i+8]<='9' &&
        bytes[i+9]>='0' && bytes[i+9]<='9' && bytes[i+10]>='0' && bytes[i+10]<='9') {
      if (level < 1) level = 1; break;
    }
  }

  char *norm = malloc(n); int n_len = 0, last_sp = 1;
  if (!norm) return level;
  for (int i_n = 0; i_n < n; i_n++) {
    char c = bytes[i_n];
    if (c >= 'a' && c <= 'z') { norm[n_len++] = c; last_sp = 0; }
    else if (c >= 'A' && c <= 'Z') { norm[n_len++] = c + 32; last_sp = 0; }
    else if (c >= '0' && c <= '9') { norm[n_len++] = c; last_sp = 0; }
    else if (!last_sp) { norm[n_len++] = ' '; last_sp = 1; }
  }
  if (n_len < 12) { free(norm); return level; }

  uint32_t *hs = malloc(n_len * sizeof(uint32_t));
  if (!hs) { free(norm); return level; }
  uint32_t h = 0; int h_cnt = 0;
  for (int j = 0; j < 8; j++) h = h * 31 + norm[j];
  hs[h_cnt++] = h;
  for (int i_h = 8; i_h < n_len; i_h++) {
    h = h * 31 - norm[i_h-8] * 2487512833U + norm[i_h]; hs[h_cnt++] = h;
  }

  int m = 0; uint32_t last_fp = 0; int dist = 0;
  for (int i_w = 0; i_w <= h_cnt - 5; i_w++) {
    int m_w = i_w;
    if (hs[i_w + 1] <= hs[m_w]) m_w = i_w + 1;
    if (hs[i_w + 2] <= hs[m_w]) m_w = i_w + 2;
    if (hs[i_w + 3] <= hs[m_w]) m_w = i_w + 3;
    if (hs[i_w + 4] <= hs[m_w]) m_w = i_w + 4;
    if (hs[m_w] == last_fp) continue;
    last_fp = hs[m_w]; dist++;

    if (doc_id != 0) {
      if (use_bloom) bloom_add(hs[m_w]);
      int exists = 0;
      for (int k_k = 0; k_k < num_known_fps; k_k++) {
        if (known_fps[k_k].hash == hs[m_w] && known_fps[k_k].doc_id == doc_id) { exists = 1; break; }
      }
      if (!exists && num_known_fps < 8192) {
        known_fps[num_known_fps].hash = hs[m_w]; known_fps[num_known_fps].doc_id = doc_id; num_known_fps++;
      }
    } else {
      if (!use_bloom || bloom_may_be_has(hs[m_w])) {
        for (int k_k = 0; k_k < num_known_fps; k_k++) {
          if (known_fps[k_k].hash == hs[m_w]) { m++; break; }
        }
      }
    }
  }
  if (doc_id == 0) {
    int pct = dist > 0 ? (m * 100) / dist : 0;
    if (level < 2 && pct >= 5) level = 2;
    if (m > 0) printf("containment=%d%% (%d of %d fingerprints)\n", pct, m, dist);
  }
  free(norm); free(hs);
  return level;
}





struct nightfall_event {
  uint32_t pid;
  uint32_t kind;
  char path[128];
  uint8_t level;
};

_Static_assert(sizeof(struct nightfall_event) == 140,
               "nightfall_event ABI must match the BPF program");


struct file_id {
  __u32 major;
  __u32 minor;
  __u64 ino;
};




int test_secret(const char *bytes, int n) { return classify_internal(bytes, n, 0); }
int register_fingerprints(const char *bytes, int n, uint64_t doc_id) { return classify_internal(bytes, n, doc_id); }

int register_secret(int map_fd, const char *path) {
  struct stat st;
  stat(path, &st);

  
  struct file_id key = {0};

  
  __u32 raw_dev = ((__u32)major(st.st_dev) << 20) | (__u32)minor(st.st_dev);

  key.major = raw_dev >> 20;
  key.minor = raw_dev & ((1U << 20) - 1);
  key.ino = st.st_ino;

  
  int fd = open(path, O_RDONLY);
  ssize_t to_read = st.st_size > 4096 ? 4096 : st.st_size;
  char *buf = malloc(to_read);
  ssize_t nr = read(fd, buf, to_read);
  close(fd);
  if (nr <= 0) { free(buf); return 0; }
  __u8 level = (__u8)register_fingerprints(buf, (int)nr, key.ino);
  free(buf);

  if (level == 0) {
    printf("%s skip no regulated content\n", path);
    return 0;
  }

  if (bpf_map_update_elem(map_fd, &key, &level, BPF_ANY) != 0) {
        return -1;
  }
  printf("Registered %s (level %u) ino=%llu\n", path, level,
         (unsigned long long)key.ino);
  return 0;
}



int process_bpf_event(void *ctx, void *data, size_t sz) {
  (void)ctx;

  if (sz != sizeof(struct nightfall_event)) {
        return 0;
  }

  struct nightfall_event kernel_event;
  memcpy(&kernel_event, data, sizeof(kernel_event));

  if (kernel_event.kind != 2 &&
      kernel_event.kind != 3) {
        return 0;
  }

  if (kernel_event.kind == 2)
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




int main(void) {
  
  struct bpf_object *obj = bpf_object__open_file("bpf/dlp.bpf.o", NULL);
  if (!obj) {
        return 3;
  }
  if (bpf_object__load(obj)) {
        return 4;
  }

  int map_fd =
      bpf_object__find_map_fd_by_name(obj, "map_of_fileid_without_paths");
  if (map_fd < 0) {
        return 6;
  }

  
  {
    DIR *d = opendir("/tmp/dlp-lab/secrets");
    {
      struct dirent *ent;
      while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
          continue;
        char path[512];
        snprintf(path, sizeof(path), "/tmp/dlp-lab/secrets" "/%s", ent->d_name);
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
            return 5;
    }
    struct bpf_link *l = bpf_program__attach(prog);
    if (!l) {
            return 5;
    }
    links[nlinks++] = l;
    printf("attached %s\n", bpf_program__name(prog));
  }

  
  mkdir("/sys/fs/bpf/dlp", 0755);
  bpf_object__pin_maps(obj, "/sys/fs/bpf/dlp");
  for (int i = 0; i < nlinks; i++) {
    char pin[128];
    snprintf(pin, sizeof(pin), "/sys/fs/bpf/dlp" "/link_%d", i);
    bpf_link__pin(links[i], pin);
  }

  int rb_fd = bpf_object__find_map_fd_by_name(obj, "event_map_of_path_kind");
  if (rb_fd < 0) {
        return 7;
  }
  struct ring_buffer *rb =
      ring_buffer__new(rb_fd, process_bpf_event, NULL, NULL);
  if (!rb) {
        return 8;
  }
  int rb_epoll_fd = ring_buffer__epoll_fd(rb);

  
  Display *display = XOpenDisplay(NULL);
  Window win = 0;
  Atom clip = 0, targets = 0, utf8 = 0, targets_property = 0,
       data_property = 0;
  int ev_base = 0, err_base = 0;
  int clip_fd = -1;

  if (!display) {
      } else if (!XFixesQueryExtension(display, &ev_base, &err_base)) {
        XCloseDisplay(display);
    display = NULL;
  } else {
    win = XCreateSimpleWindow(display, DefaultRootWindow(display), 0, 0, 1, 1,
                              0, 0, 0);
    clip = XInternAtom(display, "CLIPBOARD", False);
    targets = XInternAtom(display, "TARGETS", False);
    utf8 = XInternAtom(display, "UTF8_STRING", False);
    targets_property = XInternAtom(display, "DLP_TARGETS", False);
    data_property = XInternAtom(display, "1_DATA", False);
    XFixesSelectSelectionInput(display, DefaultRootWindow(display), clip,
                               XFixesSetSelectionOwnerNotifyMask);
    XFlush(display);
    clip_fd = ConnectionNumber(display);
  }

  
  int inotify_fd = inotify_init1(0);
  
  int inotify_dir = inotify_init1(0);
  if (inotify_dir < 0) {
        return 21;
  }
  int wd2 = inotify_add_watch(inotify_dir, "/tmp/dlp-lab/secrets", IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
  if (wd2 < 0) {
        return 22;
  }
  int wd = inotify_add_watch(inotify_fd, "/tmp/dlp-test",
                             IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM);
  

  
  int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
  
  fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, "/tmp/dlp-protected");

  
  int epfd = epoll_create1(0);
  struct epoll_event ev = {.events = EPOLLIN};
  if (clip_fd >= 0) {
    ev.data.fd = clip_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, clip_fd, &ev);
  }
  ev.data.fd = inotify_fd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, inotify_fd, &ev);
  ev.data.fd = inotify_dir;
  epoll_ctl(epfd, EPOLL_CTL_ADD, inotify_dir, &ev);
  ev.data.fd = fan_fd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, fan_fd, &ev);
  ev.data.fd = rb_epoll_fd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, rb_epoll_fd, &ev);

  printf("Nightfall DLP Active. clipboard=%s inotify=%s fanotify=%s\n",
         clip_fd >= 0 ? "on" : "OFF", "/tmp/dlp-test", "/tmp/dlp-protected");
  fflush(stdout);

  struct epoll_event ready[4];
  for (;;) {
    int n = epoll_wait(epfd, ready, 4, -1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
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
                int clevel = test_secret((const char *)data, (int)nitems);
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
                    continue;
        }
        for (char *p = buf; p < buf + len;) {
          struct inotify_event *iev = (struct inotify_event *)p;
          if (iev->len) {
            char path[512];
            snprintf(path, sizeof(path), "/tmp/dlp-test" "/%s", iev->name);
            int f = open(path, O_RDONLY);
            if (f >= 0) {
              char bytes[4096];
              int rn = read(f, bytes, sizeof(bytes));
              close(f);
              int bc = rn > 0 ? rn : 0;
              int clevel = test_secret(bytes, bc);
              int caction = (clevel == 0) ? 0 : (clevel >= 2) ? 2 : 1;
              printf("source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n",
                     2, 0, (int)getuid(), bc, clevel, caction);
              fflush(stdout);
            }
          }
          p += sizeof(struct inotify_event) + iev->len;
        }
      } else if (fd == inotify_dir) {
        char sbuf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t slen = read(inotify_dir, sbuf, sizeof(sbuf));
        if (slen < 0) {
                    continue;
        }
        for (char *sp = sbuf; sp < sbuf + slen;) {
          struct inotify_event *iev = (struct inotify_event *)sp;
          if (iev->len) {
            char path[512];
            snprintf(path, sizeof(path), "/tmp/dlp-lab/secrets" "/%s", iev->name);

            if (iev->mask & (IN_DELETE | IN_MOVED_FROM)) {
              for (int j = 0; j < 64; j++) {
                if (file_map[j].path[0] && strcmp(file_map[j].path, path) == 0) {
                  uint64_t target_doc_id = file_map[j].key.ino;
                  bpf_map_delete_elem(map_fd, &file_map[j].key);
                  file_map[j].path[0] = '\0';
                  int k = 0;
                  while (k < num_known_fps) {
                    if (known_fps[k].doc_id == target_doc_id) {
                      known_fps[k] = known_fps[num_known_fps - 1];
                      num_known_fps--;
                    } else k++;
                  }
                  for (int b = 0; b < 256; b++) bloom_bits[b] = 0;
                  for (int k = 0; k < num_known_fps; k++) {
                    uint32_t b1 = bloom_mix32(known_fps[k].hash) % 8192;
                    uint32_t b2 = bloom_mix32(known_fps[k].hash * 0x9e3779b9) % 8192;
                    bloom_bits[b1 / 32] |= (1U << (b1 % 32));
                    bloom_bits[b2 / 32] |= (1U << (b2 % 32));
                  }
                  break;
                }
              }
              sp += sizeof(struct inotify_event) + iev->len;
              continue;
            }

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
                    continue;
        }
        struct fanotify_event_metadata *meta =
            (struct fanotify_event_metadata *)fbuf;
        while (FAN_EVENT_OK(meta, flen)) {
          if (meta->vers != FANOTIFY_METADATA_VERSION) {
                        return 18;
          }
          if (meta->fd == FAN_NOFD) {
            meta = FAN_EVENT_NEXT(meta, flen);
            continue;
          } else {
            
            if (meta->pid == (int)getpid()) {
              
              struct fanotify_response resp = {.fd = meta->fd,
                                               .response = FAN_ALLOW};
              ssize_t w;
              do {
                w = write(fan_fd, &resp, sizeof(resp));
              } while (w < 0 && errno == EINTR);
              if (w != (ssize_t)sizeof(resp)) {
                                close(meta->fd);
                return 20;
              }
              close(meta->fd);
            } else {
              char bytes[4096];
              lseek(meta->fd, 0, SEEK_SET);
              int rn = read(meta->fd, bytes, sizeof(bytes));
              int bc = rn > 0 ? rn : 0;
              
              int clevel = test_secret(bytes, bc);
              int caction = (clevel == 0) ? 0 : (clevel >= 2) ? 2 : 1;
              printf("source=%d pid=%d uid=%d bytes=%d level=%d action=%d\n",
                     2, (int)meta->pid, 0, bc, clevel, caction);
              fflush(stdout);
              
              struct fanotify_response resp = {
                  .fd = meta->fd,
                  .response = (clevel >= 2) ? FAN_DENY : FAN_ALLOW};
              ssize_t w;
              do {
                w = write(fan_fd, &resp, sizeof(resp));
              } while (w < 0 && errno == EINTR);
              if (w != (ssize_t)sizeof(resp)) {
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
