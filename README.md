# nightfall-demo

A minimal, kernel-level Data Loss Prevention (DLP) agent for Linux built on
**eBPF LSM** hooks. A process that reads a registered secret file is *tainted*;
the taint follows it across `fork()`; a tainted process is then denied outbound
network connections **in the kernel** — so enforcement does not depend on
userspace behaving. Content classification (SSN / credit-card PAN via Luhn / AWS
access key) runs in userspace to decide *which* files are worth protecting; the
kernel enforces the boundary by physical `{major, minor, inode}` identity.

## Architecture

```
            USERSPACE                                  KERNEL  (eBPF LSM)
  ┌────────────────────────────────┐        ┌────────────────────────────────────┐
  │ loader  (src/loader.c)         │        │                                    │
  │                                │        │  lsm/file_open     [taint source]  │
  │  1. scan /tmp/dlp-lab/secrets  │        │      {maj,min,ino} in protected    │
  │  2. classify() src/classify.c  │        │      set? -> raise task taint      │
  │       -> level 0..3            │        │                                    │
  │  3. register level>=1 files    │  set   │  lsm/task_alloc    [propagate]     │
  │        by {maj,min,ino} ───────┼───────▶│      copy parent taint -> child    │
  │                                │  HASH  │      before the child runs         │
  │                                │        │                                    │
  │                                │        │  lsm/socket_connect  [enforce]     │
  │                                │        │      AF_INET? tainted?             │
  │  4. drain ring buffer  ◀───────┼────────┤      level>=2 -> -EPERM (DENY)     │
  │       print BLOCK / ALERT      │ RINGBUF│      else     -> audit  (ALLOW)    │
  │                                │        │  lsm/socket_sendmsg  [enforce]     │
  └────────────────────────────────┘        └────────────────────────────────────┘

  Shared BPF maps:
    map_of_fileid_without_paths   HASH          protected file identities
    nightfall_payload             TASK_STORAGE  per-task taint (auto-freed on exit)
    event_map_of_path_kind        RINGBUF       audit events -> loader
```

Taint flow end to end:

```
  read secret.csv ──▶ file_open taints the reader ──▶ fork ──▶ task_alloc taints
  the child ──▶ child calls connect() ──▶ socket_connect sees taint ──▶ -EPERM
```

Sensitivity levels (from `src/classify.c`): `0` clean, `1` SSN, `2` Luhn-valid
PAN, `3` AWS key. `BLOCK_LEVEL` is `2`: level >= 2 is denied at the network,
level 1 is audited and allowed.

## Layout

```
bpf/dlp.bpf.c     four LSM hooks (file_open, task_alloc, socket_connect/sendmsg)
bpf/vmlinux.h     BTF-generated kernel types (for CO-RE)
src/loader.c      libbpf loader/agent: register secrets, drain audit ring buffer
src/classify.c    content classifier (SSN / PAN+Luhn / AWS)
src/classify.h
test/classify_test.c   unit tests for all four levels
test/demo.sh           90-second scripted live demo
clipboard/clipboard_watch.c   userspace DLP source #3: X11 clipboard watcher
LIMITS.md              honest failure modes
```

The kernel hooks cover the file and socket exfil channels; the clipboard is a
third channel that lives entirely in the X server, so
`clipboard/clipboard_watch.c` is a userspace sensor (XFixes selection-owner
notifications). It detects clipboard changes today; pulling and classifying the
pasted bytes is called out as future work in LIMITS.md.

## Build

```bash
make            # builds bpf/dlp.bpf.o (clang -target bpf) + build/loader + classify_test
make bpf        # just the eBPF object
make loader     # just the userspace agent  (gcc, -lbpf -lelf -lz)
make classify_test   # build + run the classifier unit tests
make clipboard       # optional: X11 clipboard watcher (-lX11 -lXfixes)
make clean
```

Toolchain: `clang` (BPF target), `gcc`, and libbpf headers/libs
(`libbpf-dev`, `libelf`, `zlib`). Building requires **no** root; only *loading*
the programs does.

## Live demo

`test/demo.sh` runs the non-privileged setup itself and prints the two steps
that need `sudo` + a live kernel. Full run:

```bash
./test/demo.sh          # builds objects, plants a synthetic secret, prints steps
```

Then, in two terminals:

```bash
# Terminal A — load the LSM programs and start the agent (registers the secret,
# streams audit events). Needs a kernel with BPF LSM enabled.
sudo ./build/loader

# Terminal B — read the secret (taints this shell) then try to exfiltrate.
sudo sh -c 'cat /tmp/dlp-lab/secrets/hr.csv >/dev/null; curl -m 3 https://1.1.1.1'
```

Expected: `curl` fails with `Operation not permitted` (the kernel vetoed
`connect()`), and terminal A prints
`[DLP] BLOCK pid <N> exfil /tmp/dlp-lab/secrets/hr.csv (level 2)`.

Kernel requirements for the live load: `CONFIG_BPF_LSM=y` with `bpf` present in
`/sys/kernel/security/lsm` (add `lsm=...,bpf` to the kernel cmdline if not),
BTF at `/sys/kernel/btf/vmlinux`, and task-local storage (Linux >= 5.11).

## Limitations

The mechanism's threat model is: *stop an unprivileged process from reading a
registered secret and then opening a fresh outbound connection.* It does **not**
cover copying a secret to a new inode, inspecting TLS-encrypted payloads, a root
attacker tampering with the BPF maps, every egress path (DNS tunneling, fd
passing, raw sockets), or sibling threads that predate the read. See
[LIMITS.md](LIMITS.md) for the full, honest breakdown.

## Known gaps

- Everything builds without root; the live enforcement path is exercised
  manually (Terminals A/B above) because loading BPF LSM programs needs `sudo`
  and a suitably configured kernel — it is not run in CI here.
