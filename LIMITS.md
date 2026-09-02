# LIMITS — where this kernel DLP stops

This is a focused demo of an enforcement *mechanism* (taint at read, propagate
across fork, deny at connect), not a shipping DLP product. The honest failure
modes below are the interesting part — each is a real gap with a real reason.

## 1. `cp` to a new inode escapes inode identity

Protection is keyed on physical file identity `{major, minor, inode}`, which is
robust against symlinks, hardlinks, and relative paths (they all resolve to the
same inode). It is **not** robust against *copying*: `cp secret.csv /tmp/x`
creates a brand-new inode that was never registered, so `file_open` on the copy
does not taint the reader. Real coverage needs content-based tainting (taint on
the *bytes* read, e.g. via `security_file_permission`/read hooks and inline
classification) rather than identity-based tainting. That is a much heavier hook
and is deliberately out of scope here.

## 2. TLS payload is ciphertext at the socket

The network hooks (`socket_connect`, `socket_sendmsg`) see the socket and the
destination, not readable content — by the time bytes reach the socket layer
they are already TLS ciphertext. So this agent enforces on **identity/taint**
("a process that read a secret may not connect out"), not on inspecting the
outbound bytes for secrets. Content-aware network DLP has to sit *above* crypto:
a userspace TLS-terminating proxy, an eBPF uprobe on the app's pre-encryption
buffer, or an LSM hook on the write before it is handed to the TLS library.

## 3. A privileged process can tamper with the maps

The protected-file set and the audit ring buffer are BPF maps pinned under
`/sys/fs/bpf/dlp`. Anything running as root (or with `CAP_BPF`/`CAP_SYS_ADMIN`)
can delete map entries, detach the programs, or unpin the links — disabling
enforcement entirely. This is the standard eBPF trust boundary: it defends
against unprivileged data exfiltration, not against an attacker who already owns
root. Hardening (signed programs, LSM-protected pins, a lock on `bpf()` itself)
is a separate problem.

## 4. Single connect hook — not every egress path is covered

Egress is enforced at `socket_connect` and `socket_sendmsg`. That covers the
common TCP-connect and UDP-sendmsg exfil paths, but a determined process has
other channels: DNS tunneling through a resolver process that was never tainted,
handing an already-open connected fd to another process over `SCM_RIGHTS`, or
raw/packet sockets. Each additional egress class needs its own hook and its own
taint reasoning; this demo intentionally covers the two most common ones.

## 5. Per-thread `task_storage` nuance

Taint lives in `BPF_MAP_TYPE_TASK_STORAGE`, which is keyed on the individual
`task_struct` — i.e. per **thread**, not per process (thread group). The taint
is placed on the exact task that called `open()`. Propagation to other tasks
happens only through `task_alloc`, which copies parent taint into a newly
created child (this fires for both `fork()` and thread creation via
`CLONE_THREAD`). The consequence:

- A thread created *after* the secret read inherits the taint. Good.
- A sibling thread that already existed *before* the read, and did not itself
  open the file, is **not** tainted — even though it shares the same address
  space and could read the secret straight out of memory and connect out.

Closing that would mean propagating taint across all tasks sharing an `mm`
(address space), not just across `clone`. That is a real design extension, not a
one-line fix, and is left out on purpose to keep the demo legible.

---

None of these make the mechanism useless — they define its threat model:
**stop an unprivileged process from reading a registered secret and then opening
a fresh outbound connection.** Everything above is where that boundary ends.
