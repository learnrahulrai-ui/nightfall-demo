# nightfall-demo

A minimal, kernel-level Data Loss Prevention (DLP) agent for Linux built on
**eBPF LSM** hooks. It tags any process that reads a registered secret file,
propagates that taint across `fork()`, and blocks outbound network connections
from tainted processes at the `socket_connect` hook — enforcing a data boundary
inside the kernel rather than trusting userspace to behave.

Content classification (SSN / credit-card PAN with Luhn / AWS access keys) runs
in userspace to decide *which* files are worth protecting; the kernel enforces
the boundary once they are registered by `{major, minor, inode}` identity.

> Work-in-progress scaffold. Full architecture diagram, build steps, live-demo
> commands, and an honest limitations section are filled in by later commits.
