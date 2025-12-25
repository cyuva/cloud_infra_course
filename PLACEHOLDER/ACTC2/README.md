# simple_container

A tiny “container runner” written in C. It launches a command inside isolated Linux namespaces, switches to a provided root filesystem, mounts a fresh `/proc`, applies a memory cgroup limit, drops capabilities to a small whitelist, and installs a minimal seccomp filter.

## Build

Requirements:
- `gcc`
- `libcap-ng` (development headers)
- `libseccomp` (development headers)

```bash
make
```

This produces `./simple_container`.

## Run

```bash
sudo ./simple_container <rootfs_path> <command> [args...]
```

Example:

```bash
sudo ./simple_container ~/actc2/rootfs /bin/sh
```

Notes:
- Needs privileges for `unshare()`, `mount()`, `pivot_root()`, and cgroup manipulation.
- The rootfs should contain the binary you run (e.g., `/bin/sh`) and basic directories.

---

## What it does (high level)

1. **PID namespace**: parent calls `unshare(CLONE_NEWPID)` so the child becomes PID 1 in its namespace.
2. **UTS/Mount/IPC namespaces** (child): isolates hostname, mounts, and IPC.
3. **Hostname**: sets hostname to `mycontainer`.
4. **Filesystem isolation**: `pivot_root()` into the given rootfs, unmounts old root.
5. **`/proc`**: mounts a fresh proc filesystem at `/proc` inside the new root.
6. **Memory cgroup (Phase 4)**: creates `/sys/fs/cgroup/simple_container`, sets a memory limit, and moves the child into it.
7. **Capabilities**: drops everything except a small whitelist:
   - `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_NET_BIND_SERVICE`, `CAP_SYS_CHROOT`
8. **Seccomp**: blocks a few sensitive syscalls (e.g., `reboot`, `swapon`, `swapoff`, module loading syscalls) with `EPERM`.
9. **Exec**: runs the requested command.

---

## The pipe race-condition (why it exists)

After `fork()`, **the child can run ahead** and call `execv()` immediately, while the parent is still setting up the cgroup.

That creates a real race:
- The command could start executing *before* the parent has written:
  - `memory.max`
  - the child PID into `cgroup.procs`
- Result: the payload can run (and allocate memory / do work) **outside the intended memory-limited cgroup**, or at least for a window where the limit is not enforced.

**Fix:** the code uses a `pipe2(..., O_CLOEXEC)` barrier:
- Child closes the write-end and blocks on `read(pipefd[0], ...)` **right before `execv()`**.
- Parent sets up the cgroup and only then writes a byte to the pipe, releasing the child.

This guarantees the payload starts only after the child has been placed in the correct cgroup with the limit applied.

---

## The “memory+” thing (cgroup v2 controller enabling)

On **cgroup v2**, you often must enable controllers in the parent cgroup before they can be used in child cgroups.

This project does a best-effort enable step:

- Tries writing `+memory` into:
  - `/sys/fs/cgroup/cgroup.subtree_control`

If that’s allowed/enabled, then setting:

- `/sys/fs/cgroup/simple_container/memory.max = 100000000` (≈ 100MB)

will work reliably.

If the system already enables it (or policy disallows writing there), the code intentionally **does not hard-fail** during the enable step—so it can still run on setups where memory is already enabled or locked down.

---

## Cleanup

After the child exits, the parent removes the created cgroup directory:

- `/sys/fs/cgroup/simple_container`

(Assumes it’s empty after the child terminates.)
