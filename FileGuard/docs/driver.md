# Kernel driver and kernel/user-space interaction

## Target
Ubuntu 24.04 LTS, Linux 6.8 series. APIs used that differ across versions are guarded with
`LINUX_VERSION_CODE`: `class_create()` (one argument since 6.4), `class->devnode` (const `struct device *` since 6.2),
`.llseek = no_llseek` (not needed from 6.12). Check yours: `uname -r`, and install `linux-headers-$(uname -r)`.

## Purpose
`/dev/fileguard` is a **security event channel**: the application writes events
(`UNAUTHORIZED_ACCESS`, `INTEGRITY_FAILURE`, `PROTECTED_FILE_OPEN`, `PROTECTED_FILE_CREATED`), the kernel keeps a
bounded queue (256 entries), counters, and `dmesg` lines. It does **no** encryption and enforces **no** access control.
The channel is advisory: it is a teaching vehicle for the user/kernel boundary, and anyone in group `fileguard` can write
to it (the kernel overwrites pid/uid/time so they cannot be forged, but event *content* is unauthenticated).

## Interface (`driver/fileguard_ioctl.h`, shared by kernel and application)
| Operation | Behaviour |
|---|---|
| `write(fd, &fg_event, 32)` | exactly 32 bytes else `-EINVAL`; type must be 1..4; queue full → `-ENOBUFS` (counted as dropped) |
| `read(fd, buf, n>=32)` | pops oldest event; empty → `-EAGAIN`; `n<32` → `-EINVAL` |
| `ioctl FG_IOC_GET_STATS` | `struct fg_stats` (totals, per type, dropped, pending, capacity) |
| `ioctl FG_IOC_GET_VERSION` | ABI version (`__u32`) |
| `ioctl FG_IOC_CLEAR` | resets queue and counters; needs `CAP_SYS_ADMIN` |
| `/proc/fileguard` | read-only text counters |
| `/sys/class/fileguard/fileguard/` | created by `class_create` + `device_create` (dev number, uevent) |

## Kernel concepts used
`module_init/exit`, `alloc_chrdev_region`, `cdev_init/cdev_add`, `class_create`, `device_create`, `file_operations`
(`open/release/read/write/unlocked_ioctl`), `copy_from_user`, `copy_to_user`, `put_user`, `kcalloc/kfree`, `mutex`,
`capable()`, `proc_create_single`, goto-based unwinding on every init error path, reverse-order teardown on exit.

## Safety checklist (what the code does)
* Fixed-size strict `write` length; type range-checked **before** it indexes an array.
* Only `copy_*_user`/`put_user` touch user memory; no user pointer is dereferenced; faults return `-EFAULT`
  (tested with a bad pointer).
* `read` copies to user *before* advancing the queue, so a bad pointer loses nothing.
* All shared state (ring, counters) guarded by one mutex; `mutex_lock_interruptible` on every path.
* Identity/time fields filled by the kernel (`task_tgid_vnr`, `from_kuid`, `ktime_get_real_seconds`).
* Device node mode 0660 (never world-writable); `CLEAR` privileged.
* Bounded memory: 256 × 32 B allocated once at load.

## Why root is needed (and only here)
Loading code into the kernel (`insmod`/`rmmod`) and changing a device node's group are privileged operations
(`CAP_SYS_MODULE`, `CAP_CHOWN`). `scripts/install_driver.sh` does exactly that; afterwards the application runs as a
normal user in group `fileguard`. The application works with the driver absent (events still go to SQLite and `audit.log`).

## Build and use
```bash
sudo apt install build-essential linux-headers-$(uname -r)
make -C driver                              # Kbuild, not CMake
sudo scripts/install_driver.sh              # insmod, group, udev rule
ls -l /dev/fileguard                        # crw-rw---- root fileguard
cat /proc/fileguard; dmesg | tail
build/fileguard driver status               # ioctl GET_STATS from user space
build/fileguard --user admin driver events  # read() queued events
ctest --test-dir build -R driver            # test_driver (skips if not loaded)
sudo scripts/uninstall_driver.sh            # rmmod
```
Secure Boot blocks unsigned modules: use a VM, or sign with a MOK key.

## User space ↔ kernel space
```
FileGuard (user space, unprivileged)         ring 3
   | write()/read()/ioctl()  -> glibc wrapper -> SYSCALL instruction (CPU switches to ring 0)
   v
Kernel: VFS looks up /dev/fileguard -> major/minor -> cdev -> our file_operations     ring 0
   | copy_from_user()/copy_to_user()  (validated, fault-tolerant copies)
   v
fg ring buffer in kernel memory (kcalloc)
```
* **System call**: the only sanctioned way for user code to request kernel services; the CPU privilege switch is
  hardware-enforced.
* **Why no direct kernel-memory access**: the MMU page tables mark kernel pages supervisor-only; user code touching
  them faults (SIGSEGV). User and kernel also use separate address ranges, and the kernel never trusts a user pointer
  without `copy_*_user` (which handles faults and, on modern CPUs, SMAP/SMEP protections).
* **Device file / character device**: a name in `/dev` bound to (major, minor) handled by a driver; byte-stream
  semantics, no block buffering. `ioctl` carries control operations that do not fit read/write.
