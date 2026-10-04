# FileGuard

**A C/C++ Linux security system for protected file distribution, access control, integrity verification, audit logging and kernel-level interaction.**

> **FileGuard controls and logs access to protected files and detects unauthorized access attempts.**
> It does **not** and **cannot** track every physical copy of a document - see [Limitations](#limitations).

## Project overview
FileGuard turns a document (`confidential.pdf`) into a protected `confidential.fguard` package: AES-256-GCM encrypted,
integrity-protected, and openable only through FileGuard by users the owner has authorised. Every open, denial, share,
revocation and tamper detection is audited. A small Linux character-device driver (`/dev/fileguard`) receives security events
from user space. Written for a 20-day capstone: C++17 application, C kernel module, SQLite, OpenSSL, Qt6 GUI + CLI.

## Problem statement
Confidential files are emailed, copied and forwarded; the owner loses control. Once an unrestricted copy exists nobody can
tell who holds it. FileGuard solves the realistic part: protect the *controlled* version, authorise every access, keep an
audit trail, verify integrity, detect unauthorised attempts, and allow revocable sharing.

## Objectives
User registration/auth/roles · file registration with unique ID · encryption · SHA-256 integrity · controlled sharing and
revocation · access and security logging · Linux filesystem/permission/syscall integration · character driver with user-space
communication · tests · documentation.

## Features (all implemented)
* Users, PBKDF2 password hashing, roles OWNER/USER/ADMIN, lockout after repeated failures
* Register file → ID `FG-10001`, SHA-256, AES-256-GCM `.fguard` package, per-file keys
* Share with `VIEW` / `READ` / `DOWNLOAD`, optional expiry, revoke, export package
* Open pipeline: authenticate → authorise → verify integrity → decrypt → audit
* Tamper detection (`INTEGRITY_FAILURE` + alert), unauthorised-access alerts
* Audit log (SQLite + append-only file), security-alert view, dashboard counters
* Linux system info (CPU, memory, storage, kernel, driver) from `/proc`, `/sys`, `uname`, `statvfs`
* Qt6 GUI and a CLI sharing one core; kernel module `/dev/fileguard` + `/proc/fileguard`
* Future work (not built, no buttons for it): see [Future enhancements](#future-enhancements)

## Architecture
See [`docs/architecture.md`](docs/architecture.md).
```
Qt GUI / CLI → FileGuardCore → {Auth, Users, Permissions, FileManager/FilePackage, Encryption, Hash, Audit, Security}
                            → SQLite · Linux filesystem (0700/0600) · /dev/fileguard → kernel driver
```

## Technology stack
C++17 (app), C (kernel module), CMake, Kbuild, OpenSSL 3 (EVP AES-256-GCM, PBKDF2, SHA-256), SQLite3, Qt6 Widgets, Ubuntu 24.04, GCC.
No Python/Java/JS/etc. anywhere; shell is used only for build/test/demo scripts.

## Linux concepts used
POSIX file I/O (`open read write close stat fstat lstat mkdir chmod fchmod rename unlink fsync realpath`), `O_EXCL`/`O_NOFOLLOW`/
`O_APPEND`/`O_CLOEXEC`, users/groups and permission bits (0700 dirs, 0600 files), `/proc` (`cpuinfo`, `meminfo`, `fileguard`),
`/sys` (`devices/system/cpu/online`, `class/fileguard`), `/dev` device node, `uname`, `statvfs`, `sysconf`, udev rules, kernel modules, `dmesg`.

## C/C++ concepts used
RAII (statements, transactions, EVP contexts via `unique_ptr`), move semantics, namespaces, enum classes, `std::optional`,
`std::function` callbacks, const-correctness, header/source separation, static libraries, CMake targets, `static_assert` on the ABI.

## Computer architecture concepts
User vs kernel mode, system-call boundary, virtual memory/MMU protection, CPU/RAM/cache/page-cache/storage hierarchy, DMA/interrupt-driven
I/O (conceptual), AES-NI, `fsync` durability. See [`docs/architecture.md`](docs/architecture.md#computer-architecture-connection).

## Hardware/software interaction
`Physical storage → storage driver → kernel → filesystem → FileGuard → user`; the USB analogue `USB device → USB subsystem → driver →
device node → application`; and `/dev/fileguard` as a virtual device on the same syscall→VFS→driver path. Explained in the architecture doc.

## Device driver
`driver/fileguard_driver.c` - bounded event queue with `write`/`read`/`ioctl`, `/proc/fileguard`, kernel-stamped pid/uid/time, strict input
validation, goto-unwind cleanup. Target: Ubuntu 24.04, kernel 6.8. Details and safety checklist: [`docs/driver.md`](docs/driver.md).

## Security model
[`docs/security.md`](docs/security.md): PBKDF2 (600k, per-user salt), AES-256-GCM with header as AAD, wrapped per-file keys, three integrity layers,
prepared statements, path hardening, least privilege, defence in depth (application authorisation + Linux permissions + crypto + audit).

## File format
[`docs/file_format.md`](docs/file_format.md) - header (magic, version, File ID, owner, name, size, SHA-256, nonce) + ciphertext + 16-byte tag. No key inside.

## Database schema
`database/schema.sql` (embedded into the binary at build time): `users`, `files`, `permissions`, `access_logs`, `security_events` (+ `login_attempts`
for lockout). Foreign keys and CHECK constraints; all access through prepared statements. Additions to the brief's suggested columns:
`users.iterations`, `files.protected_hash`, `files.wrapped_key`, `permissions.granted_by`.

## Project structure
```
FileGuard/
├── CMakeLists.txt  README.md  LICENSE  .gitignore
├── include/{core,database,ui}/   src/{core,database,ui,cli}/  src/main.cpp (GUI)
├── driver/   fileguard_driver.c  fileguard_ioctl.h  Makefile  README.md
├── database/schema.sql
├── tests/    test_{hash,encryption,authentication,permissions,database,security,endtoend,driver}.cpp  TestUtil.h
├── docs/     architecture.md security.md driver.md file_format.md testing.md
├── scripts/  build.sh install_driver.sh uninstall_driver.sh demo.sh
└── resources/icons/
```
(`FilePackageManager` from the brief is `FilePackage` + `FileManager`; `ConfigurationManager`, `DriverManager`, `LinuxSystemManager` as suggested.)

## Prerequisites (Ubuntu 24.04)
```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libssl-dev libsqlite3-dev qt6-base-dev linux-headers-$(uname -r)
```
Plain Ubuntu (VM or bare metal). If you use WSL for coding, the driver needs a real Ubuntu kernel/VM; the application does not depend on WSL.

## Build instructions
```bash
scripts/build.sh Release --test            # CMake build + ctest   (add --with-driver to also build the module)
# or manually
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ctest --test-dir build --output-on-failure
```
Debug: `-DCMAKE_BUILD_TYPE=Debug`. Warnings `-Wall -Wextra -Wpedantic` are on. Without Qt6 the build produces the CLI and tests only.
**Application → CMake. Kernel module → Kbuild (`make -C driver`).**

## Running the application
```bash
build/fileguard-gui                         # GUI (data in ~/.fileguard, or $FILEGUARD_HOME)
build/fileguard --help                      # CLI
```

## Driver installation / removal
```bash
make -C driver                              # as a normal user
sudo scripts/install_driver.sh              # insmod, group 'fileguard', udev rule, adds you to the group (re-login)
ls -l /dev/fileguard ; cat /proc/fileguard ; dmesg | tail
sudo scripts/uninstall_driver.sh            # rmmod
```
Root is required only for these module operations. Secure Boot blocks unsigned modules (use a VM or sign the module).

## Usage (CLI; the GUI offers the same operations)
```bash
fileguard user add admin ADMIN                       # first account = ADMIN (prompts for password)
fileguard --user admin user add Omm OWNER
fileguard user add Rahul USER                        # self-registration for OWNER/USER
fileguard --user Omm register ~/confidential.pdf     # -> FG-10001, SHA-256 shown
fileguard --user Omm share FG-10001 Rahul READ 30    # optional expiry in days
fileguard --user Omm export FG-10001 confidential.fguard
fileguard --user Rahul open FG-10001                 # or: open confidential.fguard
fileguard --user Omm revoke FG-10001 Rahul           # Rahul now gets ACCESS DENIED
fileguard --user Omm verify FG-10001
fileguard --user Omm logs 50 ;  fileguard --user admin alerts
fileguard sysinfo ; fileguard driver status
scripts/demo.sh                                       # the full 12-step presentation scenario, automated
```
Exit codes: 0 ok · 1 error · 2 usage · 3 access denied · 4 integrity failure.

## Testing
`ctest --test-dir build --output-on-failure` - details in [`docs/testing.md`](docs/testing.md). Eight test programs (hash, encryption, authentication,
permissions, database, security, end-to-end, driver). **Verification status:** the core, CLI, tests and demo were compiled warning-free and run
(all passing; driver test skipped without the module) in a sandbox; the **kernel module and Qt GUI were not compilable there** and need a first build on your Ubuntu machine.

## Screenshots
Add your own after building: `docs/screenshots/login.png`, `dashboard.png`, `files.png`, `viewer.png`, `logs.png`, and a terminal capture of `scripts/demo.sh` and
`ls -l /dev/fileguard; dmesg | tail`. (None are included because none were produced.)

## Limitations
* FileGuard controls the **protected `.fguard` file**. It **cannot** track screenshots, photos of the screen, copied or retyped text, or an unrestricted copy
  extracted by a user who had `DOWNLOAD`. It does not know who physically has a copy.
* A `.fguard` opens only where its registry (DB + master key) exists; it is not portable DRM.
* An attacker controlling the same OS account or root can read the key and DB or delete logs; the audit log is not tamper-evident.
* Header metadata (name, size, owner id, plaintext hash) is unencrypted. The kernel event channel is advisory. Full list: [`docs/security.md`](docs/security.md).

## Security considerations
Never commit `~/.fileguard`, `*.db`, `*.key`, `*.fguard`, `*.ko`, build directories (see `.gitignore`). Do not use `FILEGUARD_PASSWORD` outside demos (environment variables
are visible to same-user processes). Run unprivileged.

## Future enhancements
Dedicated service daemon and multi-user store, key server for cross-machine sharing, hash-chained audit log, encrypted metadata, view-only watermarking,
TOTP 2FA, signed module packaging.

## Contributors
Fill in team members and roles.

## License
MIT for the application; GPL-2.0 for `driver/` (kernel requirement). See [`LICENSE`](LICENSE).
