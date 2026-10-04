# Architecture

```
 Qt GUI (fileguard-gui)      CLI (fileguard)         tests
        \                      |                      /
         +----------- FileGuardCore (composition root) ---------+
         | Authentication  UserManager  PermissionManager        |
         | FileManager --- FilePackage (.fguard)                 |
         | EncryptionManager (OpenSSL AES-256-GCM, PBKDF2)       |
         | HashManager (SHA-256)  AuditLogger  SecurityManager   |
         | ConfigurationManager  LinuxSystemManager  DriverMgr   |
         +-------------------+-----------------+-----------------+
                             |                 |
                      DatabaseManager       /dev/fileguard -> kernel driver
                       (SQLite3)
                             |
                  Linux filesystem (0700 dirs, 0600 files)
```
GUI and CLI contain **no business rules**; they call the same core (verified by the shared test fixtures).

## Modules
| Module | Responsibility |
|---|---|
| `FileGuardCore` | owns and wires all managers; `init()` prepares dirs, key, DB |
| `ConfigurationManager` | data dir (`$FILEGUARD_HOME` or `~/.fileguard`), master key load/create, permission checks |
| `DatabaseManager` | SQLite RAII wrapper, prepared statements only, transactions, embedded schema |
| `UserManager` / `AuthenticationManager` | accounts, PBKDF2 hashing, login, lockout |
| `PermissionManager` | grants (VIEW<READ<DOWNLOAD), expiry, revocation, effective permission |
| `FileManager` | register/protect, the access pipeline, verify, download, export, share |
| `FilePackage` | `.fguard` serialise/parse with strict validation |
| `EncryptionManager`, `HashManager` | OpenSSL wrappers (no custom crypto) |
| `AuditLogger` | `access_logs` table + append-only `audit.log` |
| `SecurityManager` | `security_events`, path/name validation, driver notification |
| `LinuxSystemManager` | POSIX file I/O helpers, `/proc` `/sys` `uname` `statvfs` system info |
| `DriverManager` | `/dev/fileguard` client (`write/read/ioctl`) |

## Data flow: protect
`registerFile` → `checkUserPath` → `realpath` (+ not inside data dir) → `open/fstat/read` (regular file, ≤256 MiB)
→ SHA-256(plain) → random DEK + nonce → header (AAD) → AES-256-GCM → wrap DEK with master key →
`writeFileAtomic` (tmp + fsync + rename, 0600) → DB insert in one transaction → audit `FILE_REGISTERED`,
`FILE_PROTECTED` → driver event `PROTECTED_FILE_CREATED`.

## Data flow: open (the same pipeline serves open / download / verify)
```
authenticated user
  -> authorisation (owner, or unexpired grant >= needed)     DENIED -> ACCESS_DENIED + UNAUTHORIZED_ACCESS alert
  -> read package, SHA-256 == registry protected_hash        MISMATCH -> INTEGRITY_FAILURE alert
  -> parse + cross-check header vs registry                  BAD -> INTEGRITY_FAILURE alert
  -> unwrap DEK -> AES-GCM decrypt (header as AAD)           FAIL -> INTEGRITY_FAILURE alert
  -> SHA-256(plain) == original hash                         MISMATCH -> INTEGRITY_FAILURE alert
  -> INTEGRITY_CHECK + FILE_OPENED/FILE_DOWNLOAD audit, driver event PROTECTED_FILE_OPEN
```
Authorisation runs **before** any file bytes are read for registered IDs, so unauthorised users learn nothing about
integrity state. Unknown IDs and unauthorised IDs return the same "Access denied."

## System calls (each with a purpose)
| Call | Where | Why |
|---|---|---|
| `open(O_RDONLY\|O_CLOEXEC)`, `fstat`, `read`, `close` | `LinuxSystemManager::readFile`, `HashManager::sha256File` | `fstat` on the *open descriptor* (no check-then-use race) rejects non-regular files (`/dev/zero`, FIFOs) and oversize input |
| `open(O_CREAT\|O_EXCL\|O_NOFOLLOW)`, `write`, `fchmod`, `fsync` | `writeFileExclusive`, `writeFileAtomic` | never overwrite or follow symlinks; exact permissions regardless of umask; durability |
| `rename` | `writeFileAtomic` | crash-safe replace: readers see old or new file, never a partial one |
| `unlink` | rollback paths, `removeFile` | clean up partial writes after failures |
| `lstat`, `mkdir`, `chmod` | `ensureDir` | create 0700 dirs, refuse symlinked or foreign-owned directories |
| `stat` | `pathExists`, master-key permission check | refuse to run with a group/world-accessible key |
| `realpath` | `canonicalize` | resolve symlinks before deciding if a path is inside the data dir |
| `open(O_APPEND)`+`write` | `AuditLogger` | append-only audit file |
| `uname`, `sysconf`, `statvfs`, `gethostname`, `geteuid` | `gather` | system information, root warning |
| `open/write/read/ioctl` on `/dev/fileguard` | `DriverManager` | kernel interaction |

## Defence in depth
Layer 1: application authorisation (registry). Layer 2: Linux permissions (`~/.fileguard` 0700, files 0600, master key 0600
checked at startup) so other OS users cannot read ciphertext, DB or key. Layer 3: cryptography (a copied `.fguard` is
useless without the wrapped key held in the registry). Layer 4: integrity (SHA-256 + GCM). Layer 5: audit + alerts +
kernel event channel.

## Computer-architecture connection
```
Application (FileGuard process, virtual memory)
   -> CPU executes instructions in user mode (ring 3); AES-NI accelerates AES/GCM inside OpenSSL
   -> RAM: plaintext exists only in heap buffers during open (zeroed with OPENSSL_cleanse)
   -> syscall -> OS kernel (ring 0): VFS -> page cache (RAM) -> filesystem (ext4) -> block layer -> storage driver
   -> Storage device (SSD/HDD)
```
* **Memory hierarchy**: registers → L1/L2/L3 cache → RAM → page cache → storage; reading a file twice is fast the second
  time because the kernel's page cache holds it in RAM. `fsync` forces dirty pages down to storage (durability vs speed).
* **I/O and interrupts (conceptual)**: when the storage controller finishes a transfer it raises an interrupt; the kernel's
  driver handles it and wakes the process blocked in `read()`. FileGuard never polls hardware; it sleeps in the syscall.
* **Hardware/software chain**: `Physical storage → storage driver (NVMe/SATA) → kernel block layer → filesystem → VFS →
  syscalls → FileGuard → user`. The same shape applies to USB: `USB device → xHCI host controller → USB subsystem → class
  driver → device node → user program`. `/dev/fileguard` is a *virtual* device on the same path: it has no hardware, but
  it exercises the identical syscall → VFS → driver route.
* `fileguard sysinfo` reads CPU model (`/proc/cpuinfo`), cores (`sysconf`, `/sys/devices/system/cpu/online`), memory
  (`/proc/meminfo`), storage (`statvfs`), kernel (`uname`), driver state (`/dev`, `/proc/fileguard`).
