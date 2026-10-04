# Testing

```bash
scripts/build.sh Debug --test         # or:  cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```
Plain C++ harness (`tests/TestUtil.h`), no external framework. Each test builds a throw-away store under `/tmp`
(PBKDF2 cost lowered to 1000 *in tests only*). `test_driver` needs the module loaded and reports SKIPPED (exit 77) otherwise.

| Test | Verifies |
|---|---|
| `test_hash` | NIST SHA-256 vectors, streaming == in-memory, modification changes digest, size limit, missing file |
| `test_encryption` | encrypt→decrypt round trip; tampered ciphertext/tag/AAD/key fail with **no plaintext released**; bad key/nonce sizes; zero-length data; PBKDF2 determinism/salting; key wrap bound to File ID |
| `test_authentication` | right/wrong password, unknown user (identical message), hash is not the password, unique salts (same password → different hash), registration rules, no self-promotion to ADMIN, disabled accounts, lockout after 5 failures + alert, bootstrap rule |
| `test_permissions` | owner/stranger, VIEW<READ<DOWNLOAD hierarchy, upsert, non-owner/admin can't share, self-share, expiry, revoke (owner/admin/stranger), disabled user |
| `test_database` | schema present, user & file registration, audit rows and `audit.log`, FK and CHECK constraints, hostile strings stored as data, visibility, unopenable DB |
| `test_security` | SQL-injection strings (login, username, file id), path traversal (register/download/export/symlink/special files/data dir), oversized input, invalid ids/permissions, unauthorised access → denied + alert, tampered/deleted package, 9 malformed `.fguard` mutations + bit flips, key/DB/dir permissions, refusal of unsafe key mode |
| `test_endtoend` | the demo: register → protect → share → export → recipient opens (also via `.fguard` path) → logged → READ≠DOWNLOAD → stranger denied even with the file → revoke → denied → tamper → integrity failure → views by role → no secrets in logs → persistence across restart |
| `test_driver` | version ioctl, send/stats/read round trip, kernel-filled pid/uid/time, empty queue, invalid type, wrong write size, bad user pointer (`EFAULT`), short read buffer, unknown ioctl (`ENOTTY`), bounded queue + drop counter, `CLEAR` privilege |

Repeated-failed-login protection is covered in `test_authentication`; SQLi/path/oversize/malformed input in `test_security`.
All security tests are defensive (they only feed hostile *input* to FileGuard inside a temp directory).

## Manual checks (not automatable here)
* Driver: `make -C driver`, `sudo scripts/install_driver.sh`, `ls -l /dev/fileguard`, `cat /proc/fileguard`,
  `dmesg | tail`, `ctest -R driver`, `sudo scripts/uninstall_driver.sh`, then confirm `/dev/fileguard` is gone.
* GUI: login/register, register file, share/revoke, open viewer (shows the four progress steps), tamper a file and re-open.
* Demo: `scripts/demo.sh` runs steps 1-12 non-interactively through the CLI.

## Verification status of this delivery
Core library, CLI, tests and demo script were compiled with GCC 13 (`-Wall -Wextra -Wpedantic`, zero warnings) and run
against OpenSSL 3 and SQLite 3 in a sandbox: **all tests passed except `test_driver` (skipped)**, and `demo.sh` ran end to end.
The sandbox had no kernel headers and no Qt, so **the kernel module and the Qt GUI were written to the target APIs but
were NOT compiled or run there**. Build them on Ubuntu 24.04 and report any compiler message; expect at most small fixes.
