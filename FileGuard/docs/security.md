# Security model

## What FileGuard does and does not promise
**FileGuard controls and logs access to protected files and detects unauthorized access attempts.**
It cannot know who *physically possesses* copies, and it cannot stop screenshots, photographs of a screen, retyped text,
or an unrestricted copy made by someone who was legitimately allowed to `DOWNLOAD`. Once plaintext leaves FileGuard it is
out of scope. We make no claim of global tracking, AI detection or blockchain.

## Authentication
PBKDF2-HMAC-SHA256, 600 000 iterations (OWASP guidance), 16-byte random salt per user (OpenSSL CSPRNG), 32-byte output;
cost is stored per user so it can be raised later. Only `salt` and derived `password_hash` are stored; verification uses
`CRYPTO_memcmp`. Unknown users trigger a dummy PBKDF2 so timing does not reveal valid usernames; the error text is identical.
**Lockout**: 5 failures per username in 5 minutes → `AccountLocked` + `REPEATED_LOGIN_FAILURE` alert (HIGH).
Username `[A-Za-z0-9_]{3,32}`, password 8–128 bytes.

## Authorisation
Roles: **OWNER** (register, share, revoke, view logs for own files), **USER** (open what is granted), **ADMIN** (manage
users, inspect all logs/alerts, revoke). Admins deliberately have **no implicit access to file content**. Only the first
account may be ADMIN without an admin actor; later admins require an authenticated admin.
Permissions: `VIEW` (metadata + integrity check) < `READ` (decrypt and view) < `DOWNLOAD` (also write a decrypted copy).
Grants may expire; revocation deletes the grant; disabled users lose everything. Checked on every access, not cached.

## Encryption and keys
AES-256-GCM via OpenSSL (never custom crypto). Per-file random 256-bit key, random 96-bit nonce, header as AAD. File keys are
wrapped with a master key (`keys/master.key`, random 32 bytes, 0600, refused if group/other-accessible) and bound to the
File ID. No key is hard-coded or placed in the `.fguard` file. Plaintext buffers are zeroed with `OPENSSL_cleanse`; output
buffers are cleared on failure.

## Integrity
Three layers (container SHA-256, GCM tag over header+ciphertext, plaintext SHA-256) - see `file_format.md`. A failure never
yields content; it writes `INTEGRITY_FAILURE` to the audit log, raises a HIGH alert and notifies the kernel driver.

## Input hardening
* **SQL**: every query uses prepared statements and bound parameters; the only `exec()` calls are constant SQL.
* **Paths**: user paths are rejected if they contain a `..` component, NUL/control characters or exceed 4095 bytes;
  sources are canonicalised with `realpath`, must be regular files, and may not be inside the data directory; protected
  files are stored under names built only from a validated `FG-<digits>` id; destinations must exist, may not be inside
  the data dir, are created `O_EXCL|O_NOFOLLOW` (no overwrite, no symlink following) with mode 0600.
* **Size**: 256 MiB plaintext cap; `.fguard` length must match declared size exactly; log text sanitised and truncated
  (prevents log injection).
* **Privilege**: runs unprivileged and warns if started as root; only module loading needs root.

## Audit logging
`USER_REGISTERED, LOGIN_SUCCESS, LOGIN_FAILURE, FILE_REGISTERED, FILE_PROTECTED, FILE_SHARED, FILE_OPENED, FILE_DOWNLOAD,
INTEGRITY_CHECK, INTEGRITY_FAILURE, ACCESS_DENIED, FILE_REVOKED, SECURITY_EVENT` (+ `PACKAGE_EXPORTED`,
`USER_STATUS_CHANGED`). Stored in SQLite and an append-only `audit.log`. Passwords, keys and plaintext are never logged
(asserted in tests). No IP/host data is collected: FileGuard is a local application, so such fields would not be meaningful.

## Known limitations 
1. **Same-account attacker**: the DB, master key and packages live in one user's data directory. Someone who controls that
   OS account (or root) can read the key, edit the DB, or delete the audit log. Defence in depth is against *other* OS
   users and against copied `.fguard` files, not against the account owner. A production design would run a dedicated
   service account/daemon and ship logs off-box.
2. **Single store**: a `.fguard` can only be opened where its registry (DB + master key) exists. It is not a portable
   DRM container. Multi-machine sharing would need a key server (future work).
3. **Audit log is append-only by convention** (`O_APPEND`), not tamper-evident (no hash chain).
4. Header metadata (name, size, owner id, plaintext hash) is unencrypted.
5. The kernel event channel is advisory (see `driver.md`).
6. Lockout is per username and can be used to annoy a user (temporary denial of service).
7. Memory zeroing is best-effort; plaintext can exist in swap or core dumps.
8. `DOWNLOAD`/`READ` recipients can copy what they see.
