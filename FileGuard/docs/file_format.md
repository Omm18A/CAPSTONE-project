# `.fguard` file format (version 1)

A `.fguard` file is a container: an authenticated header followed by AES-256-GCM ciphertext and its tag.
All integers are **little-endian**. Implementation: `src/core/FilePackage.cpp`.

```
offset  size  field
0       8     magic            "FGUARD\0\0"
8       2     format version   1
10      2     header length    74 + uuidLen + nameLen   (bytes, from offset 0)
12      1     cipher id        1 = AES-256-GCM
13      1     nonce length     12
14      1     tag length       16
15      1     flags            0 (reserved, must be 0)
16      8     original size    plaintext length in bytes (= ciphertext length; GCM has no padding)
24      4     owner id         FileGuard user id of the owner
28      1     uuidLen          length of File ID string
29      1     nameLen          length of original file name
30      32    original SHA-256 of the plaintext
62      12    nonce            random, unique per file
74      uuidLen   File ID      e.g. "FG-10001"
74+u    nameLen   original name  base name only (no '/')
hdr     size  ciphertext
hdr+n   16    GCM authentication tag
```

Total file length is **exactly** `headerLen + originalSize + 16`; anything else is rejected.

## What is *not* in the file
* **No key.** The per-file 256-bit key (DEK) is random, stored in the SQLite registry wrapped
  (AES-256-GCM) by a master key in `keys/master.key` (mode 0600), bound to the File ID.
* No password, no user list, no permissions. Authorisation is decided by the registry, not by the file.

## Integrity layers
1. **Container hash** - SHA-256 of the whole `.fguard` file is stored in the registry (`files.protected_hash`).
   Any changed byte is reported as `INTEGRITY_FAILURE` *before* anything is decrypted.
2. **GCM tag** - the entire header is *additional authenticated data*, so header edits (name, size, owner,
   hash) also break decryption.
3. **Plaintext hash** - after decryption, SHA-256 is compared with the original hash taken at registration.

## Validation rules in the parser
Bad magic/version/cipher/flags, header length not matching field lengths, declared size over 256 MiB,
File ID not `FG-<5..10 digits>`, unsafe file name (`/`, controls, `.`/`..`), trailing bytes, truncation
→ `Err::Corrupted`; the parser never reads out of bounds (checked by `test_security`).

## Privacy note
The header is not encrypted: the file name, size, owner id and plaintext SHA-256 are visible to anyone holding
the file. (A SHA-256 of a *known* document lets someone confirm a guess.) Encrypting metadata is future work.
