#pragma once
#include <string>

#include "core/Common.h"

namespace fg {

// AES-256-GCM (authenticated encryption) and PBKDF2 via OpenSSL.
// No home-made cryptography; keys are never hard-coded.
class EncryptionManager {
public:
    static constexpr size_t kKeyLen = 32, kNonceLen = 12, kTagLen = 16;

    static Status randomBytes(size_t n, Bytes& out);   // OpenSSL CSPRNG

    // `aad` is authenticated but not encrypted (we bind the file header to it).
    static Status aesGcmEncrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                const Bytes& plaintext, Bytes& ciphertext, Bytes& tag);
    static Status aesGcmDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                const Bytes& ciphertext, const Bytes& tag, Bytes& plaintext);

    static Status pbkdf2(const std::string& password, const Bytes& salt, int iterations,
                         size_t keyLen, Bytes& out);

    // Key wrapping: blob = nonce(12) | ciphertext(32) | tag(16), bound to the file id.
    static Status wrapKey(const Bytes& masterKey, const std::string& fileUuid,
                          const Bytes& dek, Bytes& blob);
    static Status unwrapKey(const Bytes& masterKey, const std::string& fileUuid,
                            const Bytes& blob, Bytes& dek);
};

}  // namespace fg
