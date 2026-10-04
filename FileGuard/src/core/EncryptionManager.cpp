#include "core/EncryptionManager.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <climits>
#include <memory>

namespace fg {

namespace {
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
const Status kBadParams = Status::fail(Err::InvalidInput, "Invalid cryptographic parameters.");

std::string wrapAadString(const std::string& uuid) { return "fileguard-key-wrap-v1:" + uuid; }
}  // namespace

Status EncryptionManager::randomBytes(size_t n, Bytes& out) {
    out.assign(n, 0);
    if (n && RAND_bytes(out.data(), static_cast<int>(n)) != 1)
        return Status::fail(Err::CryptoFailure, "Random number generator failure.");
    return Status::success();
}

Status EncryptionManager::aesGcmEncrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                        const Bytes& pt, Bytes& ct, Bytes& tag) {
    if (key.size() != kKeyLen || nonce.size() != kNonceLen || pt.size() > INT_MAX / 2) return kBadParams;
    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return Status::fail(Err::CryptoFailure, "Cipher context allocation failed.");
    int len = 0;
    ct.assign(pt.size(), 0);
    tag.assign(kTagLen, 0);
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return Status::fail(Err::CryptoFailure, "Encryption initialisation failed.");
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        return Status::fail(Err::CryptoFailure, "Encryption (AAD) failed.");
    if (!pt.empty() && EVP_EncryptUpdate(ctx.get(), ct.data(), &len, pt.data(), static_cast<int>(pt.size())) != 1)
        return Status::fail(Err::CryptoFailure, "Encryption failed.");
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + (pt.empty() ? 0 : pt.size()), &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen), tag.data()) != 1)
        return Status::fail(Err::CryptoFailure, "Encryption finalisation failed.");
    return Status::success();
}

Status EncryptionManager::aesGcmDecrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                                        const Bytes& ct, const Bytes& tag, Bytes& pt) {
    pt.clear();
    if (key.size() != kKeyLen || nonce.size() != kNonceLen || tag.size() != kTagLen ||
        ct.size() > INT_MAX / 2)
        return kBadParams;
    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) return Status::fail(Err::CryptoFailure, "Cipher context allocation failed.");
    int len = 0;
    Bytes out(ct.size(), 0);
    Bytes tagCopy = tag;   // OpenSSL wants a non-const pointer
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceLen), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return Status::fail(Err::CryptoFailure, "Decryption initialisation failed.");
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1)
        return Status::fail(Err::CryptoFailure, "Decryption (AAD) failed.");
    if (!ct.empty() && EVP_DecryptUpdate(ctx.get(), out.data(), &len, ct.data(), static_cast<int>(ct.size())) != 1)
        return Status::fail(Err::CryptoFailure, "Decryption failed.");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen), tagCopy.data()) != 1)
        return Status::fail(Err::CryptoFailure, "Decryption failed (tag).");
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + (ct.empty() ? 0 : ct.size()), &len) != 1) {
        secureZero(out);
        return Status::fail(Err::CryptoFailure, "Authentication failed: data or key is corrupted or tampered.");
    }
    pt = std::move(out);
    return Status::success();
}

Status EncryptionManager::pbkdf2(const std::string& password, const Bytes& salt, int iterations,
                                 size_t keyLen, Bytes& out) {
    if (iterations < 1 || salt.size() < 8 || keyLen == 0 || keyLen > 1024) return kBadParams;
    out.assign(keyLen, 0);
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(),
                          static_cast<int>(salt.size()), iterations, EVP_sha256(),
                          static_cast<int>(keyLen), out.data()) != 1)
        return Status::fail(Err::CryptoFailure, "Key derivation failed.");
    return Status::success();
}

Status EncryptionManager::wrapKey(const Bytes& master, const std::string& uuid, const Bytes& dek, Bytes& blob) {
    Bytes nonce, ct, tag, aad;
    Status s = randomBytes(kNonceLen, nonce);
    if (!s.ok()) return s;
    std::string a = wrapAadString(uuid);
    aad.assign(a.begin(), a.end());
    s = aesGcmEncrypt(master, nonce, aad, dek, ct, tag);
    if (!s.ok()) return s;
    blob = nonce;
    blob.insert(blob.end(), ct.begin(), ct.end());
    blob.insert(blob.end(), tag.begin(), tag.end());
    return Status::success();
}

Status EncryptionManager::unwrapKey(const Bytes& master, const std::string& uuid, const Bytes& blob, Bytes& dek) {
    if (blob.size() != kNonceLen + kKeyLen + kTagLen)
        return Status::fail(Err::Corrupted, "Stored key material is malformed.");
    Bytes nonce(blob.begin(), blob.begin() + kNonceLen);
    Bytes ct(blob.begin() + kNonceLen, blob.begin() + kNonceLen + kKeyLen);
    Bytes tag(blob.end() - kTagLen, blob.end());
    std::string a = wrapAadString(uuid);
    Bytes aad(a.begin(), a.end());
    return aesGcmDecrypt(master, nonce, aad, ct, tag, dek);
}

}  // namespace fg
