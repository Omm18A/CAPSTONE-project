#include "TestUtil.h"
#include "core/EncryptionManager.h"
using namespace fg;

int main() {
    Bytes key, nonce, aad = {'h', 'd', 'r'};
    CHECK_OK(EncryptionManager::randomBytes(32, key));
    CHECK_OK(EncryptionManager::randomBytes(12, nonce));
    Bytes pt(1000);
    for (size_t i = 0; i < pt.size(); ++i) pt[i] = static_cast<uint8_t>(i * 7);

    Bytes ct, tag, out;
    CHECK_OK(EncryptionManager::aesGcmEncrypt(key, nonce, aad, pt, ct, tag));
    CHECK(ct.size() == pt.size() && tag.size() == 16 && ct != pt);
    CHECK_OK(EncryptionManager::aesGcmDecrypt(key, nonce, aad, ct, tag, out));
    CHECK(out == pt);                                                    // round trip

    Bytes bad = ct; bad[10] ^= 1;                                        // tampered ciphertext
    CHECK_CODE(EncryptionManager::aesGcmDecrypt(key, nonce, aad, bad, tag, out), Err::CryptoFailure);
    CHECK(out.empty());                                                  // no plaintext leaked
    Bytes badTag = tag; badTag[0] ^= 1;
    CHECK_CODE(EncryptionManager::aesGcmDecrypt(key, nonce, aad, ct, badTag, out), Err::CryptoFailure);
    Bytes badAad = {'x', 'd', 'r'};                                      // header tamper (AAD)
    CHECK_CODE(EncryptionManager::aesGcmDecrypt(key, nonce, badAad, ct, tag, out), Err::CryptoFailure);
    Bytes key2; EncryptionManager::randomBytes(32, key2);
    CHECK_CODE(EncryptionManager::aesGcmDecrypt(key2, nonce, aad, ct, tag, out), Err::CryptoFailure);

    CHECK_CODE(EncryptionManager::aesGcmEncrypt(Bytes(16), nonce, aad, pt, ct, tag), Err::InvalidInput);  // bad key size
    CHECK_CODE(EncryptionManager::aesGcmEncrypt(key, Bytes(8), aad, pt, ct, tag), Err::InvalidInput);     // bad nonce size

    Bytes n2; EncryptionManager::randomBytes(12, n2);
    CHECK(n2 != nonce);                                                  // fresh randomness

    Bytes empty_ct, empty_tag, empty_out;                                // zero-length plaintext works
    CHECK_OK(EncryptionManager::aesGcmEncrypt(key, nonce, aad, Bytes{}, empty_ct, empty_tag));
    CHECK_OK(EncryptionManager::aesGcmDecrypt(key, nonce, aad, empty_ct, empty_tag, empty_out));

    Bytes s1, s2, k1, k1b, k2;
    EncryptionManager::randomBytes(16, s1); EncryptionManager::randomBytes(16, s2);
    CHECK_OK(EncryptionManager::pbkdf2("password", s1, 1000, 32, k1));
    CHECK_OK(EncryptionManager::pbkdf2("password", s1, 1000, 32, k1b));
    CHECK_OK(EncryptionManager::pbkdf2("password", s2, 1000, 32, k2));
    CHECK(k1 == k1b && k1 != k2 && k1.size() == 32);                     // deterministic, salt-dependent
    CHECK_CODE(EncryptionManager::pbkdf2("p", Bytes(2), 1000, 32, k1), Err::InvalidInput);

    Bytes dek, blob, dek2;
    EncryptionManager::randomBytes(32, dek);
    CHECK_OK(EncryptionManager::wrapKey(key, "FG-10001", dek, blob));
    CHECK_OK(EncryptionManager::unwrapKey(key, "FG-10001", blob, dek2));
    CHECK(dek == dek2);
    CHECK_CODE(EncryptionManager::unwrapKey(key, "FG-10002", blob, dek2), Err::CryptoFailure);  // bound to file id
    CHECK_CODE(EncryptionManager::unwrapKey(key, "FG-10001", Bytes(5), dek2), Err::Corrupted);
    return finish("test_encryption");
}
