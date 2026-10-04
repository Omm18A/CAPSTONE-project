#pragma once
// .fguard container: serialisation + strict parsing. See docs/file_format.md.
#include <string>

#include "core/Common.h"

namespace fg {

struct PackageHeader {
    uint16_t version = 1;
    uint8_t cipherId = 1;               // 1 = AES-256-GCM
    uint64_t originalSize = 0;
    uint32_t ownerId = 0;
    std::string fileUuid;               // FG-10001
    std::string originalName;           // base name only
    Bytes originalHash;                 // 32 bytes SHA-256 of plaintext
    Bytes nonce;                        // 12 bytes
};

class FilePackage {
public:
    static constexpr size_t kFixedHeader = 74;
    static constexpr size_t kTagLen = 16;

    // Header bytes (also used as AES-GCM additional authenticated data).
    static Status serializeHeader(const PackageHeader& h, Bytes& out);
    // header || ciphertext || tag
    static Status build(const PackageHeader& h, const Bytes& ciphertext, const Bytes& tag, Bytes& out);
    // Validates every field and the exact total length. Never reads out of bounds.
    static Status parse(const Bytes& data, PackageHeader& h, size_t& headerLen);
};

}  // namespace fg
