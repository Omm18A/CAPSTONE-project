#pragma once
#include <string>

#include "core/Common.h"

namespace fg {

// SHA-256 via OpenSSL EVP.
class HashManager {
public:
    static Bytes sha256(const uint8_t* data, size_t len);
    static Bytes sha256(const Bytes& data);
    static std::string sha256Hex(const Bytes& data);
    // Streams the file with open()/read(); never loads more than maxBytes.
    static Status sha256File(const std::string& path, Bytes& digest, uint64_t maxBytes);
};

}  // namespace fg
