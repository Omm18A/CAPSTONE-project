#include "core/HashManager.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>

namespace fg {

namespace {
using MdPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
}

Bytes HashManager::sha256(const uint8_t* data, size_t len) {
    MdPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int n = 0;
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        (len && EVP_DigestUpdate(ctx.get(), data, len) != 1) ||
        EVP_DigestFinal_ex(ctx.get(), out.data(), &n) != 1)
        return {};
    out.resize(n);
    return out;
}
Bytes HashManager::sha256(const Bytes& d) { return sha256(d.data(), d.size()); }
std::string HashManager::sha256Hex(const Bytes& d) { return hexEncode(sha256(d)); }

Status HashManager::sha256File(const std::string& path, Bytes& digest, uint64_t maxBytes) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return Status::fail(Err::IoFailure, "Cannot open '" + path + "': " + std::strerror(errno));
    MdPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        ::close(fd);
        return Status::fail(Err::CryptoFailure, "SHA-256 initialisation failed.");
    }
    uint8_t buf[65536];
    uint64_t total = 0;
    for (;;) {
        ssize_t r = ::read(fd, buf, sizeof buf);
        if (r < 0) {
            if (errno == EINTR) continue;
            int e = errno; ::close(fd);
            return Status::fail(Err::IoFailure, std::string("Read error: ") + std::strerror(e));
        }
        if (r == 0) break;
        total += static_cast<uint64_t>(r);
        if (total > maxBytes) { ::close(fd); return Status::fail(Err::InvalidInput, "File too large."); }
        EVP_DigestUpdate(ctx.get(), buf, static_cast<size_t>(r));
    }
    ::close(fd);
    digest.assign(EVP_MAX_MD_SIZE, 0);
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &n) != 1)
        return Status::fail(Err::CryptoFailure, "SHA-256 finalisation failed.");
    digest.resize(n);
    return Status::success();
}

}  // namespace fg
