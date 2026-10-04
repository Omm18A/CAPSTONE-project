#include "core/FilePackage.h"

#include <cstring>

#include "core/ConfigurationManager.h"
#include "core/SecurityManager.h"

namespace fg {

namespace {
const uint8_t kMagic[8] = {'F', 'G', 'U', 'A', 'R', 'D', 0, 0};
void put16(Bytes& b, uint16_t v) { b.push_back(v & 0xff); b.push_back(v >> 8); }
void put32(Bytes& b, uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back((v >> (8 * i)) & 0xff); }
void put64(Bytes& b, uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back((v >> (8 * i)) & 0xff); }
uint16_t get16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t get32(const uint8_t* p) { uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i); return v; }
uint64_t get64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i); return v; }
Status corrupt(const std::string& why) { return Status::fail(Err::Corrupted, "Corrupted .fguard file: " + why); }
}  // namespace

Status FilePackage::serializeHeader(const PackageHeader& h, Bytes& out) {
    if (!isValidFileId(h.fileUuid) || h.originalHash.size() != 32 || h.nonce.size() != 12 ||
        !SecurityManager::isSafeFileName(h.originalName) || h.originalName.size() > 255)
        return Status::fail(Err::InvalidInput, "Invalid package header fields.");
    out.clear();
    out.insert(out.end(), kMagic, kMagic + 8);
    put16(out, h.version);
    put16(out, static_cast<uint16_t>(kFixedHeader + h.fileUuid.size() + h.originalName.size()));
    out.push_back(h.cipherId);
    out.push_back(12);
    out.push_back(static_cast<uint8_t>(kTagLen));
    out.push_back(0);
    put64(out, h.originalSize);
    put32(out, h.ownerId);
    out.push_back(static_cast<uint8_t>(h.fileUuid.size()));
    out.push_back(static_cast<uint8_t>(h.originalName.size()));
    out.insert(out.end(), h.originalHash.begin(), h.originalHash.end());
    out.insert(out.end(), h.nonce.begin(), h.nonce.end());
    out.insert(out.end(), h.fileUuid.begin(), h.fileUuid.end());
    out.insert(out.end(), h.originalName.begin(), h.originalName.end());
    return Status::success();
}

Status FilePackage::build(const PackageHeader& h, const Bytes& ct, const Bytes& tag, Bytes& out) {
    if (tag.size() != kTagLen || ct.size() != h.originalSize)
        return Status::fail(Err::InvalidInput, "Ciphertext/tag size mismatch.");
    Status s = serializeHeader(h, out);
    if (!s.ok()) return s;
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return Status::success();
}

Status FilePackage::parse(const Bytes& d, PackageHeader& h, size_t& headerLen) {
    if (d.size() < kFixedHeader + kTagLen) return corrupt("file too short");
    const uint8_t* p = d.data();
    if (std::memcmp(p, kMagic, 8) != 0) return corrupt("bad magic (not a FileGuard file)");
    h = PackageHeader{};
    h.version = get16(p + 8);
    if (h.version != 1) return corrupt("unsupported format version " + std::to_string(h.version));
    const size_t hl = get16(p + 10);
    h.cipherId = p[12];
    if (h.cipherId != 1) return corrupt("unsupported cipher id");
    if (p[13] != 12 || p[14] != kTagLen || p[15] != 0) return corrupt("bad nonce/tag/flags fields");
    h.originalSize = get64(p + 16);
    h.ownerId = get32(p + 24);
    const size_t uuidLen = p[28], nameLen = p[29];
    if (h.originalSize > ConfigurationManager::kMaxFileSize) return corrupt("declared size too large");
    if (uuidLen < 8 || uuidLen > 13 || nameLen == 0) return corrupt("bad identifier lengths");
    if (hl != kFixedHeader + uuidLen + nameLen || hl > d.size()) return corrupt("bad header length");
    // exact length check: header + ciphertext(originalSize) + tag; no trailing bytes
    if (static_cast<uint64_t>(d.size()) != static_cast<uint64_t>(hl) + h.originalSize + kTagLen)
        return corrupt("length does not match declared size");
    h.originalHash.assign(p + 30, p + 62);
    h.nonce.assign(p + 62, p + 74);
    h.fileUuid.assign(reinterpret_cast<const char*>(p + 74), uuidLen);
    h.originalName.assign(reinterpret_cast<const char*>(p + 74 + uuidLen), nameLen);
    if (!isValidFileId(h.fileUuid)) return corrupt("invalid file id");
    if (!SecurityManager::isSafeFileName(h.originalName)) return corrupt("invalid original file name");
    headerLen = hl;
    return Status::success();
}

}  // namespace fg
