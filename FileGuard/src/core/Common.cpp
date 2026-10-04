#include "core/Common.h"

#include <openssl/crypto.h>

#include <ctime>

namespace fg {

std::string toString(Role r) {
    switch (r) {
        case Role::Owner: return "OWNER";
        case Role::Admin: return "ADMIN";
        default: return "USER";
    }
}
std::string toString(Permission p) {
    switch (p) {
        case Permission::View: return "VIEW";
        case Permission::Read: return "READ";
        default: return "DOWNLOAD";
    }
}
bool parseRole(const std::string& s, Role& out) {
    if (s == "OWNER") { out = Role::Owner; return true; }
    if (s == "USER")  { out = Role::User;  return true; }
    if (s == "ADMIN") { out = Role::Admin; return true; }
    return false;
}
bool parsePermission(const std::string& s, Permission& out) {
    if (s == "VIEW")     { out = Permission::View;     return true; }
    if (s == "READ")     { out = Permission::Read;     return true; }
    if (s == "DOWNLOAD") { out = Permission::Download; return true; }
    return false;
}

std::string nowUtc() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    gmtime_r(&t, &tmv);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

void secureZero(Bytes& b) {
    if (!b.empty()) OPENSSL_cleanse(b.data(), b.size());
    b.clear();
}

bool constantTimeEqual(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string hexEncode(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 15]); }
    return s;
}

static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hexDecode(const std::string& s, Bytes& out) {
    out.clear();
    if (s.size() % 2 != 0) return false;
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = nibble(s[i]), lo = nibble(s[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back(static_cast<uint8_t>(hi * 16 + lo));
    }
    return true;
}

bool isValidFileId(const std::string& s) {
    if (s.size() < 8 || s.size() > 13 || s.compare(0, 3, "FG-") != 0) return false;
    for (size_t i = 3; i < s.size(); ++i)
        if (s[i] < '0' || s[i] > '9') return false;
    return true;
}

uint32_t fileNumber(const std::string& uuid) {
    if (!isValidFileId(uuid)) return 0;
    uint64_t v = 0;
    for (size_t i = 3; i < uuid.size(); ++i) v = v * 10 + static_cast<uint64_t>(uuid[i] - '0');
    return v > 0xFFFFFFFFull ? 0 : static_cast<uint32_t>(v);
}

std::string sanitizeText(const std::string& s, size_t maxLen) {
    std::string r;
    for (char ch : s) {
        if (r.size() >= maxLen) break;
        unsigned char c = static_cast<unsigned char>(ch);
        r.push_back((c < 0x20 || c == 0x7f) ? ' ' : ch);
    }
    return r;
}

}  // namespace fg
