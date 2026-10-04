#pragma once
// Shared types and small helpers used by every FileGuard module.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fg {

using Bytes = std::vector<uint8_t>;

enum class Err {
    Ok = 0, InvalidInput, NotFound, AccessDenied, AuthFailed, AccountLocked,
    IntegrityFailure, CryptoFailure, DbFailure, IoFailure, Corrupted,
    DriverUnavailable, PermissionDenied
};

struct Status {
    Err code = Err::Ok;
    std::string message;
    bool ok() const { return code == Err::Ok; }
    static Status success() { return Status{}; }
    static Status fail(Err c, std::string m) { Status s; s.code = c; s.message = std::move(m); return s; }
};

enum class Role { Owner, User, Admin };
enum class Permission { View = 1, Read = 2, Download = 3 };  // higher implies lower

std::string toString(Role r);
std::string toString(Permission p);
bool parseRole(const std::string& s, Role& out);
bool parsePermission(const std::string& s, Permission& out);

struct User {
    int64_t id = 0;
    std::string username;
    Role role = Role::User;
    std::string status;      // ACTIVE | DISABLED
    std::string createdAt;
};

struct FileRecord {
    int64_t id = 0;
    std::string uuid;        // FG-10001
    int64_t ownerId = 0;
    std::string ownerName;
    std::string originalName;
    std::string protectedPath;
    uint64_t originalSize = 0;
    std::string originalHash;   // SHA-256 hex of plaintext
    std::string protectedHash;  // SHA-256 hex of the .fguard container
    std::string createdAt;
    std::string status;
    Bytes wrappedKey;
};

std::string nowUtc();                       // "YYYY-MM-DD HH:MM:SS" (UTC)
void secureZero(Bytes& b);                  // OPENSSL_cleanse + clear
bool constantTimeEqual(const Bytes& a, const Bytes& b);
std::string hexEncode(const Bytes& b);
bool hexDecode(const std::string& s, Bytes& out);
bool isValidFileId(const std::string& s);   // ^FG-[0-9]{5,10}$
uint32_t fileNumber(const std::string& uuid);
std::string sanitizeText(const std::string& s, size_t maxLen = 200); // strips control chars

}  // namespace fg
