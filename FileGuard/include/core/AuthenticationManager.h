#pragma once
#include <optional>
#include <string>

#include "core/AuditLogger.h"
#include "core/Common.h"
#include "core/SecurityManager.h"
#include "core/UserManager.h"

namespace fg {

struct PasswordHash { std::string saltHex, hashHex; int iterations = 0; };

// PBKDF2-HMAC-SHA256, random 16-byte salt per password, cost stored per user.
class PasswordHasher {
public:
    static constexpr int kDefaultIterations = 600000;   // OWASP guidance for PBKDF2-SHA256
    static void setIterations(int n);                   // test hook only (clamped to >= 1000)
    static int iterations();
    static Status hash(const std::string& password, PasswordHash& out);
    static bool verify(const std::string& password, const std::string& saltHex,
                       const std::string& hashHex, int iterations);   // constant-time compare
};

struct LoginResult {
    Status status;
    std::optional<User> user;
};

class AuthenticationManager {
public:
    static constexpr int kMaxFailures = 5;          // within the window below
    static constexpr int kLockoutSeconds = 300;

    AuthenticationManager(DatabaseManager& db, UserManager& users, AuditLogger& audit, SecurityManager& sec)
        : db_(db), users_(users), audit_(audit), sec_(sec) {}

    LoginResult login(const std::string& username, const std::string& password);

private:
    int64_t recentFailures(const std::string& username);
    DatabaseManager& db_;
    UserManager& users_;
    AuditLogger& audit_;
    SecurityManager& sec_;
};

}  // namespace fg
