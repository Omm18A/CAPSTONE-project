#include "core/AuthenticationManager.h"

#include <ctime>

#include "core/EncryptionManager.h"

namespace fg {

namespace {
int g_iterations = PasswordHasher::kDefaultIterations;
const char* kDummySalt = "00112233445566778899aabbccddeeff";
}  // namespace

void PasswordHasher::setIterations(int n) { g_iterations = n < 1000 ? 1000 : n; }
int PasswordHasher::iterations() { return g_iterations; }

Status PasswordHasher::hash(const std::string& pw, PasswordHash& out) {
    Bytes salt, key;
    Status s = EncryptionManager::randomBytes(16, salt);
    if (!s.ok()) return s;
    s = EncryptionManager::pbkdf2(pw, salt, g_iterations, 32, key);
    if (!s.ok()) return s;
    out.saltHex = hexEncode(salt); out.hashHex = hexEncode(key); out.iterations = g_iterations;
    secureZero(key);
    return Status::success();
}

bool PasswordHasher::verify(const std::string& pw, const std::string& saltHex, const std::string& hashHex, int it) {
    Bytes salt, expect, key;
    if (!hexDecode(saltHex, salt) || !hexDecode(hashHex, expect) || it < 1) return false;
    if (!EncryptionManager::pbkdf2(pw, salt, it, expect.size(), key).ok()) return false;
    bool ok = constantTimeEqual(key, expect);
    secureZero(key);
    return ok;
}

int64_t AuthenticationManager::recentFailures(const std::string& username) {
    auto st = db_.prepare("SELECT COUNT(*) FROM login_attempts WHERE username=?1 AND ts>?2");
    st.bindText(1, username).bindInt(2, static_cast<int64_t>(std::time(nullptr)) - kLockoutSeconds);
    return st.next() ? st.integer(0) : 0;
}

LoginResult AuthenticationManager::login(const std::string& rawName, const std::string& password) {
    const std::string name = sanitizeText(rawName, 64);
    const std::string generic = "Invalid username or password.";
    LoginResult res;

    auto user = users_.findByName(name);
    std::optional<int64_t> uid = user ? std::optional<int64_t>(user->id) : std::nullopt;

    if (recentFailures(name) >= kMaxFailures) {
        audit_.log(std::nullopt, uid, "LOGIN_FAILURE", "DENIED", "account temporarily locked: " + name);
        res.status = Status::fail(Err::AccountLocked, "Too many failed attempts. Try again in a few minutes.");
        return res;
    }

    bool ok = false;
    if (user && user->status == "ACTIVE") {
        auto st = db_.prepare("SELECT password_hash,salt,iterations FROM users WHERE id=?1");
        st.bindInt(1, user->id);
        if (st.next()) ok = PasswordHasher::verify(password, st.text(1), st.text(0), static_cast<int>(st.integer(2)));
    } else {
        // equalise timing so unknown/disabled users are not distinguishable
        (void)PasswordHasher::verify(password, kDummySalt, kDummySalt, PasswordHasher::iterations());
    }

    if (ok) {
        auto del = db_.prepare("DELETE FROM login_attempts WHERE username=?1");
        del.bindText(1, name); del.execute();
        audit_.log(std::nullopt, user->id, "LOGIN_SUCCESS", "SUCCESS", "");
        res.status = Status::success();
        res.user = user;
        return res;
    }

    auto ins = db_.prepare("INSERT INTO login_attempts(username,ts) VALUES(?1,?2)");
    ins.bindText(1, name).bindInt(2, static_cast<int64_t>(std::time(nullptr)));
    ins.execute();
    auto trim = db_.prepare("DELETE FROM login_attempts WHERE ts<?1");   // bound table growth
    trim.bindInt(1, static_cast<int64_t>(std::time(nullptr)) - 3600);
    trim.execute();

    audit_.log(std::nullopt, uid, "LOGIN_FAILURE", "FAILURE",
               user ? (user->status == "ACTIVE" ? "bad password" : "account disabled") : "unknown user '" + name + "'");
    if (recentFailures(name) == kMaxFailures)
        sec_.raise(std::nullopt, uid, "REPEATED_LOGIN_FAILURE", "HIGH",
                   std::to_string(kMaxFailures) + " failed logins for '" + name + "'; account locked temporarily");
    res.status = Status::fail(Err::AuthFailed, generic);
    return res;
}

}  // namespace fg
