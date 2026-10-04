#include "core/ConfigurationManager.h"

#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <climits>
#include <cstdlib>

#include "core/EncryptionManager.h"
#include "core/LinuxSystemManager.h"

namespace fg {

ConfigurationManager::ConfigurationManager(const std::string& homeOverride) {
    std::string b = homeOverride;
    if (b.empty()) { const char* e = std::getenv("FILEGUARD_HOME"); if (e && *e) b = e; }
    if (b.empty()) {
        const char* h = std::getenv("HOME");
        std::string home = (h && *h) ? h : "";
        if (home.empty()) { struct passwd* pw = ::getpwuid(::getuid()); if (pw && pw->pw_dir) home = pw->pw_dir; }
        b = home + "/.fileguard";
    }
    if (b.empty() || b[0] != '/') {
        char cwd[PATH_MAX];
        if (::getcwd(cwd, sizeof cwd)) b = std::string(cwd) + "/" + b;
    }
    while (b.size() > 1 && b.back() == '/') b.pop_back();
    base_ = b;
}

Status ConfigurationManager::prepare() {
    Status s = LinuxSystemManager::ensureDir(base_, 0700);
    if (!s.ok()) return s;
    for (const char* sub : {"/protected_files", "/database", "/audit", "/keys"}) {
        s = LinuxSystemManager::ensureDir(base_ + sub, 0700);
        if (!s.ok()) return s;
    }
    canonBase_ = LinuxSystemManager::canonicalize(base_);
    if (canonBase_.empty()) return Status::fail(Err::IoFailure, "Cannot resolve data directory.");

    const std::string kp = keyPath();
    if (!LinuxSystemManager::pathExists(kp)) {
        Bytes k;
        s = EncryptionManager::randomBytes(EncryptionManager::kKeyLen, k);
        if (!s.ok()) return s;
        s = LinuxSystemManager::writeFileExclusive(kp, k, 0600);
        secureZero(k);
        if (!s.ok()) return s;
    }
    struct stat st;
    if (::stat(kp.c_str(), &st) != 0) return Status::fail(Err::IoFailure, "Cannot stat master key.");
    if ((st.st_mode & 077) != 0)
        return Status::fail(Err::PermissionDenied, "Master key '" + kp + "' has unsafe permissions (must be 0600).");
    if (st.st_uid != ::geteuid())
        return Status::fail(Err::PermissionDenied, "Master key is owned by a different user.");
    s = LinuxSystemManager::readFile(kp, 64, master_);
    if (!s.ok()) return s;
    if (master_.size() != EncryptionManager::kKeyLen)
        return Status::fail(Err::Corrupted, "Master key file is corrupted (wrong length).");
    return Status::success();
}

}  // namespace fg
