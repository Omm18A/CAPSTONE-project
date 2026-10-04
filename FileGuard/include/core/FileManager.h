#pragma once
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "core/AuditLogger.h"
#include "core/Common.h"
#include "core/ConfigurationManager.h"
#include "core/DriverManager.h"
#include "core/PermissionManager.h"
#include "core/SecurityManager.h"
#include "core/UserManager.h"
#include "database/DatabaseManager.h"

namespace fg {

// Registration, protection, controlled access, verification, sharing.
// Every access path runs the same pipeline:
//   authenticated user -> authorisation -> on-disk integrity (SHA-256)
//   -> unwrap key -> AES-256-GCM decrypt -> plaintext SHA-256 check -> audit log
class FileManager {
public:
    using Progress = std::function<void(const std::string&)>;

    FileManager(ConfigurationManager& cfg, DatabaseManager& db, PermissionManager& perms,
                AuditLogger& audit, SecurityManager& sec, DriverManager& drv, UserManager& users)
        : cfg_(cfg), db_(db), perms_(perms), audit_(audit), sec_(sec), drv_(drv), users_(users) {}

    Status registerFile(const User& owner, const std::string& srcPath, FileRecord& out);
    std::optional<FileRecord> findByUuid(const std::string& uuid);
    std::vector<FileRecord> listVisible(const User& u);   // owned + shared with me (not expired)

    // idOrPath: "FG-10001" or the path of a .fguard file (e.g. one that was e-mailed).
    Status open(const User& u, const std::string& idOrPath, Bytes& content,
                FileRecord* rec = nullptr, const Progress& progress = {});
    Status download(const User& u, const std::string& idOrPath, const std::string& dest);
    Status verify(const User& u, const std::string& idOrPath);
    Status exportPackage(const User& owner, const std::string& id, const std::string& dest);

    Status share(const User& owner, const std::string& id, const std::string& targetUser,
                 Permission p, int expiresDays = 0);
    Status revoke(const User& actor, const std::string& id, const std::string& targetUser);

    int64_t countOwned(const User& u);
    int64_t countSharedWith(const User& u);

private:
    Status pipeline(const User& u, const std::string& idOrPath, Permission need, const std::string& action,
                    const std::string& successAction, Bytes* content, FileRecord* rec, const Progress& progress);
    Status checkDestination(const std::string& dest);
    void integrityAlert(const FileRecord& f, const User& u, const std::string& why);

    ConfigurationManager& cfg_;
    DatabaseManager& db_;
    PermissionManager& perms_;
    AuditLogger& audit_;
    SecurityManager& sec_;
    DriverManager& drv_;
    UserManager& users_;
};

}  // namespace fg
