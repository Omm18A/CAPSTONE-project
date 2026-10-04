#pragma once
#include <optional>
#include <string>
#include <vector>

#include "core/AuditLogger.h"
#include "core/Common.h"
#include "database/DatabaseManager.h"

namespace fg {

struct GrantInfo {
    int64_t userId = 0;
    std::string username, permission, expiresAt, createdAt;
};

// VIEW     : see metadata, run integrity verification
// READ     : VIEW + decrypt and view content in memory
// DOWNLOAD : READ + export a decrypted copy to disk
// The file owner always has every permission. ADMIN has no implicit access to
// file *content* (admins manage users and inspect logs).
class PermissionManager {
public:
    PermissionManager(DatabaseManager& db, AuditLogger& audit) : db_(db), audit_(audit) {}

    // Only the file owner may share. expiresDays 0 = never expires.
    Status grant(const User& actor, const FileRecord& file, const User& target,
                 Permission p, int expiresDays = 0);
    // Owner or ADMIN may revoke.
    Status revoke(const User& actor, const FileRecord& file, const User& target);
    bool check(const User& user, const FileRecord& file, Permission needed);
    std::optional<Permission> effective(const User& user, const FileRecord& file);
    std::vector<GrantInfo> listForFile(int64_t fileId);

private:
    DatabaseManager& db_;
    AuditLogger& audit_;
};

}  // namespace fg
