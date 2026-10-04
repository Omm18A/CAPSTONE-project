#include "core/PermissionManager.h"

namespace fg {

std::optional<Permission> PermissionManager::effective(const User& u, const FileRecord& f) {
    if (u.status != "ACTIVE") return std::nullopt;
    if (u.id == f.ownerId) return Permission::Download;
    auto st = db_.prepare("SELECT permission FROM permissions WHERE file_id=?1 AND user_id=?2 "
                          "AND (expires_at IS NULL OR expires_at > datetime('now'))");
    st.bindInt(1, f.id).bindInt(2, u.id);
    Permission p;
    if (st.next() && parsePermission(st.text(0), p)) return p;
    return std::nullopt;
}

bool PermissionManager::check(const User& u, const FileRecord& f, Permission needed) {
    auto e = effective(u, f);
    return e && static_cast<int>(*e) >= static_cast<int>(needed);
}

Status PermissionManager::grant(const User& actor, const FileRecord& f, const User& target,
                                Permission p, int days) {
    if (actor.id != f.ownerId || actor.status != "ACTIVE") {
        audit_.log(f.id, actor.id, "ACCESS_DENIED", "DENIED", "share attempted by non-owner");
        return Status::fail(Err::AccessDenied, "Only the file owner can share this file.");
    }
    if (target.id == actor.id) return Status::fail(Err::InvalidInput, "You already own this file.");
    if (target.status != "ACTIVE") return Status::fail(Err::InvalidInput, "Target user is disabled.");
    if (days < 0 || days > 3650) return Status::fail(Err::InvalidInput, "Expiry must be 0..3650 days.");

    auto st = db_.prepare("INSERT INTO permissions(file_id,user_id,permission,granted_by,created_at,expires_at) "
                          "VALUES(?1,?2,?3,?4,?5,datetime('now',?6)) "
                          "ON CONFLICT(file_id,user_id) DO UPDATE SET permission=excluded.permission, "
                          "granted_by=excluded.granted_by, created_at=excluded.created_at, expires_at=excluded.expires_at");
    st.bindInt(1, f.id).bindInt(2, target.id).bindText(3, toString(p)).bindInt(4, actor.id).bindText(5, nowUtc());
    if (days > 0) st.bindText(6, "+" + std::to_string(days) + " days"); else st.bindNull(6);
    if (!st.execute()) return Status::fail(Err::DbFailure, "Could not store permission: " + db_.lastError());

    audit_.log(f.id, actor.id, "FILE_SHARED", "SUCCESS",
               "to=" + target.username + " perm=" + toString(p) + (days > 0 ? " expires_in_days=" + std::to_string(days) : ""));
    return Status::success();
}

Status PermissionManager::revoke(const User& actor, const FileRecord& f, const User& target) {
    if ((actor.id != f.ownerId && actor.role != Role::Admin) || actor.status != "ACTIVE") {
        audit_.log(f.id, actor.id, "ACCESS_DENIED", "DENIED", "revoke attempted without rights");
        return Status::fail(Err::AccessDenied, "Only the file owner or an ADMIN can revoke access.");
    }
    auto st = db_.prepare("DELETE FROM permissions WHERE file_id=?1 AND user_id=?2");
    st.bindInt(1, f.id).bindInt(2, target.id);
    if (!st.execute()) return Status::fail(Err::DbFailure, db_.lastError());
    auto ch = db_.prepare("SELECT changes()");
    if (!ch.next() || ch.integer(0) == 0) return Status::fail(Err::NotFound, target.username + " has no access to this file.");
    audit_.log(f.id, actor.id, "FILE_REVOKED", "SUCCESS", "from=" + target.username);
    return Status::success();
}

std::vector<GrantInfo> PermissionManager::listForFile(int64_t fileId) {
    std::vector<GrantInfo> out;
    auto st = db_.prepare("SELECT p.user_id,u.username,p.permission,COALESCE(p.expires_at,''),p.created_at "
                          "FROM permissions p JOIN users u ON u.id=p.user_id WHERE p.file_id=?1 ORDER BY u.username");
    st.bindInt(1, fileId);
    while (st.next()) {
        GrantInfo g;
        g.userId = st.integer(0); g.username = st.text(1); g.permission = st.text(2);
        g.expiresAt = st.text(3); g.createdAt = st.text(4);
        out.push_back(std::move(g));
    }
    return out;
}

}  // namespace fg
