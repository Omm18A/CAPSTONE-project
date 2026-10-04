#include "core/UserManager.h"

#include "core/AuthenticationManager.h"

namespace fg {

Status UserManager::validateUsername(const std::string& n) {
    if (n.size() < 3 || n.size() > 32) return Status::fail(Err::InvalidInput, "Username must be 3-32 characters.");
    for (char c : n) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return Status::fail(Err::InvalidInput, "Username may contain only letters, digits and '_'.");
    }
    return Status::success();
}

Status UserManager::validatePassword(const std::string& p) {
    if (p.size() < 8) return Status::fail(Err::InvalidInput, "Password must be at least 8 characters.");
    if (p.size() > 128) return Status::fail(Err::InvalidInput, "Password must be at most 128 characters.");
    return Status::success();
}

static User rowToUser(DatabaseManager::Stmt& s) {
    User u;
    u.id = s.integer(0); u.username = s.text(1);
    parseRole(s.text(2), u.role);
    u.status = s.text(3); u.createdAt = s.text(4);
    return u;
}

int64_t UserManager::count() {
    auto st = db_.prepare("SELECT COUNT(*) FROM users");
    return st.next() ? st.integer(0) : 0;
}

std::optional<User> UserManager::findByName(const std::string& name) {
    auto st = db_.prepare("SELECT id,username,role,status,created_at FROM users WHERE username=?1");
    st.bindText(1, name);
    if (st.next()) return rowToUser(st);
    return std::nullopt;
}

std::optional<User> UserManager::findById(int64_t id) {
    auto st = db_.prepare("SELECT id,username,role,status,created_at FROM users WHERE id=?1");
    st.bindInt(1, id);
    if (st.next()) return rowToUser(st);
    return std::nullopt;
}

std::vector<User> UserManager::list() {
    std::vector<User> out;
    auto st = db_.prepare("SELECT id,username,role,status,created_at FROM users ORDER BY id");
    while (st.next()) out.push_back(rowToUser(st));
    return out;
}

Status UserManager::registerUser(const std::string& name, const std::string& password, Role role,
                                 const User* actor, User* created) {
    Status s = validateUsername(name);
    if (!s.ok()) return s;
    s = validatePassword(password);
    if (!s.ok()) return s;

    const int64_t n = count();
    if (n == 0 && role != Role::Admin)
        return Status::fail(Err::InvalidInput, "The first account must be an ADMIN (bootstrap).");
    if (role == Role::Admin && n > 0 && !(actor && actor->role == Role::Admin && actor->status == "ACTIVE")) {
        audit_.log(std::nullopt, actor ? std::optional<int64_t>(actor->id) : std::nullopt,
                   "ACCESS_DENIED", "DENIED", "attempt to create ADMIN without admin rights");
        return Status::fail(Err::AccessDenied, "Only an ADMIN can create ADMIN accounts.");
    }
    if (findByName(name)) return Status::fail(Err::InvalidInput, "Username already exists.");

    PasswordHash ph;
    s = PasswordHasher::hash(password, ph);
    if (!s.ok()) return s;

    auto st = db_.prepare("INSERT INTO users(username,password_hash,salt,iterations,role,created_at,status) VALUES(?1,?2,?3,?4,?5,?6,'ACTIVE')");
    st.bindText(1, name).bindText(2, ph.hashHex).bindText(3, ph.saltHex).bindInt(4, ph.iterations)
      .bindText(5, toString(role)).bindText(6, nowUtc());
    if (!st.execute()) return Status::fail(Err::DbFailure, "Could not create user: " + db_.lastError());

    int64_t id = db_.lastInsertId();
    audit_.log(std::nullopt, id, "USER_REGISTERED", "SUCCESS", "role=" + toString(role));
    if (created) *created = *findById(id);
    return Status::success();
}

Status UserManager::setActive(const User& actor, const std::string& name, bool active) {
    if (actor.role != Role::Admin) {
        audit_.log(std::nullopt, actor.id, "ACCESS_DENIED", "DENIED", "user management requires ADMIN");
        return Status::fail(Err::AccessDenied, "Only an ADMIN can manage users.");
    }
    auto t = findByName(name);
    if (!t) return Status::fail(Err::NotFound, "No such user.");
    if (t->id == actor.id) return Status::fail(Err::InvalidInput, "You cannot change your own status.");
    auto st = db_.prepare("UPDATE users SET status=?1 WHERE id=?2");
    st.bindText(1, active ? "ACTIVE" : "DISABLED").bindInt(2, t->id);
    if (!st.execute()) return Status::fail(Err::DbFailure, db_.lastError());
    audit_.log(std::nullopt, actor.id, "USER_STATUS_CHANGED", "SUCCESS", name + (active ? " enabled" : " disabled"));
    return Status::success();
}

}  // namespace fg
