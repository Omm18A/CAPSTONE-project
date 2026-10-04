#pragma once
#include <optional>
#include <string>
#include <vector>

#include "core/AuditLogger.h"
#include "core/Common.h"
#include "database/DatabaseManager.h"

namespace fg {

class UserManager {
public:
    UserManager(DatabaseManager& db, AuditLogger& audit) : db_(db), audit_(audit) {}

    // Rules: the first account must be ADMIN (bootstrap). Later ADMIN accounts need an
    // authenticated ADMIN actor. Anyone may self-register OWNER or USER (actor may be null).
    Status registerUser(const std::string& name, const std::string& password, Role role,
                        const User* actor, User* created = nullptr);
    int64_t count();
    std::optional<User> findByName(const std::string& name);
    std::optional<User> findById(int64_t id);
    std::vector<User> list();
    Status setActive(const User& actor, const std::string& name, bool active);

    static Status validateUsername(const std::string& name);   // 3..32 of [A-Za-z0-9_]
    static Status validatePassword(const std::string& pw);     // 8..128 bytes

private:
    DatabaseManager& db_;
    AuditLogger& audit_;
};

}  // namespace fg
