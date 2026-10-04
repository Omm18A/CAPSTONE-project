#pragma once
// Composition root: owns every manager. The CLI, the Qt GUI and the tests all
// construct exactly this object, so they share one implementation of the rules.
#include "core/AuditLogger.h"
#include "core/AuthenticationManager.h"
#include "core/ConfigurationManager.h"
#include "core/DriverManager.h"
#include "core/FileManager.h"
#include "core/PermissionManager.h"
#include "core/SecurityManager.h"
#include "core/UserManager.h"
#include "database/DatabaseManager.h"

namespace fg {

class FileGuardCore {
public:
    explicit FileGuardCore(const std::string& home = "", const std::string& devicePath = "/dev/fileguard")
        : config(home), driver(devicePath), audit(db, config.auditLogPath()), security(db, audit, driver),
          users(db, audit), auth(db, users, audit, security), perms(db, audit),
          files(config, db, perms, audit, security, driver, users) {}

    Status init() {
        Status s = config.prepare();
        if (!s.ok()) return s;
        s = db.open(config.databasePath());
        if (!s.ok()) return s;
        return db.initSchema();
    }

    ConfigurationManager config;
    DatabaseManager db;
    DriverManager driver;
    AuditLogger audit;
    SecurityManager security;
    UserManager users;
    AuthenticationManager auth;
    PermissionManager perms;
    FileManager files;
};

}  // namespace fg
