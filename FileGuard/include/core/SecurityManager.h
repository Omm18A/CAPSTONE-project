#pragma once
#include <optional>
#include <string>
#include <vector>

#include "core/AuditLogger.h"
#include "core/Common.h"
#include "core/DriverManager.h"

namespace fg {

struct SecurityEvent {
    int64_t id = 0;
    std::string timestamp, username, fileUuid, type, severity, details;
};

// Records security events (DB + audit log + best-effort kernel driver) and
// hosts the input/path validation rules shared by all modules.
class SecurityManager {
public:
    SecurityManager(DatabaseManager& db, AuditLogger& audit, DriverManager& driver)
        : db_(db), audit_(audit), driver_(driver) {}

    // driverEvent: one of enum fg_event_type, or 0 to not notify the driver.
    void raise(std::optional<int64_t> fileId, std::optional<int64_t> userId,
               const std::string& type, const std::string& severity,
               const std::string& details, uint32_t driverEvent = 0, uint32_t fileNum = 0);

    std::vector<SecurityEvent> recent(const User& viewer, size_t limit);
    int64_t count(const User& viewer);

    // User-supplied filesystem path: non-empty, <4096 bytes, no NUL/control chars,
    // and no ".." component (blocks ../../etc/passwd style traversal outright).
    static Status checkUserPath(const std::string& path);
    // A file name that is safe to store in metadata (no '/', NUL, controls, not "."/"..").
    static bool isSafeFileName(const std::string& name);

private:
    DatabaseManager& db_;
    AuditLogger& audit_;
    DriverManager& driver_;
};

}  // namespace fg
