#pragma once
#include <optional>
#include <string>
#include <vector>

#include "core/Common.h"
#include "database/DatabaseManager.h"

namespace fg {

struct AuditEntry {
    int64_t id = 0;
    std::string timestamp, username, fileUuid, action, result, details;
};

// Every important event goes to SQLite (access_logs) AND an append-only text
// file (audit.log, opened O_APPEND). Passwords/keys are never passed in here.
class AuditLogger {
public:
    AuditLogger(DatabaseManager& db, std::string logFilePath) : db_(db), logPath_(std::move(logFilePath)) {}

    void log(std::optional<int64_t> fileId, std::optional<int64_t> userId,
             const std::string& action, const std::string& result, const std::string& details = "");

    // ADMIN sees everything; others see entries for files they own or their own actions.
    std::vector<AuditEntry> recent(const User& viewer, size_t limit);
    int64_t count(const User& viewer);

private:
    DatabaseManager& db_;
    std::string logPath_;
};

}  // namespace fg
