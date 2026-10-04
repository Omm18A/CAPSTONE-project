#pragma once
#include <string>

#include "core/Common.h"

namespace fg {

// Locates and prepares the FileGuard data directory:
//   <home>/protected_files  (0700)  .fguard packages
//   <home>/database         (0700)  SQLite DB (file itself 0600)
//   <home>/audit            (0700)  append-only audit.log
//   <home>/keys             (0700)  master.key (0600)
// <home> = $FILEGUARD_HOME, else $HOME/.fileguard.
class ConfigurationManager {
public:
    static constexpr uint64_t kMaxFileSize = 256ull * 1024 * 1024;   // plaintext limit
    static constexpr uint64_t kMaxPackageSize = kMaxFileSize + 4096; // header + tag slack

    explicit ConfigurationManager(const std::string& homeOverride = "");
    Status prepare();   // create dirs, load or create master key

    const std::string& baseDir() const { return base_; }
    std::string protectedDir() const { return base_ + "/protected_files"; }
    std::string databasePath() const { return base_ + "/database/fileguard.db"; }
    std::string auditLogPath() const { return base_ + "/audit/audit.log"; }
    std::string keyPath() const { return base_ + "/keys/master.key"; }
    const Bytes& masterKey() const { return master_; }
    const std::string& canonicalBase() const { return canonBase_; }

private:
    std::string base_, canonBase_;
    Bytes master_;
};

}  // namespace fg
