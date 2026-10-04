#include "database/DatabaseManager.h"

#include <sqlite3.h>
#include <sys/stat.h>

#include "SchemaSql.h"

namespace fg {

// ---- Stmt -----------------------------------------------------------------
DatabaseManager::Stmt::Stmt(Stmt&& o) noexcept : db_(o.db_), s_(o.s_) { o.s_ = nullptr; }
DatabaseManager::Stmt& DatabaseManager::Stmt::operator=(Stmt&& o) noexcept {
    if (this != &o) {
        if (s_) sqlite3_finalize(s_);
        db_ = o.db_; s_ = o.s_; o.s_ = nullptr;
    }
    return *this;
}
DatabaseManager::Stmt::~Stmt() { if (s_) sqlite3_finalize(s_); }

DatabaseManager::Stmt& DatabaseManager::Stmt::bindText(int i, const std::string& v) {
    if (s_) sqlite3_bind_text(s_, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}
DatabaseManager::Stmt& DatabaseManager::Stmt::bindInt(int i, int64_t v) {
    if (s_) sqlite3_bind_int64(s_, i, v);
    return *this;
}
DatabaseManager::Stmt& DatabaseManager::Stmt::bindNull(int i) {
    if (s_) sqlite3_bind_null(s_, i);
    return *this;
}
DatabaseManager::Stmt& DatabaseManager::Stmt::bindBlob(int i, const Bytes& v) {
    if (s_) sqlite3_bind_blob(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
    return *this;
}
int DatabaseManager::Stmt::step() { return s_ ? sqlite3_step(s_) : SQLITE_MISUSE; }
bool DatabaseManager::Stmt::execute() { return step() == SQLITE_DONE; }
bool DatabaseManager::Stmt::next() { return step() == SQLITE_ROW; }

std::string DatabaseManager::Stmt::text(int col) {
    const unsigned char* p = sqlite3_column_text(s_, col);
    if (!p) return {};
    int n = sqlite3_column_bytes(s_, col);
    return std::string(reinterpret_cast<const char*>(p), static_cast<size_t>(n));
}
int64_t DatabaseManager::Stmt::integer(int col) { return sqlite3_column_int64(s_, col); }
Bytes DatabaseManager::Stmt::blob(int col) {
    const void* p = sqlite3_column_blob(s_, col);
    int n = sqlite3_column_bytes(s_, col);
    if (!p || n <= 0) return {};
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return Bytes(b, b + n);
}
bool DatabaseManager::Stmt::isNull(int col) { return sqlite3_column_type(s_, col) == SQLITE_NULL; }
std::string DatabaseManager::Stmt::error() const { return db_ ? sqlite3_errmsg(db_) : "no statement"; }

// ---- Transaction ------------------------------------------------------------
DatabaseManager::Transaction::Transaction(DatabaseManager& db) : db_(db) {
    active_ = db_.exec("BEGIN IMMEDIATE").ok();
}
DatabaseManager::Transaction::~Transaction() {
    if (active_) db_.exec("ROLLBACK");
}
bool DatabaseManager::Transaction::commit() {
    if (!active_) return false;
    bool ok = db_.exec("COMMIT").ok();
    active_ = false;
    if (!ok) db_.exec("ROLLBACK");
    return ok;
}

// ---- DatabaseManager ----------------------------------------------------------
DatabaseManager::~DatabaseManager() { close(); }

void DatabaseManager::close() {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
}

Status DatabaseManager::open(const std::string& path) {
    close();
    int rc = sqlite3_open_v2(path.c_str(), &db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
    if (rc != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        close();
        return Status::fail(Err::DbFailure, "Cannot open database '" + path + "': " + msg);
    }
    ::chmod(path.c_str(), 0600);   // DB holds hashes and wrapped keys: owner only
    sqlite3_busy_timeout(db_, 3000);
    return exec("PRAGMA foreign_keys = ON;");
}

Status DatabaseManager::initSchema() { return exec(kSchemaSql); }

Status DatabaseManager::exec(const char* sql) {
    if (!db_) return Status::fail(Err::DbFailure, "Database is not open.");
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string m = err ? err : "unknown error";
        sqlite3_free(err);
        return Status::fail(Err::DbFailure, "Database error: " + m);
    }
    return Status::success();
}

DatabaseManager::Stmt DatabaseManager::prepare(const char* sql) {
    if (!db_) return Stmt();
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &s, nullptr) != SQLITE_OK) return Stmt(db_, nullptr);
    return Stmt(db_, s);
}

int64_t DatabaseManager::lastInsertId() const { return db_ ? sqlite3_last_insert_rowid(db_) : 0; }
std::string DatabaseManager::lastError() const { return db_ ? sqlite3_errmsg(db_) : "database not open"; }

}  // namespace fg
