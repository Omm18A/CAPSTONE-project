#pragma once
// Thin RAII wrapper over SQLite3. All data-bearing SQL goes through prepared
// statements with bound parameters (never string concatenation).
#include <string>

#include "core/Common.h"

struct sqlite3;
struct sqlite3_stmt;

namespace fg {

class DatabaseManager {
public:
    class Stmt {
    public:
        Stmt() = default;
        Stmt(sqlite3* db, sqlite3_stmt* s) : db_(db), s_(s) {}
        Stmt(Stmt&& o) noexcept;
        Stmt& operator=(Stmt&& o) noexcept;
        Stmt(const Stmt&) = delete;
        Stmt& operator=(const Stmt&) = delete;
        ~Stmt();

        bool valid() const { return s_ != nullptr; }
        Stmt& bindText(int idx, const std::string& v);
        Stmt& bindInt(int idx, int64_t v);
        Stmt& bindNull(int idx);
        Stmt& bindBlob(int idx, const Bytes& v);

        int step();                       // raw sqlite3_step result
        bool execute();                   // true if statement ran to SQLITE_DONE
        bool next();                      // true if a row is available

        std::string text(int col);
        int64_t integer(int col);
        Bytes blob(int col);
        bool isNull(int col);
        std::string error() const;

    private:
        sqlite3* db_ = nullptr;
        sqlite3_stmt* s_ = nullptr;
    };

    // BEGIN IMMEDIATE ... COMMIT; rolls back automatically unless commit() ran.
    class Transaction {
    public:
        explicit Transaction(DatabaseManager& db);
        ~Transaction();
        bool active() const { return active_; }
        bool commit();
    private:
        DatabaseManager& db_;
        bool active_ = false;
    };

    DatabaseManager() = default;
    ~DatabaseManager();
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    Status open(const std::string& path);
    Status initSchema();
    void close();
    bool isOpen() const { return db_ != nullptr; }

    Status exec(const char* constantSql);   // only for fixed SQL (schema, BEGIN, ...)
    Stmt prepare(const char* sql);          // invalid Stmt on error (see lastError)
    int64_t lastInsertId() const;
    std::string lastError() const;

private:
    sqlite3* db_ = nullptr;
};

}  // namespace fg
