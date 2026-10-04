#include "TestUtil.h"
using namespace fg;

static bool tableExists(DatabaseManager& db, const char* name) {
    auto st = db.prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1");
    st.bindText(1, name);
    return st.next() && st.integer(0) == 1;
}

int main() {
    Fixture fx;
    for (const char* t : {"users", "files", "permissions", "access_logs", "security_events", "login_attempts"})
        CHECK(tableExists(fx.core.db, t));

    // user creation
    CHECK(fx.core.users.count() == 4);
    CHECK(fx.core.users.findByName("Omm")->role == Role::Owner);
    CHECK(!fx.core.users.findByName("nobody"));
    CHECK(fx.core.users.list().size() == 4);

    // file registration populates metadata
    FileRecord f = fx.registerDoc("hello world\n");
    CHECK(f.uuid == "FG-10001" && f.originalSize == 12 && f.originalHash.size() == 64 && f.protectedHash.size() == 64);
    CHECK(f.wrappedKey.size() == 60);
    CHECK(fx.core.files.findByUuid("FG-10001").has_value());
    FileRecord f2 = fx.registerDoc("second\n", "second.txt");
    CHECK(f2.uuid == "FG-10002");

    // audit logging
    CHECK(fx.countAction("USER_REGISTERED") == 4);
    CHECK(fx.countAction("FILE_REGISTERED") == 2 && fx.countAction("FILE_PROTECTED") == 2);
    std::string log = slurp(fx.core.config.auditLogPath());
    CHECK(log.find("FILE_REGISTERED") != std::string::npos);
    CHECK(log.find("ommpass123") == std::string::npos);                  // no secrets in logs

    // foreign keys enforced
    auto bad = fx.core.db.prepare("INSERT INTO permissions(file_id,user_id,permission,granted_by,created_at) VALUES(999,999,'READ',1,'x')");
    CHECK(!bad.execute());
    auto badRole = fx.core.db.prepare("INSERT INTO users(username,password_hash,salt,iterations,role,created_at) VALUES('x','h','s',1,'ROOT','t')");
    CHECK(!badRole.execute());                                           // CHECK constraint

    // prepared statements treat hostile input as data
    std::string evil = "x'; DROP TABLE users; --";
    auto ins = fx.core.db.prepare("INSERT INTO access_logs(action,result,timestamp,details) VALUES('T','R','t',?1)");
    ins.bindText(1, evil); CHECK(ins.execute());
    auto sel = fx.core.db.prepare("SELECT details FROM access_logs WHERE details=?1");
    sel.bindText(1, evil); CHECK(sel.next() && sel.text(0) == evil);
    CHECK(tableExists(fx.core.db, "users"));

    // visibility
    CHECK(fx.core.files.listVisible(fx.omm).size() == 2);
    CHECK(fx.core.files.listVisible(fx.rahul).empty());
    CHECK_OK(fx.core.files.share(fx.omm, "FG-10001", "Rahul", Permission::Read));
    CHECK(fx.core.files.listVisible(fx.rahul).size() == 1);
    CHECK(fx.core.files.countOwned(fx.omm) == 2 && fx.core.files.countSharedWith(fx.rahul) == 1);

    // missing / unwritable database location
    TempDir d; DatabaseManager db;
    CHECK_CODE(db.open(d.path + "/no/such/dir/x.db"), Err::DbFailure);
    CHECK(!db.prepare("SELECT 1").valid());
    return finish("test_database");
}
