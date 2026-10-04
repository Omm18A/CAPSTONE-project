#pragma once
// Minimal dependency-free test harness (no external framework required).
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

#include "core/FileGuardCore.h"
#include "core/LinuxSystemManager.h"
#include "core/HashManager.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(cond) do { if (cond) { ++g_pass; } else { ++g_fail; \
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_CODE(status, expected) do { fg::Status _s = (status); if (_s.code == (expected)) { ++g_pass; } else { ++g_fail; \
    std::fprintf(stderr, "  FAIL %s:%d: %s -> code %d (%s)\n", __FILE__, __LINE__, #status, static_cast<int>(_s.code), _s.message.c_str()); } } while (0)
#define CHECK_OK(status) CHECK_CODE(status, fg::Err::Ok)

inline int finish(const char* name) {
    std::printf("%-22s %3d passed, %d failed\n", name, g_pass, g_fail);
    return g_fail ? 1 : 0;
}

struct TempDir {
    std::string path;
    TempDir() { char t[] = "/tmp/fgtestXXXXXX"; path = mkdtemp(t); }
    ~TempDir() { std::string c = "rm -rf '" + path + "'"; int r = std::system(c.c_str()); (void)r; }
};

inline std::string writeFile(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary); f << data; return path;
}
inline std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary); return std::string((std::istreambuf_iterator<char>(f)), {});
}

// Fresh store with admin + three users (Omm=OWNER, Rahul/Priya=USER).
struct Fixture {
    TempDir home, src;
    fg::FileGuardCore core;
    fg::User admin, omm, rahul, priya;

    explicit Fixture(const std::string& device = "/nonexistent/fileguard") : core(home.path, device) {
        fg::PasswordHasher::setIterations(1000);  // fast tests; production default is 600000
        fg::Status s = core.init();
        if (!s.ok()) { std::fprintf(stderr, "init failed: %s\n", s.message.c_str()); std::exit(2); }
        must(core.users.registerUser("admin", "adminpass1", fg::Role::Admin, nullptr, &admin));
        must(core.users.registerUser("Omm", "ommpass123", fg::Role::Owner, nullptr, &omm));
        must(core.users.registerUser("Rahul", "rahulpass1", fg::Role::User, nullptr, &rahul));
        must(core.users.registerUser("Priya", "priyapass1", fg::Role::User, nullptr, &priya));
    }
    static void must(const fg::Status& s) {
        if (!s.ok()) { std::fprintf(stderr, "fixture error: %s\n", s.message.c_str()); std::exit(2); }
    }
    std::string srcFile(const std::string& name, const std::string& data) { return writeFile(src.path + "/" + name, data); }
    fg::FileRecord registerDoc(const std::string& data = "TOP SECRET: launch code 0000\n", const std::string& name = "confidential.txt") {
        fg::FileRecord r;
        must(core.files.registerFile(omm, srcFile(name, data), r));
        return r;
    }
    int64_t countAction(const std::string& action, const std::string& result = "") {
        auto st = core.db.prepare("SELECT COUNT(*) FROM access_logs WHERE action=?1 AND (?2='' OR result=?2)");
        st.bindText(1, action).bindText(2, result);
        return st.next() ? st.integer(0) : -1;
    }
    int64_t countEvents(const std::string& type) {
        auto st = core.db.prepare("SELECT COUNT(*) FROM security_events WHERE event_type=?1");
        st.bindText(1, type);
        return st.next() ? st.integer(0) : -1;
    }
};
