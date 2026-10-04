// FileGuard command-line interface. Uses exactly the same core as the Qt GUI.
#include <termios.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "core/FileGuardCore.h"
#include "core/LinuxSystemManager.h"

using namespace fg;

namespace {

const char* kUsage =
R"(FileGuard - protected file distribution, access control and audit logging

Usage: fileguard [--home DIR] [--user NAME] <command> [args]

  user add <name> <OWNER|USER|ADMIN>   create an account (first account must be ADMIN;
                                       creating ADMINs needs --user <admin>)
  user list | user disable <name> | user enable <name>
  register <file>                      protect a file -> FG-xxxxx (OWNER role)
  list                                 files you own or that are shared with you
  share <file-id> <user> <VIEW|READ|DOWNLOAD> [days]
  revoke <file-id> <user>
  open <file-id | file.fguard>         authenticate, authorise, verify, decrypt, view
  download <file-id|file.fguard> <dest>   write a decrypted copy (DOWNLOAD permission)
  verify <file-id>                     integrity check only
  export <file-id> <dest.fguard>       copy the protected package for distribution (owner)
  logs [N]                             audit log (ADMIN: all; others: own/owned files)
  alerts [N]                           security events
  sysinfo                              CPU / memory / storage / kernel / driver state
  driver status | driver events        /dev/fileguard counters / drain queued events (ADMIN)

Passwords: prompted without echo. For scripted demos only: FILEGUARD_PASSWORD (login) and
FILEGUARD_NEW_PASSWORD (user add). Data directory: --home, $FILEGUARD_HOME or ~/.fileguard.
Exit codes: 0 ok, 1 error, 2 usage, 3 access denied, 4 integrity failure.
)";

int exitFor(const Status& s) {
    switch (s.code) {
        case Err::Ok: return 0;
        case Err::AccessDenied: case Err::AuthFailed: case Err::AccountLocked: case Err::PermissionDenied: return 3;
        case Err::IntegrityFailure: case Err::Corrupted: return 4;
        default: return 1;
    }
}

int fail(const Status& s) {
    if (s.code == Err::IntegrityFailure || s.code == Err::Corrupted) std::fprintf(stderr, "\xe2\x9a\xa0 %s\n", s.message.c_str());
    else std::fprintf(stderr, "Error: %s\n", s.message.c_str());
    return exitFor(s);
}

std::string readSecret(const char* prompt) {
    std::fputs(prompt, stderr);
    std::fflush(stderr);
    termios oldt{};
    bool tty = ::isatty(STDIN_FILENO) && ::tcgetattr(STDIN_FILENO, &oldt) == 0;
    if (tty) { termios t = oldt; t.c_lflag &= static_cast<tcflag_t>(~ECHO); ::tcsetattr(STDIN_FILENO, TCSANOW, &t); }
    std::string s;
    std::getline(std::cin, s);
    if (tty) { ::tcsetattr(STDIN_FILENO, TCSANOW, &oldt); std::fputs("\n", stderr); }
    return s;
}

std::string fromEnvOrPrompt(const char* env, const std::string& prompt) {
    const char* e = std::getenv(env);
    return (e && *e) ? std::string(e) : readSecret(prompt.c_str());
}

bool authenticate(FileGuardCore& core, const std::string& name, User& out, int& rc) {
    if (name.empty()) { std::fprintf(stderr, "Error: this command needs --user <name>.\n"); rc = 2; return false; }
    LoginResult r = core.auth.login(name, fromEnvOrPrompt("FILEGUARD_PASSWORD", "Password for " + name + ": "));
    if (!r.status.ok()) { rc = fail(r.status); return false; }
    out = *r.user;
    return true;
}

bool looksLikeText(const Bytes& b) {
    for (uint8_t c : b)
        if (c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t')) return false;
    return true;
}

std::string human(uint64_t n) {
    char buf[32];
    if (n >= 1048576) std::snprintf(buf, sizeof buf, "%.1f MiB", n / 1048576.0);
    else if (n >= 1024) std::snprintf(buf, sizeof buf, "%.1f KiB", n / 1024.0);
    else std::snprintf(buf, sizeof buf, "%llu B", static_cast<unsigned long long>(n));
    return buf;
}

size_t parseCount(const std::vector<std::string>& a, size_t idx, size_t def) {
    if (a.size() <= idx) return def;
    char* end = nullptr;
    long v = std::strtol(a[idx].c_str(), &end, 10);
    return (end && *end == '\0' && v > 0 && v <= 10000) ? static_cast<size_t>(v) : def;
}

}  // namespace

int main(int argc, char** argv) {
    std::string home, userName;
    std::vector<std::string> a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--home" && i + 1 < argc) home = argv[++i];
        else if (s == "--user" && i + 1 < argc) userName = argv[++i];
        else if (s == "-h" || s == "--help") { std::fputs(kUsage, stdout); return 0; }
        else a.push_back(s);
    }
    if (a.empty()) { std::fputs(kUsage, stderr); return 2; }

    if (LinuxSystemManager::isRoot())
        std::fprintf(stderr, "Warning: running as root is unnecessary and discouraged. Only driver install needs root.\n");

    FileGuardCore core(home);
    Status st = core.init();
    if (!st.ok()) return fail(st);
    const std::string cmd = a[0];
    int rc = 0;
    User me;

    // ---- commands that need no login ----
    if (cmd == "sysinfo") {
        std::fputs(LinuxSystemManager::format(LinuxSystemManager::gather(core.config.baseDir())).c_str(), stdout);
        return 0;
    }
    if (cmd == "driver" && a.size() == 2 && a[1] == "status") {
        uint32_t ver = 0; fg_stats s{};
        st = core.driver.getVersion(ver);
        if (!st.ok()) return fail(st);
        st = core.driver.getStats(s);
        if (!st.ok()) return fail(st);
        std::printf("driver version : %u\npending events : %u/%u\ntotal accepted : %llu\ndropped        : %llu\n",
                    ver, s.pending, s.capacity, static_cast<unsigned long long>(s.total), static_cast<unsigned long long>(s.dropped));
        for (uint32_t t = 1; t < FG_EVT_MAX; ++t)
            std::printf("  %-24s %llu\n", DriverManager::typeName(t), static_cast<unsigned long long>(s.per_type[t]));
        return 0;
    }

    // ---- user add (self-registration allowed for OWNER/USER) ----
    if (cmd == "user" && a.size() >= 2 && a[1] == "add") {
        if (a.size() != 4) { std::fputs("usage: user add <name> <OWNER|USER|ADMIN>\n", stderr); return 2; }
        Role role;
        if (!parseRole(a[3], role)) { std::fprintf(stderr, "Error: role must be OWNER, USER or ADMIN.\n"); return 2; }
        User actor; const User* ap = nullptr;
        if (!userName.empty()) { if (!authenticate(core, userName, actor, rc)) return rc; ap = &actor; }
        std::string pw = fromEnvOrPrompt("FILEGUARD_NEW_PASSWORD", "New password for " + a[2] + ": ");
        if (!std::getenv("FILEGUARD_NEW_PASSWORD") && readSecret("Repeat password: ") != pw) { std::fprintf(stderr, "Error: passwords differ.\n"); return 1; }
        User created;
        st = core.users.registerUser(a[2], pw, role, ap, &created);
        if (!st.ok()) return fail(st);
        std::printf("User '%s' created with role %s.\n", created.username.c_str(), toString(created.role).c_str());
        return 0;
    }

    // ---- everything else requires authentication ----
    if (!authenticate(core, userName, me, rc)) return rc;

    if (cmd == "user" && a.size() >= 2) {
        if (a[1] == "list") {
            std::printf("%-4s %-20s %-7s %-9s %s\n", "ID", "USERNAME", "ROLE", "STATUS", "CREATED (UTC)");
            for (auto& u : core.users.list())
                std::printf("%-4lld %-20s %-7s %-9s %s\n", static_cast<long long>(u.id), u.username.c_str(), toString(u.role).c_str(), u.status.c_str(), u.createdAt.c_str());
            return 0;
        }
        if ((a[1] == "disable" || a[1] == "enable") && a.size() == 3) {
            st = core.users.setActive(me, a[2], a[1] == "enable");
            if (!st.ok()) return fail(st);
            std::printf("User '%s' %sd.\n", a[2].c_str(), a[1].c_str());
            return 0;
        }
    } else if (cmd == "register" && a.size() == 2) {
        FileRecord r;
        st = core.files.registerFile(me, a[1], r);
        if (!st.ok()) return fail(st);
        std::printf("File ID        : %s\nFilename       : %s\nSize           : %s\nOriginal SHA-256: %s\nOwner          : %s\nCreated (UTC)  : %s\nProtection     : AES-256-GCM, stored at %s\n",
                    r.uuid.c_str(), r.originalName.c_str(), human(r.originalSize).c_str(), r.originalHash.c_str(),
                    r.ownerName.c_str(), r.createdAt.c_str(), r.protectedPath.c_str());
        return 0;
    } else if (cmd == "list" && a.size() == 1) {
        std::printf("%-10s %-28s %-10s %-10s %s\n", "FILE ID", "NAME", "SIZE", "OWNER", "YOUR ACCESS");
        for (auto& f : core.files.listVisible(me)) {
            auto e = core.perms.effective(me, f);
            std::printf("%-10s %-28s %-10s %-10s %s\n", f.uuid.c_str(), f.originalName.c_str(), human(f.originalSize).c_str(),
                        f.ownerName.c_str(), e ? toString(*e).c_str() : "-");
        }
        return 0;
    } else if (cmd == "share" && (a.size() == 4 || a.size() == 5)) {
        Permission p;
        if (!parsePermission(a[3], p)) { std::fprintf(stderr, "Error: permission must be VIEW, READ or DOWNLOAD.\n"); return 2; }
        int days = 0;
        if (a.size() == 5) { char* e = nullptr; long v = std::strtol(a[4].c_str(), &e, 10); if (*e || v < 0 || v > 3650) { std::fprintf(stderr, "Error: days must be 0..3650.\n"); return 2; } days = static_cast<int>(v); }
        st = core.files.share(me, a[1], a[2], p, days);
        if (!st.ok()) return fail(st);
        std::printf("Shared %s with %s (%s%s).\n", a[1].c_str(), a[2].c_str(), toString(p).c_str(), days ? (", expires in " + std::to_string(days) + " days").c_str() : "");
        return 0;
    } else if (cmd == "revoke" && a.size() == 3) {
        st = core.files.revoke(me, a[1], a[2]);
        if (!st.ok()) return fail(st);
        std::printf("Revoked %s's access to %s.\n", a[2].c_str(), a[1].c_str());
        return 0;
    } else if (cmd == "open" && a.size() == 2) {
        Bytes content; FileRecord r;
        st = core.files.open(me, a[1], content, &r, [](const std::string& s) { std::fprintf(stderr, "%s\n", s.c_str()); });
        if (!st.ok()) return fail(st);
        std::printf("\xe2\x9c\x93 Integrity verified (SHA-256 %s)\n%s  (%s, owner %s)\n----------------------------------------\n",
                    r.originalHash.substr(0, 16).c_str(), r.originalName.c_str(), human(r.originalSize).c_str(), r.ownerName.c_str());
        if (looksLikeText(content)) {
            std::fwrite(content.data(), 1, content.size() > 65536 ? 65536 : content.size(), stdout);
            if (content.size() > 65536) std::printf("\n[... truncated, %s total]", human(content.size()).c_str());
            std::puts("");
        } else {
            std::printf("[binary content, %s - not printed. Use 'download' if you have DOWNLOAD permission.]\n", human(content.size()).c_str());
        }
        secureZero(content);
        return 0;
    } else if (cmd == "download" && a.size() == 3) {
        st = core.files.download(me, a[1], a[2]);
        if (!st.ok()) return fail(st);
        std::printf("\xe2\x9c\x93 Integrity verified. Decrypted copy written to %s (mode 0600).\n", a[2].c_str());
        return 0;
    } else if (cmd == "verify" && a.size() == 2) {
        st = core.files.verify(me, a[1]);
        if (!st.ok()) return fail(st);
        std::printf("\xe2\x9c\x93 Integrity verified\n");
        return 0;
    } else if (cmd == "export" && a.size() == 3) {
        st = core.files.exportPackage(me, a[1], a[2]);
        if (!st.ok()) return fail(st);
        std::printf("Protected package written to %s. Recipients still need an account and a grant.\n", a[2].c_str());
        return 0;
    } else if (cmd == "logs") {
        std::printf("%-19s  %-10s %-9s %-19s %-9s %s\n", "TIMESTAMP (UTC)", "USER", "FILE", "ACTION", "RESULT", "DETAILS");
        for (auto& e : core.audit.recent(me, parseCount(a, 1, 50)))
            std::printf("%-19s  %-10s %-9s %-19s %-9s %s\n", e.timestamp.c_str(), e.username.c_str(), e.fileUuid.c_str(), e.action.c_str(), e.result.c_str(), e.details.c_str());
        return 0;
    } else if (cmd == "alerts") {
        std::printf("%-19s  %-10s %-9s %-24s %-7s %s\n", "TIMESTAMP (UTC)", "USER", "FILE", "TYPE", "SEVERITY", "DETAILS");
        for (auto& e : core.security.recent(me, parseCount(a, 1, 50)))
            std::printf("%-19s  %-10s %-9s %-24s %-7s %s\n", e.timestamp.c_str(), e.username.c_str(), e.fileUuid.c_str(), e.type.c_str(), e.severity.c_str(), e.details.c_str());
        return 0;
    } else if (cmd == "driver" && a.size() == 2 && a[1] == "events") {
        if (me.role != Role::Admin) { std::fprintf(stderr, "Error: only ADMIN can drain driver events.\n"); return 3; }
        fg_event ev{}; int n = 0;
        while ((st = core.driver.readEvent(ev)).ok()) {
            std::printf("t=%llu %-24s FG-%u app_user=%u pid=%u uid=%u\n", static_cast<unsigned long long>(ev.timestamp),
                        DriverManager::typeName(ev.type), ev.file_num, ev.user_id, ev.pid, ev.uid);
            ++n;
        }
        if (st.code != Err::NotFound) return fail(st);
        std::printf("(%d event%s drained)\n", n, n == 1 ? "" : "s");
        return 0;
    }

    std::fputs(kUsage, stderr);
    return 2;
}
