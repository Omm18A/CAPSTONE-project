// Defensive security tests: nothing here attacks a real system.
#include <sys/stat.h>
#include <unistd.h>

#include "TestUtil.h"
#include "core/FilePackage.h"
using namespace fg;

int main() {
    Fixture fx;
    auto& files = fx.core.files;

    // ---- SQL injection ----
    CHECK_CODE(fx.core.auth.login("' OR '1'='1' --", "x").status, Err::AuthFailed);
    CHECK_CODE(fx.core.auth.login("Omm' --", "anything123").status, Err::AuthFailed);
    CHECK_CODE(fx.core.users.registerUser("x'; DROP TABLE users;--", "validpass1", Role::User, nullptr), Err::InvalidInput);
    Bytes c;
    CHECK_CODE(files.open(fx.omm, "FG-1'; DROP TABLE files;--", c), Err::InvalidInput);
    CHECK_CODE(files.open(fx.omm, "FG-10001' OR '1'='1", c), Err::InvalidInput);
    CHECK(fx.core.users.count() == 4);                                   // tables intact

    // ---- path traversal ----
    CHECK_CODE(SecurityManager::checkUserPath("../../etc/passwd"), Err::InvalidInput);
    CHECK_CODE(SecurityManager::checkUserPath("/tmp/../etc/passwd"), Err::InvalidInput);
    CHECK_CODE(SecurityManager::checkUserPath("a/../../b"), Err::InvalidInput);
    CHECK_OK(SecurityManager::checkUserPath("/tmp/..hidden/file..txt"));  // ".." only as a whole component
    CHECK_CODE(SecurityManager::checkUserPath(std::string("a\0b", 3)), Err::InvalidInput);
    CHECK_CODE(SecurityManager::checkUserPath(std::string(5000, 'a')), Err::InvalidInput);  // oversized path
    FileRecord tmp;
    CHECK_CODE(files.registerFile(fx.omm, "../../../etc/passwd", tmp), Err::InvalidInput);
    CHECK_CODE(files.registerFile(fx.omm, fx.src.path + "/nope.txt", tmp), Err::NotFound);
    CHECK_CODE(files.registerFile(fx.omm, fx.core.config.keyPath(), tmp), Err::InvalidInput);          // data dir off-limits
    CHECK_CODE(files.registerFile(fx.omm, fx.src.path, tmp), Err::InvalidInput);                       // directory
    CHECK_CODE(files.registerFile(fx.omm, "/dev/zero", tmp), Err::InvalidInput);                       // special file
    CHECK_CODE(files.registerFile(fx.rahul, fx.srcFile("r.txt", "x"), tmp), Err::AccessDenied);        // USER role
    CHECK_CODE(files.registerFile(fx.omm, fx.srcFile("empty.txt", ""), tmp), Err::InvalidInput);

    FileRecord f = fx.registerDoc("classified\n");
    CHECK_OK(files.share(fx.omm, f.uuid, "Rahul", Permission::Download));
    CHECK_CODE(files.download(fx.rahul, f.uuid, "../../tmp/out.txt"), Err::InvalidInput);
    CHECK_CODE(files.download(fx.rahul, f.uuid, fx.core.config.baseDir() + "/stolen.txt"), Err::InvalidInput);
    CHECK_CODE(files.download(fx.rahul, f.uuid, fx.src.path + "/no/such/dir/o.txt"), Err::NotFound);
    std::string existing = fx.srcFile("exists.txt", "precious");
    CHECK_CODE(files.download(fx.rahul, f.uuid, existing), Err::InvalidInput);                         // never overwrite
    CHECK(slurp(existing) == "precious");
    std::string link = fx.src.path + "/link.txt";
    CHECK(symlink("/tmp/fg_target_should_not_exist", link.c_str()) == 0);
    CHECK_CODE(files.download(fx.rahul, f.uuid, link), Err::InvalidInput);                             // O_EXCL|O_NOFOLLOW
    CHECK(!LinuxSystemManager::pathExists("/tmp/fg_target_should_not_exist"));
    std::string okDest = fx.src.path + "/dl.txt";
    CHECK_OK(files.download(fx.rahul, f.uuid, okDest));
    CHECK(slurp(okDest) == "classified\n");
    struct stat st; CHECK(stat(okDest.c_str(), &st) == 0 && (st.st_mode & 077) == 0);                  // 0600

    // ---- oversized input ----
    CHECK_CODE(fx.core.users.registerUser("Longpw", std::string(10000, 'p'), Role::User, nullptr), Err::InvalidInput);
    CHECK_CODE(fx.core.users.registerUser(std::string(500, 'u'), "validpass1", Role::User, nullptr), Err::InvalidInput);
    CHECK_CODE(files.open(fx.omm, std::string(100000, 'F'), c), Err::InvalidInput);
    CHECK(sanitizeText(std::string(10000, 'x'), 200).size() == 200);
    CHECK(sanitizeText("a\nb\tc\x01").find('\n') == std::string::npos);                                // log injection

    // ---- invalid file id / permission ----
    CHECK_CODE(files.open(fx.omm, "FG-abc", c), Err::InvalidInput);
    CHECK_CODE(files.open(fx.omm, "", c), Err::InvalidInput);
    CHECK_CODE(files.open(fx.omm, "FG-99999", c), Err::AccessDenied);                                  // unknown id looks like denied
    CHECK_CODE(files.share(fx.omm, f.uuid, "Nobody", Permission::Read), Err::NotFound);
    Permission pp; CHECK(!parsePermission("", pp) && !parsePermission("read", pp) && !parsePermission("ADMIN", pp));

    // ---- unauthorised access is denied, logged, and raises an alert ----
    int64_t before = fx.countEvents("UNAUTHORIZED_ACCESS");
    CHECK_CODE(files.open(fx.priya, f.uuid, c), Err::AccessDenied);
    CHECK(c.empty());
    CHECK(fx.countEvents("UNAUTHORIZED_ACCESS") == before + 1);
    CHECK(fx.countAction("ACCESS_DENIED", "DENIED") >= 1);
    CHECK_CODE(files.open(fx.rahul, f.uuid, c), Err::Ok);                                              // Rahul has DOWNLOAD (implies READ)
    CHECK_CODE(files.exportPackage(fx.rahul, f.uuid, fx.src.path + "/x.fguard"), Err::AccessDenied);   // only owner exports
    CHECK_CODE(files.verify(fx.priya, f.uuid), Err::AccessDenied);

    // ---- tampered protected file ----
    std::string path = fx.core.files.findByUuid(f.uuid)->protectedPath;
    { Bytes pkg; LinuxSystemManager::readFile(path, 1 << 20, pkg); pkg[pkg.size() - 20] ^= 0x01;
      std::ofstream o(path, std::ios::binary | std::ios::trunc); o.write(reinterpret_cast<char*>(pkg.data()), static_cast<std::streamsize>(pkg.size())); }
    CHECK_CODE(files.open(fx.omm, f.uuid, c), Err::IntegrityFailure);
    CHECK(c.empty());                                                                                  // nothing decrypted
    CHECK_CODE(files.verify(fx.omm, f.uuid), Err::IntegrityFailure);
    CHECK_CODE(files.download(fx.rahul, f.uuid, fx.src.path + "/t.txt"), Err::IntegrityFailure);
    CHECK_CODE(files.exportPackage(fx.omm, f.uuid, fx.src.path + "/t.fguard"), Err::IntegrityFailure);
    CHECK(fx.countAction("INTEGRITY_FAILURE") >= 4 && fx.countEvents("INTEGRITY_FAILURE") >= 4);
    ::unlink(path.c_str());                                                                            // deleted file
    CHECK_CODE(files.open(fx.omm, f.uuid, c), Err::IntegrityFailure);

    // ---- malformed .fguard files ----
    FileRecord g = fx.registerDoc("second doc\n", "g.txt");
    std::string good = fx.src.path + "/good.fguard";
    CHECK_OK(files.exportPackage(fx.omm, g.uuid, good));
    Bytes pkg; CHECK_OK(LinuxSystemManager::readFile(good, 1 << 20, pkg));
    PackageHeader h; size_t hl = 0;
    CHECK_OK(FilePackage::parse(pkg, h, hl));
    CHECK(h.fileUuid == g.uuid && h.originalName == "g.txt" && h.originalSize == 11);
    auto mutate = [&](const char* name, std::function<void(Bytes&)> fn) {
        Bytes b = pkg; fn(b);
        std::string p = fx.src.path + "/" + name;
        { std::ofstream o(p, std::ios::binary); o.write(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(b.size())); }
        PackageHeader hh; size_t l = 0;
        CHECK_CODE(FilePackage::parse(b, hh, l), Err::Corrupted);
        CHECK(!files.open(fx.omm, p, c).ok());                          // never crashes, never succeeds
    };
    mutate("trunc.fguard", [](Bytes& b) { b.resize(b.size() / 2); });
    mutate("tiny.fguard", [](Bytes& b) { b.resize(10); });
    mutate("magic.fguard", [](Bytes& b) { b[0] = 'X'; });
    mutate("ver.fguard", [](Bytes& b) { b[8] = 9; });
    mutate("size.fguard", [](Bytes& b) { b[16] = 0xff; b[23] = 0x7f; });
    mutate("hlen.fguard", [](Bytes& b) { b[10] = 0xff; b[11] = 0xff; });
    mutate("trail.fguard", [](Bytes& b) { b.push_back(0); });
    mutate("empty.fguard", [](Bytes& b) { b.clear(); });
    mutate("uuid.fguard", [](Bytes& b) { b[74] = 'X'; });
    CHECK_CODE(files.open(fx.omm, fx.src.path + "/missing.fguard", c), Err::IoFailure);
    CHECK(fx.countEvents("CORRUPTED_PACKAGE") >= 5);
    // bit-flip in an exported copy -> hash mismatch against registry
    { Bytes b = pkg; b[b.size() - 3] ^= 1; std::string p = fx.src.path + "/flip.fguard";
      std::ofstream o(p, std::ios::binary); o.write(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(b.size())); o.close();
      CHECK_CODE(files.open(fx.omm, p, c), Err::IntegrityFailure); }

    // ---- master key / data directory permissions ----
    CHECK(stat(fx.core.config.keyPath().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
    CHECK(stat(fx.core.config.databasePath().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
    CHECK(stat(fx.core.config.protectedDir().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
    chmod(fx.core.config.keyPath().c_str(), 0644);
    ConfigurationManager cm(fx.home.path);
    CHECK_CODE(cm.prepare(), Err::PermissionDenied);                                                   // refuses unsafe key perms
    return finish("test_security");
}
