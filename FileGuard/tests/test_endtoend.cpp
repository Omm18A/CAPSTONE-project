// Full demonstration scenario from the project brief (docs/testing.md).
#include "TestUtil.h"
using namespace fg;

int main() {
    Fixture fx;
    auto login = [&](const char* n, const char* p) { auto r = fx.core.auth.login(n, p); CHECK_OK(r.status); return *r.user; };

    User omm = login("Omm", "ommpass123");
    FileRecord f;
    const std::string secret = "CONFIDENTIAL BOARD MINUTES\nBudget: 4.2M\n";
    CHECK_OK(fx.core.files.registerFile(omm, fx.srcFile("confidential.pdf", secret), f));       // Register + Protect
    CHECK(f.uuid == "FG-10001" && f.originalName == "confidential.pdf" && f.originalHash.size() == 64);

    // ciphertext on disk must not contain the plaintext
    CHECK(slurp(f.protectedPath).find("BOARD MINUTES") == std::string::npos);
    CHECK(slurp(f.protectedPath).find("FGUARD") == 0);

    CHECK_OK(fx.core.files.share(omm, f.uuid, "Rahul", Permission::Read));                        // Share
    std::string pkg = fx.src.path + "/confidential.fguard";
    CHECK_OK(fx.core.files.exportPackage(omm, f.uuid, pkg));

    User rahul = login("Rahul", "rahulpass1");                                                    // Recipient logs in
    Bytes content; FileRecord rec; std::vector<std::string> steps;
    CHECK_OK(fx.core.files.open(rahul, f.uuid, content, &rec, [&](const std::string& s) { steps.push_back(s); }));
    CHECK(std::string(content.begin(), content.end()) == secret);                                 // Open: exact plaintext
    CHECK(steps.size() == 4 && steps[0] == "Authenticating..." && steps[3] == "Decrypting content...");
    CHECK_OK(fx.core.files.open(rahul, pkg, content));                                            // open via .fguard path too
    CHECK(fx.countAction("FILE_OPENED", "SUCCESS") == 2);
    CHECK(fx.countAction("INTEGRITY_CHECK", "SUCCESS") >= 2);

    CHECK_CODE(fx.core.files.download(rahul, f.uuid, fx.src.path + "/d.pdf"), Err::AccessDenied); // READ != DOWNLOAD
    CHECK_OK(fx.core.files.share(omm, f.uuid, "Rahul", Permission::Download));
    CHECK_OK(fx.core.files.download(rahul, f.uuid, fx.src.path + "/d.pdf"));
    CHECK(slurp(fx.src.path + "/d.pdf") == secret);
    CHECK(fx.countAction("FILE_DOWNLOAD", "SUCCESS") == 1);

    User priya = login("Priya", "priyapass1");                                                    // Never shared
    CHECK_CODE(fx.core.files.open(priya, f.uuid, content), Err::AccessDenied);
    CHECK_CODE(fx.core.files.open(priya, pkg, content), Err::AccessDenied);                       // even with the file in hand

    CHECK_OK(fx.core.files.revoke(omm, f.uuid, "Rahul"));                                         // Revoke
    CHECK_CODE(fx.core.files.open(rahul, f.uuid, content), Err::AccessDenied);                    // -> DENIED
    CHECK_CODE(fx.core.files.open(rahul, pkg, content), Err::AccessDenied);
    CHECK(fx.countAction("FILE_REVOKED", "SUCCESS") == 1);
    CHECK(fx.countAction("ACCESS_DENIED", "DENIED") >= 3);

    // Tamper demonstration
    CHECK_OK(fx.core.files.share(omm, f.uuid, "Rahul", Permission::Read));
    { Bytes b; LinuxSystemManager::readFile(f.protectedPath, 1 << 20, b); b[b.size() - 1] ^= 0xff;
      std::ofstream o(f.protectedPath, std::ios::binary | std::ios::trunc); o.write(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(b.size())); }
    CHECK_CODE(fx.core.files.open(rahul, f.uuid, content), Err::IntegrityFailure);
    CHECK(content.empty());
    CHECK(fx.countEvents("INTEGRITY_FAILURE") >= 1);

    // Views: owner sees everything about own file; unrelated user sees none of it
    auto ownerLog = fx.core.audit.recent(omm, 100);
    auto priyaAlerts = fx.core.security.recent(priya, 100);
    CHECK(!ownerLog.empty());
    for (auto& e : priyaAlerts) CHECK(e.username == "Priya");
    CHECK(fx.core.security.count(fx.admin) >= 4);                                                 // admin inspects all alerts
    CHECK(fx.core.audit.count(fx.admin) >= fx.core.audit.count(omm));

    // audit log never contains secrets
    std::string logTxt = slurp(fx.core.config.auditLogPath());
    CHECK(logTxt.find("ommpass123") == std::string::npos && logTxt.find("rahulpass1") == std::string::npos);
    CHECK(logTxt.find("BOARD MINUTES") == std::string::npos);

    // second store opening the same files from disk (persistence)
    FileGuardCore again(fx.home.path, "/nonexistent");
    CHECK_OK(again.init());
    CHECK(again.users.count() == 4 && again.files.findByUuid("FG-10001").has_value());
    return finish("test_endtoend");
}
