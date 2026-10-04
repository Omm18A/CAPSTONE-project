#include "core/FileManager.h"

#include <libgen.h>

#include <cstring>

#include "core/EncryptionManager.h"
#include "core/FilePackage.h"
#include "core/HashManager.h"
#include "core/LinuxSystemManager.h"

namespace fg {

namespace {
const char* kSelect =
    "SELECT f.id,f.file_uuid,f.owner_id,u.username,f.original_name,f.protected_path,f.original_size,"
    "f.original_hash,f.protected_hash,f.created_at,f.status,f.wrapped_key "
    "FROM files f JOIN users u ON u.id=f.owner_id ";

FileRecord rowToRecord(DatabaseManager::Stmt& s) {
    FileRecord r;
    r.id = s.integer(0); r.uuid = s.text(1); r.ownerId = s.integer(2); r.ownerName = s.text(3);
    r.originalName = s.text(4); r.protectedPath = s.text(5);
    r.originalSize = static_cast<uint64_t>(s.integer(6));
    r.originalHash = s.text(7); r.protectedHash = s.text(8); r.createdAt = s.text(9);
    r.status = s.text(10); r.wrappedKey = s.blob(11);
    return r;
}

bool looksLikePath(const std::string& s) {
    return s.find('/') != std::string::npos || (s.size() > 7 && s.compare(s.size() - 7, 7, ".fguard") == 0);
}

std::string baseName(const std::string& path) {
    size_t p = path.find_last_of('/');
    return p == std::string::npos ? path : path.substr(p + 1);
}
}  // namespace

std::optional<FileRecord> FileManager::findByUuid(const std::string& uuid) {
    if (!isValidFileId(uuid)) return std::nullopt;
    std::string sql = std::string(kSelect) + "WHERE f.file_uuid=?1";
    auto st = db_.prepare(sql.c_str());
    st.bindText(1, uuid);
    if (st.next()) return rowToRecord(st);
    return std::nullopt;
}

std::vector<FileRecord> FileManager::listVisible(const User& u) {
    std::vector<FileRecord> out;
    std::string sql = std::string(kSelect) +
        "WHERE f.status='ACTIVE' AND (f.owner_id=?1 OR EXISTS (SELECT 1 FROM permissions p WHERE p.file_id=f.id "
        "AND p.user_id=?1 AND (p.expires_at IS NULL OR p.expires_at>datetime('now')))) ORDER BY f.id";
    auto st = db_.prepare(sql.c_str());
    st.bindInt(1, u.id);
    while (st.next()) out.push_back(rowToRecord(st));
    return out;
}

int64_t FileManager::countOwned(const User& u) {
    auto st = db_.prepare("SELECT COUNT(*) FROM files WHERE owner_id=?1 AND status='ACTIVE'");
    st.bindInt(1, u.id);
    return st.next() ? st.integer(0) : 0;
}

int64_t FileManager::countSharedWith(const User& u) {
    auto st = db_.prepare("SELECT COUNT(*) FROM permissions WHERE user_id=?1 AND (expires_at IS NULL OR expires_at>datetime('now'))");
    st.bindInt(1, u.id);
    return st.next() ? st.integer(0) : 0;
}

// ---------------------------------------------------------------------------
Status FileManager::registerFile(const User& owner, const std::string& srcPath, FileRecord& out) {
    if (owner.status != "ACTIVE" || (owner.role != Role::Owner && owner.role != Role::Admin)) {
        audit_.log(std::nullopt, owner.id, "ACCESS_DENIED", "DENIED", "file registration requires OWNER role");
        return Status::fail(Err::AccessDenied, "Only users with the OWNER role can register files.");
    }
    Status s = SecurityManager::checkUserPath(srcPath);
    if (!s.ok()) return s;
    const std::string canon = LinuxSystemManager::canonicalize(srcPath);
    if (canon.empty()) return Status::fail(Err::NotFound, "File not found: " + srcPath);
    if (LinuxSystemManager::isUnder(canon, cfg_.canonicalBase()))
        return Status::fail(Err::InvalidInput, "Refusing to register a file from FileGuard's own data directory.");
    const std::string name = baseName(canon);
    if (!SecurityManager::isSafeFileName(name)) return Status::fail(Err::InvalidInput, "Unsupported file name.");

    Bytes plain;
    s = LinuxSystemManager::readFile(canon, ConfigurationManager::kMaxFileSize, plain);
    if (!s.ok()) return s;
    if (plain.empty()) return Status::fail(Err::InvalidInput, "Refusing to protect an empty file.");

    PackageHeader h;
    h.originalSize = plain.size();
    h.ownerId = static_cast<uint32_t>(owner.id);
    h.originalName = name;
    h.originalHash = HashManager::sha256(plain);

    Bytes dek, nonce;
    if (!(s = EncryptionManager::randomBytes(EncryptionManager::kKeyLen, dek)).ok() ||
        !(s = EncryptionManager::randomBytes(EncryptionManager::kNonceLen, nonce)).ok()) {
        secureZero(plain); secureZero(dek); return s;
    }
    h.nonce = nonce;

    DatabaseManager::Transaction tx(db_);
    if (!tx.active()) { secureZero(plain); secureZero(dek); return Status::fail(Err::DbFailure, "Cannot start transaction."); }

    int64_t nextId = 1;
    { auto q = db_.prepare("SELECT COALESCE(MAX(id),0)+1 FROM files"); if (q.next()) nextId = q.integer(0); }
    h.fileUuid = "FG-" + std::to_string(10000 + nextId);

    Bytes headerBytes, ct, tag, pkg, wrapped;
    s = FilePackage::serializeHeader(h, headerBytes);
    if (s.ok()) s = EncryptionManager::aesGcmEncrypt(dek, nonce, headerBytes, plain, ct, tag);
    if (s.ok()) s = FilePackage::build(h, ct, tag, pkg);
    if (s.ok()) s = EncryptionManager::wrapKey(cfg_.masterKey(), h.fileUuid, dek, wrapped);
    secureZero(plain); secureZero(dek);
    if (!s.ok()) return s;

    const std::string path = cfg_.protectedDir() + "/" + h.fileUuid + ".fguard";   // built from validated id only
    s = LinuxSystemManager::writeFileAtomic(path, pkg, 0600);
    if (!s.ok()) return s;

    auto ins = db_.prepare("INSERT INTO files(id,file_uuid,owner_id,original_name,protected_path,original_size,"
                           "original_hash,protected_hash,wrapped_key,created_at,status) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'ACTIVE')");
    ins.bindInt(1, nextId).bindText(2, h.fileUuid).bindInt(3, owner.id).bindText(4, name).bindText(5, path)
       .bindInt(6, static_cast<int64_t>(h.originalSize)).bindText(7, hexEncode(h.originalHash))
       .bindText(8, HashManager::sha256Hex(pkg)).bindBlob(9, wrapped).bindText(10, nowUtc());
    if (!ins.execute() || !tx.commit()) {
        std::string err = db_.lastError();
        LinuxSystemManager::removeFile(path);
        return Status::fail(Err::DbFailure, "Could not record file: " + err);
    }

    auto rec = findByUuid(h.fileUuid);
    if (!rec) return Status::fail(Err::DbFailure, "File vanished after registration.");
    out = *rec;
    audit_.log(rec->id, owner.id, "FILE_REGISTERED", "SUCCESS", "name=" + name + " size=" + std::to_string(rec->originalSize) + " sha256=" + rec->originalHash);
    audit_.log(rec->id, owner.id, "FILE_PROTECTED", "SUCCESS", "AES-256-GCM package " + h.fileUuid + ".fguard");
    (void)drv_.sendEvent(FG_EVT_PROTECTED_FILE_CREATED, fileNumber(rec->uuid), static_cast<uint32_t>(owner.id));
    return Status::success();
}

// ---------------------------------------------------------------------------
void FileManager::integrityAlert(const FileRecord& f, const User& u, const std::string& why) {
    audit_.log(f.id, u.id, "INTEGRITY_FAILURE", "FAILURE", why);
    sec_.raise(f.id, u.id, "INTEGRITY_FAILURE", "HIGH", why, FG_EVT_INTEGRITY_FAILURE, fileNumber(f.uuid));
}

Status FileManager::pipeline(const User& u, const std::string& idOrPath, Permission need,
                             const std::string& action, const std::string& successAction,
                             Bytes* content, FileRecord* recOut, const Progress& progress) {
    if (content) secureZero(*content);   // never leave stale plaintext in the caller's buffer on failure
    auto say = [&](const char* m) { if (progress) progress(m); };
    say("Authenticating...");
    if (u.status != "ACTIVE") return Status::fail(Err::AccessDenied, "Account is disabled.");

    Bytes pkg;
    bool havePkg = false;
    std::string uuid = idOrPath;

    if (looksLikePath(idOrPath)) {                       // a .fguard file handed to us
        Status s = SecurityManager::checkUserPath(idOrPath);
        if (!s.ok()) return s;
        s = LinuxSystemManager::readFile(idOrPath, ConfigurationManager::kMaxPackageSize, pkg);
        if (!s.ok()) return s;
        PackageHeader ph; size_t hl = 0;
        s = FilePackage::parse(pkg, ph, hl);
        if (!s.ok()) {
            audit_.log(std::nullopt, u.id, "INTEGRITY_CHECK", "FAILURE", "malformed .fguard file presented");
            sec_.raise(std::nullopt, u.id, "CORRUPTED_PACKAGE", "MEDIUM", s.message);
            return s;
        }
        uuid = ph.fileUuid;
        havePkg = true;
    }

    if (!isValidFileId(uuid)) {
        audit_.log(std::nullopt, u.id, "ACCESS_DENIED", "DENIED", "invalid file id");
        return Status::fail(Err::InvalidInput, "Invalid File ID (expected FG-<digits>).");
    }

    say("Checking permissions...");
    auto fo = findByUuid(uuid);
    if (!fo || fo->status != "ACTIVE" || !perms_.check(u, *fo, need)) {
        const std::string det = "attempted " + action + " (needs " + toString(need) + ") on " + uuid;
        audit_.log(fo ? std::optional<int64_t>(fo->id) : std::nullopt, u.id, "ACCESS_DENIED", "DENIED", det);
        sec_.raise(fo ? std::optional<int64_t>(fo->id) : std::nullopt, u.id, "UNAUTHORIZED_ACCESS", "MEDIUM", det,
                   FG_EVT_UNAUTHORIZED_ACCESS, fileNumber(uuid));
        return Status::fail(Err::AccessDenied, "Access denied.");
    }
    const FileRecord& f = *fo;

    say("Verifying integrity...");
    if (!havePkg) {
        Status s = LinuxSystemManager::readFile(f.protectedPath, ConfigurationManager::kMaxPackageSize, pkg);
        if (!s.ok()) {
            integrityAlert(f, u, "protected file missing or unreadable: " + s.message);
            return Status::fail(Err::IntegrityFailure, "Integrity violation: the protected file is missing or unreadable.");
        }
    }
    if (HashManager::sha256Hex(pkg) != f.protectedHash) {
        integrityAlert(f, u, "protected package hash mismatch (file modified)");
        return Status::fail(Err::IntegrityFailure, "Integrity violation detected: the protected file was modified.");
    }
    PackageHeader h; size_t hl = 0;
    Status s = FilePackage::parse(pkg, h, hl);
    if (!s.ok() || h.fileUuid != f.uuid || h.ownerId != static_cast<uint32_t>(f.ownerId) || h.originalSize != f.originalSize) {
        integrityAlert(f, u, "package metadata does not match registry");
        return Status::fail(Err::Corrupted, "Corrupted .fguard file: metadata does not match the registry.");
    }

    say("Decrypting content...");
    Bytes dek, plain;
    s = EncryptionManager::unwrapKey(cfg_.masterKey(), f.uuid, f.wrappedKey, dek);
    if (!s.ok()) { integrityAlert(f, u, "key unwrap failed"); return Status::fail(Err::CryptoFailure, "Cannot unlock file key."); }
    Bytes aad(pkg.begin(), pkg.begin() + static_cast<std::ptrdiff_t>(hl));
    Bytes ct(pkg.begin() + static_cast<std::ptrdiff_t>(hl), pkg.end() - static_cast<std::ptrdiff_t>(FilePackage::kTagLen));
    Bytes tag(pkg.end() - static_cast<std::ptrdiff_t>(FilePackage::kTagLen), pkg.end());
    s = EncryptionManager::aesGcmDecrypt(dek, h.nonce, aad, ct, tag, plain);
    secureZero(dek);
    if (!s.ok()) { integrityAlert(f, u, "authenticated decryption failed"); return Status::fail(Err::CryptoFailure, "Decryption failed: " + s.message); }
    if (hexEncode(HashManager::sha256(plain)) != f.originalHash) {
        secureZero(plain);
        integrityAlert(f, u, "plaintext SHA-256 differs from registered original hash");
        return Status::fail(Err::IntegrityFailure, "Integrity violation detected: content hash mismatch.");
    }

    audit_.log(f.id, u.id, "INTEGRITY_CHECK", "SUCCESS", "sha256 verified");
    if (!successAction.empty()) audit_.log(f.id, u.id, successAction, "SUCCESS", "");
    if (action == "OPEN") (void)drv_.sendEvent(FG_EVT_PROTECTED_FILE_OPEN, fileNumber(f.uuid), static_cast<uint32_t>(u.id));

    if (recOut) *recOut = f;
    if (content) *content = std::move(plain); else secureZero(plain);
    return Status::success();
}

Status FileManager::open(const User& u, const std::string& idOrPath, Bytes& content, FileRecord* rec, const Progress& p) {
    return pipeline(u, idOrPath, Permission::Read, "OPEN", "FILE_OPENED", &content, rec, p);
}

Status FileManager::verify(const User& u, const std::string& idOrPath) {
    return pipeline(u, idOrPath, Permission::View, "VERIFY", "", nullptr, nullptr, {});
}

Status FileManager::checkDestination(const std::string& dest) {
    Status s = SecurityManager::checkUserPath(dest);
    if (!s.ok()) return s;
    std::string dir = dest;
    std::vector<char> buf(dir.begin(), dir.end()); buf.push_back('\0');
    std::string parent = ::dirname(buf.data());
    std::string canon = LinuxSystemManager::canonicalize(parent);
    if (canon.empty()) return Status::fail(Err::NotFound, "Destination directory does not exist: " + parent);
    if (LinuxSystemManager::isUnder(canon, cfg_.canonicalBase()))
        return Status::fail(Err::InvalidInput, "Destination must not be inside FileGuard's data directory.");
    return Status::success();
}

Status FileManager::download(const User& u, const std::string& idOrPath, const std::string& dest) {
    Status s = checkDestination(dest);
    if (!s.ok()) return s;
    Bytes content; FileRecord rec;
    s = pipeline(u, idOrPath, Permission::Download, "DOWNLOAD", "", &content, &rec, {});
    if (!s.ok()) return s;
    s = LinuxSystemManager::writeFileExclusive(dest, content, 0600);
    secureZero(content);
    if (!s.ok()) { audit_.log(rec.id, u.id, "FILE_DOWNLOAD", "FAILURE", s.message); return s; }
    audit_.log(rec.id, u.id, "FILE_DOWNLOAD", "SUCCESS", "decrypted copy written");
    return Status::success();
}

Status FileManager::exportPackage(const User& owner, const std::string& id, const std::string& dest) {
    Status s = checkDestination(dest);
    if (!s.ok()) return s;
    auto f = findByUuid(id);
    if (!f || f->ownerId != owner.id || owner.status != "ACTIVE") {
        audit_.log(f ? std::optional<int64_t>(f->id) : std::nullopt, owner.id, "ACCESS_DENIED", "DENIED", "export attempted on " + id);
        return Status::fail(Err::AccessDenied, "Access denied (only the owner can export a package).");
    }
    Bytes pkg;
    s = LinuxSystemManager::readFile(f->protectedPath, ConfigurationManager::kMaxPackageSize, pkg);
    if (!s.ok() || HashManager::sha256Hex(pkg) != f->protectedHash) {
        integrityAlert(*f, owner, "refusing to export: stored package failed integrity check");
        return Status::fail(Err::IntegrityFailure, "Integrity violation detected: stored package was modified.");
    }
    s = LinuxSystemManager::writeFileExclusive(dest, pkg, 0600);
    if (!s.ok()) return s;
    audit_.log(f->id, owner.id, "PACKAGE_EXPORTED", "SUCCESS", "copy for distribution written");
    return Status::success();
}

Status FileManager::share(const User& owner, const std::string& id, const std::string& target, Permission p, int days) {
    auto f = findByUuid(id);
    auto t = users_.findByName(target);
    if (!f) { audit_.log(std::nullopt, owner.id, "ACCESS_DENIED", "DENIED", "share on unknown file " + sanitizeText(id, 20)); return Status::fail(Err::AccessDenied, "Access denied."); }
    if (!t) return Status::fail(Err::NotFound, "No such user: " + target);
    return perms_.grant(owner, *f, *t, p, days);
}

Status FileManager::revoke(const User& actor, const std::string& id, const std::string& target) {
    auto f = findByUuid(id);
    auto t = users_.findByName(target);
    if (!f) { audit_.log(std::nullopt, actor.id, "ACCESS_DENIED", "DENIED", "revoke on unknown file " + sanitizeText(id, 20)); return Status::fail(Err::AccessDenied, "Access denied."); }
    if (!t) return Status::fail(Err::NotFound, "No such user: " + target);
    return perms_.revoke(actor, *f, *t);
}

}  // namespace fg
