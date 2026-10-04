#include "core/SecurityManager.h"

namespace fg {

void SecurityManager::raise(std::optional<int64_t> fileId, std::optional<int64_t> userId,
                            const std::string& type, const std::string& severity,
                            const std::string& details, uint32_t driverEvent, uint32_t fileNum) {
    auto st = db_.prepare("INSERT INTO security_events(file_id,user_id,event_type,severity,timestamp,details) VALUES(?1,?2,?3,?4,?5,?6)");
    if (fileId) st.bindInt(1, *fileId); else st.bindNull(1);
    if (userId) st.bindInt(2, *userId); else st.bindNull(2);
    st.bindText(3, type).bindText(4, severity).bindText(5, nowUtc()).bindText(6, sanitizeText(details, 300));
    st.execute();
    audit_.log(fileId, userId, "SECURITY_EVENT", "ALERT", type + ": " + details);
    if (driverEvent != 0) (void)driver_.sendEvent(driverEvent, fileNum, userId ? static_cast<uint32_t>(*userId) : 0);
}

namespace {
const char* kRecentSql =
    "SELECT s.id,s.timestamp,COALESCE(u.username,''),COALESCE(f.file_uuid,''),s.event_type,s.severity,COALESCE(s.details,'') "
    "FROM security_events s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN files f ON f.id=s.file_id "
    "WHERE ?1=1 OR f.owner_id=?2 OR s.user_id=?2 ORDER BY s.id DESC LIMIT ?3";
const char* kCountSql =
    "SELECT COUNT(*) FROM security_events s LEFT JOIN files f ON f.id=s.file_id "
    "WHERE ?1=1 OR f.owner_id=?2 OR s.user_id=?2";
}  // namespace

std::vector<SecurityEvent> SecurityManager::recent(const User& v, size_t limit) {
    std::vector<SecurityEvent> out;
    auto st = db_.prepare(kRecentSql);
    st.bindInt(1, v.role == Role::Admin ? 1 : 0).bindInt(2, v.id).bindInt(3, static_cast<int64_t>(limit));
    while (st.next()) {
        SecurityEvent e;
        e.id = st.integer(0); e.timestamp = st.text(1); e.username = st.text(2); e.fileUuid = st.text(3);
        e.type = st.text(4); e.severity = st.text(5); e.details = st.text(6);
        out.push_back(std::move(e));
    }
    return out;
}

int64_t SecurityManager::count(const User& v) {
    auto st = db_.prepare(kCountSql);
    st.bindInt(1, v.role == Role::Admin ? 1 : 0).bindInt(2, v.id);
    return st.next() ? st.integer(0) : 0;
}

Status SecurityManager::checkUserPath(const std::string& path) {
    if (path.empty()) return Status::fail(Err::InvalidInput, "Path is empty.");
    if (path.size() >= 4096) return Status::fail(Err::InvalidInput, "Path is too long.");
    for (char c : path) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) return Status::fail(Err::InvalidInput, "Path contains control characters.");
    }
    size_t i = 0;
    while (i <= path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        if (path.compare(i, j - i, "..") == 0 && j - i == 2)
            return Status::fail(Err::InvalidInput, "Path contains '..' (path traversal is not allowed). Use an absolute path.");
        i = j + 1;
    }
    return Status::success();
}

bool SecurityManager::isSafeFileName(const std::string& n) {
    if (n.empty() || n.size() > 255 || n == "." || n == "..") return false;
    for (char c : n) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f || c == '/') return false;
    }
    return true;
}

}  // namespace fg
