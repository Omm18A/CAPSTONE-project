#include "core/AuditLogger.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>

namespace fg {

void AuditLogger::log(std::optional<int64_t> fileId, std::optional<int64_t> userId,
                      const std::string& action, const std::string& result, const std::string& details) {
    const std::string ts = nowUtc();
    const std::string det = sanitizeText(details, 300);

    auto st = db_.prepare("INSERT INTO access_logs(file_id,user_id,action,result,timestamp,details) VALUES(?1,?2,?3,?4,?5,?6)");
    if (fileId) st.bindInt(1, *fileId); else st.bindNull(1);
    if (userId) st.bindInt(2, *userId); else st.bindNull(2);
    st.bindText(3, action).bindText(4, result).bindText(5, ts).bindText(6, det);
    st.execute();

    // human-readable names for the flat file
    std::string uname = "-", fuuid = "-";
    if (userId) {
        auto q = db_.prepare("SELECT username FROM users WHERE id=?1");
        q.bindInt(1, *userId);
        if (q.next()) uname = q.text(0);
    }
    if (fileId) {
        auto q = db_.prepare("SELECT file_uuid FROM files WHERE id=?1");
        q.bindInt(1, *fileId);
        if (q.next()) fuuid = q.text(0);
    }
    std::string line = ts + "Z\t" + uname + "\t" + fuuid + "\t" + action + "\t" + result + "\t" + det + "\n";
    int fd = ::open(logPath_.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd >= 0) {
        ssize_t ignored = ::write(fd, line.data(), line.size());  // best effort; DB copy is authoritative
        (void)ignored;
        ::close(fd);
    }
}

namespace {
const char* kRecentSql =
    "SELECT a.id,a.timestamp,COALESCE(u.username,''),COALESCE(f.file_uuid,''),a.action,a.result,COALESCE(a.details,'') "
    "FROM access_logs a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN files f ON f.id=a.file_id "
    "WHERE ?1=1 OR f.owner_id=?2 OR a.user_id=?2 ORDER BY a.id DESC LIMIT ?3";
const char* kCountSql =
    "SELECT COUNT(*) FROM access_logs a LEFT JOIN files f ON f.id=a.file_id "
    "WHERE ?1=1 OR f.owner_id=?2 OR a.user_id=?2";
}  // namespace

std::vector<AuditEntry> AuditLogger::recent(const User& v, size_t limit) {
    std::vector<AuditEntry> out;
    auto st = db_.prepare(kRecentSql);
    st.bindInt(1, v.role == Role::Admin ? 1 : 0).bindInt(2, v.id).bindInt(3, static_cast<int64_t>(limit));
    while (st.next()) {
        AuditEntry e;
        e.id = st.integer(0); e.timestamp = st.text(1); e.username = st.text(2);
        e.fileUuid = st.text(3); e.action = st.text(4); e.result = st.text(5); e.details = st.text(6);
        out.push_back(std::move(e));
    }
    return out;
}

int64_t AuditLogger::count(const User& v) {
    auto st = db_.prepare(kCountSql);
    st.bindInt(1, v.role == Role::Admin ? 1 : 0).bindInt(2, v.id);
    return st.next() ? st.integer(0) : 0;
}

}  // namespace fg
