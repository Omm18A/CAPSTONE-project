#include "core/DriverManager.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace fg {

static_assert(sizeof(fg_event) == 32, "fg_event ABI mismatch with driver");
static_assert(sizeof(fg_stats) == 64, "fg_stats ABI mismatch with driver");

DriverManager::~DriverManager() { close(); }

void DriverManager::close() { if (fd_ >= 0) { ::close(fd_); fd_ = -1; } }

Status DriverManager::open() {
    if (fd_ >= 0) return Status::success();
    fd_ = ::open(path_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd_ < 0) {
        int e = errno;
        if (e == ENOENT) return Status::fail(Err::DriverUnavailable, "Driver not loaded (" + path_ + " does not exist). See docs/driver.md.");
        if (e == EACCES) return Status::fail(Err::PermissionDenied, "No permission to open " + path_ + " (are you in the 'fileguard' group? run scripts/install_driver.sh).");
        return Status::fail(Err::DriverUnavailable, "Cannot open " + path_ + ": " + std::strerror(e));
    }
    return Status::success();
}

Status DriverManager::ensureOpen() { return fd_ >= 0 ? Status::success() : open(); }

Status DriverManager::sendEvent(uint32_t type, uint32_t fileNum, uint32_t userId) {
    Status s = ensureOpen();
    if (!s.ok()) return s;
    fg_event ev;
    std::memset(&ev, 0, sizeof ev);
    ev.type = type; ev.file_num = fileNum; ev.user_id = userId;
    ssize_t w;
    do { w = ::write(fd_, &ev, sizeof ev); } while (w < 0 && errno == EINTR);
    if (w != static_cast<ssize_t>(sizeof ev)) {
        int e = errno;
        if (e == ENOBUFS) return Status::fail(Err::DriverUnavailable, "Driver event queue is full (event dropped).");
        if (e == EINVAL) return Status::fail(Err::InvalidInput, "Driver rejected the event as invalid.");
        close();  // stale descriptor (e.g. module reloaded): reopen next time
        return Status::fail(Err::DriverUnavailable, std::string("Driver write failed: ") + std::strerror(e));
    }
    return Status::success();
}

Status DriverManager::readEvent(fg_event& ev) {
    Status s = ensureOpen();
    if (!s.ok()) return s;
    ssize_t r;
    do { r = ::read(fd_, &ev, sizeof ev); } while (r < 0 && errno == EINTR);
    if (r == static_cast<ssize_t>(sizeof ev)) return Status::success();
    if (r < 0 && errno == EAGAIN) return Status::fail(Err::NotFound, "No pending events.");
    return Status::fail(Err::DriverUnavailable, std::string("Driver read failed: ") + std::strerror(errno));
}

Status DriverManager::getStats(fg_stats& st) {
    Status s = ensureOpen();
    if (!s.ok()) return s;
    std::memset(&st, 0, sizeof st);
    if (::ioctl(fd_, FG_IOC_GET_STATS, &st) != 0)
        return Status::fail(Err::DriverUnavailable, std::string("ioctl(GET_STATS) failed: ") + std::strerror(errno));
    return Status::success();
}

Status DriverManager::getVersion(uint32_t& v) {
    Status s = ensureOpen();
    if (!s.ok()) return s;
    v = 0;
    if (::ioctl(fd_, FG_IOC_GET_VERSION, &v) != 0)
        return Status::fail(Err::DriverUnavailable, std::string("ioctl(GET_VERSION) failed: ") + std::strerror(errno));
    return Status::success();
}

Status DriverManager::clear() {
    Status s = ensureOpen();
    if (!s.ok()) return s;
    if (::ioctl(fd_, FG_IOC_CLEAR) != 0) {
        if (errno == EPERM) return Status::fail(Err::PermissionDenied, "Clearing the driver queue requires CAP_SYS_ADMIN (root).");
        return Status::fail(Err::DriverUnavailable, std::string("ioctl(CLEAR) failed: ") + std::strerror(errno));
    }
    return Status::success();
}

const char* DriverManager::typeName(uint32_t t) {
    switch (t) {
        case FG_EVT_UNAUTHORIZED_ACCESS: return "UNAUTHORIZED_ACCESS";
        case FG_EVT_INTEGRITY_FAILURE: return "INTEGRITY_FAILURE";
        case FG_EVT_PROTECTED_FILE_OPEN: return "PROTECTED_FILE_OPEN";
        case FG_EVT_PROTECTED_FILE_CREATED: return "PROTECTED_FILE_CREATED";
        default: return "UNKNOWN";
    }
}

}  // namespace fg
