#pragma once
// User-space side of /dev/fileguard. The driver is OPTIONAL at run time:
// when it is not loaded every call returns DriverUnavailable and FileGuard
// keeps working (events are still stored in SQLite and audit.log).
#include <string>

#include "core/Common.h"
#include "fileguard_ioctl.h"

namespace fg {

class DriverManager {
public:
    explicit DriverManager(std::string devicePath = "/dev/fileguard") : path_(std::move(devicePath)) {}
    ~DriverManager();
    DriverManager(const DriverManager&) = delete;
    DriverManager& operator=(const DriverManager&) = delete;

    Status open();                       // O_RDWR|O_CLOEXEC
    void close();
    bool isOpen() const { return fd_ >= 0; }

    Status sendEvent(uint32_t type, uint32_t fileNum, uint32_t userId);  // write()
    Status readEvent(fg_event& ev);      // read(); Err::NotFound when queue empty
    Status getStats(fg_stats& st);       // ioctl FG_IOC_GET_STATS
    Status getVersion(uint32_t& v);      // ioctl FG_IOC_GET_VERSION
    Status clear();                      // ioctl FG_IOC_CLEAR (needs CAP_SYS_ADMIN)

    static const char* typeName(uint32_t type);

private:
    Status ensureOpen();
    std::string path_;
    int fd_ = -1;
};

}  // namespace fg
