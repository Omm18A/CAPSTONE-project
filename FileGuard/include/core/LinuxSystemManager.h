#pragma once
// Linux system-programming layer: every function maps to a real POSIX call
// with a security purpose (see docs/architecture.md, "System calls").
#include <string>

#include "core/Common.h"

namespace fg {

struct SystemInfo {
    std::string kernel, arch, hostname, cpuModel, cpusOnline, driverState, driverProc;
    long cpuCores = 0;
    uint64_t memTotalKb = 0, memAvailKb = 0;
    uint64_t storageTotalBytes = 0, storageFreeBytes = 0;
    unsigned uid = 0, euid = 0;
};

class LinuxSystemManager {
public:
    // open + fstat + read: reads a regular file, refusing special files / oversize.
    static Status readFile(const std::string& path, uint64_t maxBytes, Bytes& out);
    // open(O_EXCL|O_NOFOLLOW tmp) + write + fchmod + fsync + rename: crash-safe replace.
    static Status writeFileAtomic(const std::string& path, const Bytes& data, unsigned mode);
    // open(O_CREAT|O_EXCL|O_NOFOLLOW) + write: never overwrites an existing file.
    static Status writeFileExclusive(const std::string& path, const Bytes& data, unsigned mode);
    // lstat + mkdir + chmod; refuses symlinks and directories owned by someone else.
    static Status ensureDir(const std::string& path, unsigned mode);
    static bool pathExists(const std::string& path);                  // stat
    static Status removeFile(const std::string& path);                // unlink
    static std::string canonicalize(const std::string& path);         // realpath ("" on error)
    static bool isUnder(const std::string& canonicalPath, const std::string& canonicalDir);
    static bool isRoot();                                             // geteuid()==0

    static SystemInfo gather(const std::string& dataDir);             // uname,/proc,/sys,statvfs
    static std::string format(const SystemInfo& si);
};

}  // namespace fg
