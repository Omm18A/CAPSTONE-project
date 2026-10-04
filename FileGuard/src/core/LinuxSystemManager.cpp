#include "core/LinuxSystemManager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace fg {

namespace {
Status ioErr(const std::string& what, const std::string& path) {
    return Status::fail(Err::IoFailure, what + " '" + path + "': " + std::strerror(errno));
}
bool writeAll(int fd, const uint8_t* p, size_t n) {
    while (n > 0) {
        ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= static_cast<size_t>(w);
    }
    return true;
}
}  // namespace

Status LinuxSystemManager::readFile(const std::string& path, uint64_t maxBytes, Bytes& out) {
    out.clear();
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return ioErr("Cannot open", path);
    struct stat st;
    if (::fstat(fd, &st) != 0) { Status s = ioErr("Cannot stat", path); ::close(fd); return s; }
    if (!S_ISREG(st.st_mode)) { ::close(fd); return Status::fail(Err::InvalidInput, "'" + path + "' is not a regular file."); }
    if (static_cast<uint64_t>(st.st_size) > maxBytes) {
        ::close(fd);
        return Status::fail(Err::InvalidInput, "'" + path + "' exceeds the maximum allowed size.");
    }
    out.resize(static_cast<size_t>(st.st_size));
    size_t got = 0;
    while (got < out.size()) {
        ssize_t r = ::read(fd, out.data() + got, out.size() - got);
        if (r < 0) { if (errno == EINTR) continue; Status s = ioErr("Read error on", path); ::close(fd); out.clear(); return s; }
        if (r == 0) break;
        got += static_cast<size_t>(r);
    }
    ::close(fd);
    out.resize(got);
    return Status::success();
}

Status LinuxSystemManager::writeFileAtomic(const std::string& path, const Bytes& data, unsigned mode) {
    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) return ioErr("Cannot create", tmp);
    bool ok = writeAll(fd, data.data(), data.size()) && ::fchmod(fd, mode) == 0 && ::fsync(fd) == 0;
    int e = errno;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
        if (ok) e = errno;
        ::unlink(tmp.c_str());
        errno = e;
        return ioErr("Cannot write", path);
    }
    return Status::success();
}

Status LinuxSystemManager::writeFileExclusive(const std::string& path, const Bytes& data, unsigned mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) {
        if (errno == EEXIST) return Status::fail(Err::InvalidInput, "Destination '" + path + "' already exists; refusing to overwrite.");
        return ioErr("Cannot create", path);
    }
    bool ok = writeAll(fd, data.data(), data.size()) && ::fchmod(fd, mode) == 0 && ::fsync(fd) == 0;
    int e = errno;
    ::close(fd);
    if (!ok) { ::unlink(path.c_str()); errno = e; return ioErr("Cannot write", path); }
    return Status::success();
}

Status LinuxSystemManager::ensureDir(const std::string& path, unsigned mode) {
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0) {
        if (errno != ENOENT) return ioErr("Cannot stat", path);
        if (::mkdir(path.c_str(), mode) != 0 && errno != EEXIST) return ioErr("Cannot create directory", path);
        if (::lstat(path.c_str(), &st) != 0) return ioErr("Cannot stat", path);
    }
    if (!S_ISDIR(st.st_mode)) return Status::fail(Err::IoFailure, "'" + path + "' exists but is not a real directory (symlinks are refused).");
    if (st.st_uid != ::geteuid()) return Status::fail(Err::PermissionDenied, "'" + path + "' is owned by another user.");
    if ((st.st_mode & 07777) != mode && ::chmod(path.c_str(), mode) != 0) return ioErr("Cannot chmod", path);
    return Status::success();
}

bool LinuxSystemManager::pathExists(const std::string& p) { struct stat st; return ::stat(p.c_str(), &st) == 0; }

Status LinuxSystemManager::removeFile(const std::string& p) {
    if (::unlink(p.c_str()) != 0 && errno != ENOENT) return ioErr("Cannot delete", p);
    return Status::success();
}

std::string LinuxSystemManager::canonicalize(const std::string& path) {
    char buf[PATH_MAX];
    if (!::realpath(path.c_str(), buf)) return {};
    return buf;
}

bool LinuxSystemManager::isUnder(const std::string& p, const std::string& dir) {
    if (p.empty() || dir.empty()) return false;
    std::string d = dir;
    if (d.back() != '/') d.push_back('/');
    return p == dir || p.compare(0, d.size(), d) == 0;
}

bool LinuxSystemManager::isRoot() { return ::geteuid() == 0; }

// ---- system information (/proc, /sys, uname, statvfs) -------------------------
static std::string firstLine(const std::string& path) {
    std::ifstream f(path);
    std::string l;
    std::getline(f, l);
    return l;
}

SystemInfo LinuxSystemManager::gather(const std::string& dataDir) {
    SystemInfo si;
    struct utsname u;
    if (::uname(&u) == 0) { si.kernel = std::string(u.sysname) + " " + u.release; si.arch = u.machine; }
    char host[256] = {0};
    if (::gethostname(host, sizeof host - 1) == 0) si.hostname = host;
    si.cpuCores = ::sysconf(_SC_NPROCESSORS_ONLN);
    si.cpusOnline = firstLine("/sys/devices/system/cpu/online");
    si.uid = ::getuid(); si.euid = ::geteuid();

    std::ifstream ci("/proc/cpuinfo");
    for (std::string l; std::getline(ci, l);) {
        if (l.rfind("model name", 0) == 0 || l.rfind("Model name", 0) == 0 || l.rfind("Hardware", 0) == 0) {
            auto c = l.find(':');
            if (c != std::string::npos) { si.cpuModel = l.substr(c + 2); break; }
        }
    }
    if (si.cpuModel.empty()) si.cpuModel = "unknown";

    std::ifstream mi("/proc/meminfo");
    for (std::string l; std::getline(mi, l);) {
        unsigned long long v = 0;
        if (std::sscanf(l.c_str(), "MemTotal: %llu kB", &v) == 1) si.memTotalKb = v;
        else if (std::sscanf(l.c_str(), "MemAvailable: %llu kB", &v) == 1) si.memAvailKb = v;
    }

    struct statvfs sv;
    if (::statvfs(dataDir.c_str(), &sv) == 0) {
        si.storageTotalBytes = static_cast<uint64_t>(sv.f_blocks) * sv.f_frsize;
        si.storageFreeBytes = static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
    }

    struct stat st;
    if (::stat("/dev/fileguard", &st) == 0) {
        char m[16]; std::snprintf(m, sizeof m, "%04o", static_cast<unsigned>(st.st_mode & 07777));
        si.driverState = std::string("loaded: /dev/fileguard present (mode ") + m + ")";
        std::ifstream pf("/proc/fileguard");
        std::stringstream ss; ss << pf.rdbuf();
        si.driverProc = ss.str();
    } else {
        si.driverState = "not loaded (/dev/fileguard absent) - events will not be forwarded";
    }
    return si;
}

std::string LinuxSystemManager::format(const SystemInfo& s) {
    std::ostringstream o;
    o << "Kernel      : " << s.kernel << "\n"
      << "Architecture: " << s.arch << "\n"
      << "Hostname    : " << s.hostname << "\n"
      << "CPU         : " << s.cpuModel << "\n"
      << "CPU cores   : " << s.cpuCores << " online (" << s.cpusOnline << ")\n"
      << "Memory      : " << s.memTotalKb / 1024 << " MiB total, " << s.memAvailKb / 1024 << " MiB available\n"
      << "Storage     : " << s.storageTotalBytes / (1024 * 1024) << " MiB total, "
      << s.storageFreeBytes / (1024 * 1024) << " MiB free (FileGuard data volume)\n"
      << "Process     : uid=" << s.uid << " euid=" << s.euid << (s.euid == 0 ? "  [WARNING: running as root]" : "") << "\n"
      << "Driver      : " << s.driverState << "\n";
    if (!s.driverProc.empty()) o << "/proc/fileguard:\n" << s.driverProc;
    return o.str();
}

}  // namespace fg
