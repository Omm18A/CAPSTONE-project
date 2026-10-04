// Needs the kernel module loaded (see docs/driver.md). Exits 77 (CTest SKIP) otherwise.
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "TestUtil.h"
using namespace fg;

int main() {
    DriverManager d;
    Status s = d.open();
    if (!s.ok()) { std::printf("test_driver: SKIPPED (%s)\n", s.message.c_str()); return 77; }

    uint32_t ver = 0;
    CHECK_OK(d.getVersion(ver));
    CHECK(ver == FG_DRIVER_VERSION);

    fg_stats before{}, after{};
    CHECK_OK(d.getStats(before));
    CHECK_OK(d.sendEvent(FG_EVT_UNAUTHORIZED_ACCESS, 10001, 7));
    CHECK_OK(d.sendEvent(FG_EVT_INTEGRITY_FAILURE, 10001, 7));
    CHECK_OK(d.getStats(after));
    CHECK(after.total == before.total + 2);
    CHECK(after.per_type[FG_EVT_UNAUTHORIZED_ACCESS] == before.per_type[FG_EVT_UNAUTHORIZED_ACCESS] + 1);
    CHECK(after.pending == before.pending + 2 && after.capacity == 256);

    // drain until our two events appear; verify kernel-filled fields
    bool sawU = false, sawI = false;
    fg_event ev{};
    while (d.readEvent(ev).ok()) {
        if (ev.type == FG_EVT_UNAUTHORIZED_ACCESS && ev.file_num == 10001 && ev.user_id == 7) {
            sawU = true;
            CHECK(ev.pid == static_cast<uint32_t>(getpid()));            // set by kernel, not by us
            CHECK(ev.uid == static_cast<uint32_t>(getuid()));
            CHECK(ev.timestamp > 1600000000ull);
        }
        if (ev.type == FG_EVT_INTEGRITY_FAILURE) sawI = true;
    }
    CHECK(sawU && sawI);
    CHECK_CODE(d.readEvent(ev), Err::NotFound);                          // empty -> EAGAIN

    // invalid input must be rejected, not crash
    CHECK_CODE(d.sendEvent(0, 1, 1), Err::InvalidInput);                 // type NONE
    CHECK_CODE(d.sendEvent(99, 1, 1), Err::InvalidInput);                // out of range
    int fd = ::open("/dev/fileguard", O_RDWR);
    CHECK(fd >= 0);
    char junk[5] = {1, 2, 3, 4, 5};
    CHECK(::write(fd, junk, sizeof junk) < 0 && errno == EINVAL);        // wrong size
    volatile uintptr_t badAddr = 8;                                      // deliberately invalid user pointer
    CHECK(::write(fd, reinterpret_cast<const void*>(badAddr), sizeof(fg_event)) < 0 && errno == EFAULT);
    char small[4];
    CHECK(::read(fd, small, sizeof small) < 0 && errno == EINVAL);       // buffer too small
    CHECK(::ioctl(fd, _IO('Z', 1)) < 0 && errno == ENOTTY);              // unknown ioctl
    CHECK(::ioctl(fd, FG_IOC_GET_STATS, nullptr) < 0 && errno == EFAULT);
    ::close(fd);

    // flood: queue is bounded, overflow is counted not corrupted
    for (int i = 0; i < 300; ++i) (void)d.sendEvent(FG_EVT_PROTECTED_FILE_OPEN, 1, 1);
    fg_stats st{};
    CHECK_OK(d.getStats(st));
    CHECK(st.pending == 256 && st.dropped > 0);
    if (geteuid() != 0) CHECK_CODE(d.clear(), Err::PermissionDenied);    // CAP_SYS_ADMIN required
    else CHECK_OK(d.clear());
    return finish("test_driver");
}
