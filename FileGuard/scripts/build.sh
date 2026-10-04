#!/usr/bin/env bash
# Build FileGuard (application via CMake) and, optionally, the kernel module (via Kbuild).
#   scripts/build.sh [Debug|Release] [--with-driver] [--test]
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD_TYPE=Release; WITH_DRIVER=0; RUN_TESTS=0
for a in "$@"; do
  case "$a" in
    Debug|Release) BUILD_TYPE="$a" ;;
    --with-driver) WITH_DRIVER=1 ;;
    --test) RUN_TESTS=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
cmake -S . -B build -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build build -j"$(nproc)"
[ "$RUN_TESTS" -eq 1 ] && ctest --test-dir build --output-on-failure
if [ "$WITH_DRIVER" -eq 1 ]; then make -C driver; fi
echo "Built: build/fileguard$( [ -x build/fileguard-gui ] && echo ', build/fileguard-gui')"
