#!/usr/bin/env bash
# Load the FileGuard kernel module and make /dev/fileguard usable by group 'fileguard'.
# Root is needed ONLY here (insmod and device-node ownership). The application itself runs unprivileged.
# Build the module first, as a normal user:  make -C driver
set -euo pipefail
cd "$(dirname "$0")/.."
KO=driver/fileguard_driver.ko
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
[ -f "$KO" ] || { echo "$KO not found. Build it first (as your normal user): make -C driver" >&2; exit 1; }
lsmod | grep -q '^fileguard_driver' && { echo "Module already loaded."; } || insmod "$KO"
for i in $(seq 1 20); do [ -e /dev/fileguard ] && break; sleep 0.1; done
[ -e /dev/fileguard ] || { echo "/dev/fileguard did not appear; see: dmesg | tail" >&2; exit 1; }
getent group fileguard >/dev/null || groupadd --system fileguard
cat > /etc/udev/rules.d/99-fileguard.rules <<'RULE'
KERNEL=="fileguard", SUBSYSTEM=="fileguard", GROUP="fileguard", MODE="0660"
RULE
chgrp fileguard /dev/fileguard; chmod 0660 /dev/fileguard
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  usermod -aG fileguard "$SUDO_USER"
  echo "Added $SUDO_USER to group 'fileguard' (log out/in or run: newgrp fileguard)."
fi
ls -l /dev/fileguard
dmesg | tail -n 3
