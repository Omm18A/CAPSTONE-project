#!/usr/bin/env bash
# Unload the module and remove the udev rule. Requires root (rmmod).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
if lsmod | grep -q '^fileguard_driver'; then rmmod fileguard_driver; echo "Module unloaded."; else echo "Module not loaded."; fi
rm -f /etc/udev/rules.d/99-fileguard.rules
[ -e /dev/fileguard ] && echo "warning: /dev/fileguard still exists" || echo "/dev/fileguard removed."
dmesg | tail -n 2
