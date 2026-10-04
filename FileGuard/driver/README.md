# FileGuard kernel driver (`/dev/fileguard`)

Small character device that keeps a bounded queue of security events sent by the
FileGuard application. See [`../docs/driver.md`](../docs/driver.md) for the full explanation.

**Target:** Ubuntu 24.04 LTS, kernel 6.8 series (`uname -r` -> `6.8.0-*`). Version guards in the
source keep it building on 5.15-6.11 for the APIs that changed (`class_create`, `devnode`, `no_llseek`).

```bash
sudo apt install build-essential linux-headers-$(uname -r)
make                                  # builds fileguard_driver.ko (Kbuild, NOT cmake)
sudo ../scripts/install_driver.sh     # insmod + group 'fileguard' + udev rule
ls -l /dev/fileguard ; cat /proc/fileguard ; dmesg | tail
../build/fileguard driver status      # user space talks to the driver
sudo ../scripts/uninstall_driver.sh   # rmmod + remove rule
```

Secure Boot: unsigned modules are refused on Secure-Boot systems. Use a VM, disable Secure Boot
for the lab machine, or sign the module with a MOK key (`mokutil`, `kmodsign`).
License: GPL-2.0 (kernel requirement).
