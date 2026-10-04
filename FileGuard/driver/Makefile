# Kernel module build: uses the Linux Kbuild system, NOT CMake.
#   make            build fileguard_driver.ko against the running kernel
#   make clean
# Requires: sudo apt install build-essential linux-headers-$(uname -r)
obj-m += fileguard_driver.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
