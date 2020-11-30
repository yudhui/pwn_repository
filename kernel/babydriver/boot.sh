#!/bin/bash

qemu-system-x86_64 -gdb tcp::1234 -initrd rootfs.cpio -enable-kvm -kernel bzImage -append 'console=ttyS0 root=/dev/ram oops=panic panic=1' -monitor /dev/null -m 64M --nographic  -smp cores=1,threads=1 -cpu kvm64,+smep


