# Master Thesis Modified Memory Allocator Kernelmodule

This repository contains the kernelmodule and its corresponding kernel return probes which have been developed during my master thesis.
You will need the respective build libraries for building kernel modules for your respective Linux kernel.
This module has been built using the *v6.13.0* version of the Linux kernel.
Later versions might behave differently or not work at all with this kernel module.
In fact, it is very likely that this will be the case as the Linux memory allocation has been worked on and an important function has already been changed.

Use `make` to build the kernelmodule and `sudo insmod alloc_pages_probe.ko` to insert it into the kernel.
If you have kernel debugging messages enabled, it will print out the order and address of intercepted and exchanged pages.
