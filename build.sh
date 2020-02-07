#!/bin/bash
make
clang -Wall -Wextra -O2 -emit-llvm -c ebpf-kern.c -S -o - | llc -march=bpf -filetype=obj -o ebpf-kern.o
