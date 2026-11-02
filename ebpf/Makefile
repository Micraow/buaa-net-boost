CLANG ?= clang
CC ?= gcc
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu
CFLAGS = -O2 -Wall

all: connect_redirect.bpf.o loader

connect_redirect.bpf.o: connect_redirect.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

clean:
	rm -f connect_redirect.bpf.o loader

.PHONY: all clean
