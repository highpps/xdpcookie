# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

USER_PROG := xdpcookie
USER_HDRS := xdpcookie.h
EBPF_OBJS := xdpcookie.bpf.o

CFLAGS ?= -O2 -g -Wall -Werror
BPF_CFLAGS ?= -O2 -g -Wall -Werror -Wno-compare-distinct-pointer-types

DESTDIR ?=
VERSION ?= $(shell git describe --tags)

CONFIG := config.mk
CONFIGURE := configure
include $(CONFIG)

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

MKDEPS := Makefile $(CONFIG) ${CONFIGURE}

VMLINUX := vmlinux.h
EBPF_SKEL := ${EBPF_OBJS:.o=.h}

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS += -D__TARGET_ARCH_$(ARCH)

CFLAGS += -DVERSION=$(VERSION) $(EXTRA_CFLAGS)
BPF_CFLAGS += $(EXTRA_CFLAGS)

LDFLAGS += $(EXTRA_LDFLAGS)
LDLIBS += ${EXTRA_LDLIBS}

all: $(USER_PROG) $(MANGZ)

$(CONFIG): $(CONFIGURE)
	sh configure

${VMLINUX}: $(MKDEPS)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c >$@

$(EBPF_OBJS): %.o: %.c $(USER_HDRS) ${VMLINUX} $(MKDEPS)
	$(CLANG) -target bpf -mcpu=probe $(BPF_CFLAGS) -c -o $@ $<

$(EBPF_SKEL): %.h: %.o $(MKDEPS)
	$(BPFTOOL) gen skeleton ${@:.h=.o} >$@

$(USER_PROG): %: %.c $(EBPF_SKEL) $(MKDEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

.PHONY: install clean

install:
	install -D -t $(DESTDIR)$(BINDIR) $(USER_PROG)

clean:
	rm -f ${VMLINUX} $(USER_PROG) $(EBPF_OBJS) $(EBPF_SKEL)
