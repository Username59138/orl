# SPDX-License-Identifier: GPL-3.0-or-later
CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
# libm must stay linked even though orl-run itself barely uses it: the
# client's math imports are resolved from the host at load time.
LDLIBS  := -Wl,--push-state,--no-as-needed -lm -Wl,--pop-state -ldl

BIN  := build/orl-run
SRCS := $(wildcard src/*.c)

# Test libraries, one per relocation format we support.
TEST_CFLAGS := -O2 -fPIC -shared -nostdlib -fno-builtin
TESTLIBS := build/testlib_rela.so build/testlib_relr.so build/testlib_aps2.so build/testabi.so

all: $(BIN)

$(BIN): $(SRCS) src/*.h | build
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

build:
	mkdir -p build

build/testlib_rela.so: tests/testlib.c | build
	$(CC) $(TEST_CFLAGS) -o $@ $<

build/testlib_relr.so: tests/testlib.c | build
	$(CC) $(TEST_CFLAGS) -Wl,-z,pack-relative-relocs -o $@ $<

# Android-style packed relocations (APS2), as produced by the NDK.
build/testlib_aps2.so: tests/testlib.c | build
	clang $(TEST_CFLAGS) -fuse-ld=lld -Wl,--pack-dyn-relocs=android -o $@ $<

# Built as a real Android target, so long double, struct layouts etc. are
# bionic's. -nostdlib: every libc call is an import our shims must answer.
build/testabi.so: tests/testabi.c | build
	clang --target=x86_64-linux-android26 -O2 -fPIC -shared -nostdlib -ffreestanding \
		-fuse-ld=lld -o $@ $<

test: $(BIN) $(TESTLIBS)
	./tests/run.sh

clean:
	rm -rf build

.PHONY: all test clean
