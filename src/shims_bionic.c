// SPDX-License-Identifier: GPL-3.0-or-later
// Replacements for bionic / Android NDK symbols that glibc lacks or that
// behave differently. Anything not in a shim table falls back to the host
// libc, unless it is on the `blocked` list below: those have the same name in
// glibc but a different ABI, so they become trap stubs instead of silently
// corrupting memory.
//
// This file: the registry, core libc bits, liblog, FORTIFY helpers.
// Other areas: shims_stdio.c, shims_signal.c, shims_net.c, shims_sys.c,
// shims_dl.c.

#define _GNU_SOURCE
#include "shims.h"

#include <dlfcn.h>
#include <errno.h>
#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------ libc bits --- */

// bionic exposes errno through __errno(); glibc through __errno_location().
// Both use kernel errno numbers on x86_64, so values are compatible.
static int *b___errno(void) { return &errno; }

static void b_android_set_abort_message(const char *msg) {
    fprintf(stderr, "[abort message] %s\n", msg);
}

// bionic: __assert(file, line, msg); glibc's __assert has (msg, file, line).
__attribute__((noreturn))
static void b___assert2(const char *file, int line, const char *func, const char *msg) {
    fprintf(stderr, "%s:%d: %s: assertion \"%s\" failed\n", file, line, func, msg);
    abort();
}
__attribute__((noreturn))
static void b___assert(const char *file, int line, const char *msg) {
    fprintf(stderr, "%s:%d: assertion \"%s\" failed\n", file, line, msg);
    abort();
}

// bionic's strerror_r is the POSIX one (returns int); glibc's is the GNU one,
// which bionic calls __gnu_strerror_r.
extern int __xpg_strerror_r(int errnum, char *buf, size_t n);
static int b_strerror_r(int e, char *buf, size_t n) { return __xpg_strerror_r(e, buf, n); }
static char *b___gnu_strerror_r(int e, char *buf, size_t n) { return strerror_r(e, buf, n); }

// Normally %fs:0x28 is used, but bionic also exports the guard as a variable.
static uintptr_t b___stack_chk_guard;

/* --------------------------------------------------------------- FORTIFY --- */
// Helpers that exist in bionic but not in glibc, or whose arguments differ.

void shim_fortify_fail(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("[shim] FORTIFY: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}

static size_t b___strlen_chk(const char *s, size_t n) {
    size_t len = strlen(s);
    if (len >= n) shim_fortify_fail("strlen: prevented read past end of buffer");
    return len;
}
static char *b___strchr_chk(const char *s, int c, size_t n) { (void)n; return (char *)strchr(s, c); }
static char *b___strrchr_chk(const char *s, int c, size_t n) { (void)n; return (char *)strrchr(s, c); }

static char *b___strncpy_chk2(char *dst, const char *src, size_t n,
                              size_t dst_len, size_t src_len) {
    if (n > dst_len)
        shim_fortify_fail("strncpy: prevented %zu-byte write into %zu-byte buffer", n, dst_len);
    if (src_len < n && strnlen(src, src_len) == src_len)
        shim_fortify_fail("strncpy: prevented read past end of %zu-byte buffer", src_len);
    return strncpy(dst, src, n);
}

static ssize_t b___write_chk(int fd, const void *buf, size_t count, size_t buf_size) {
    if (count > buf_size)
        shim_fortify_fail("write: prevented %zu-byte read from %zu-byte buffer", count, buf_size);
    return write(fd, buf, count);
}

static ssize_t b___sendto_chk(int fd, const void *buf, size_t len, size_t buf_size, int flags,
                              const struct sockaddr *addr, socklen_t addr_len) {
    if (len > buf_size)
        shim_fortify_fail("sendto: prevented %zu-byte read from %zu-byte buffer", len, buf_size);
    return sendto(fd, buf, len, flags, addr, addr_len);
}

// fd_set is the same bit array in both libcs (1024 bits of unsigned long).
#define B_FD_SETSIZE 1024
#define B_NFDBITS    (8 * (int)sizeof(unsigned long))
static void check_fd_set(const char *fn, int fd, size_t set_size) {
    if (fd < 0 || fd >= B_FD_SETSIZE)
        shim_fortify_fail("%s: file descriptor %d out of range", fn, fd);
    if (set_size < B_FD_SETSIZE / 8)
        shim_fortify_fail("%s: set size %zu is too small to be an fd_set", fn, set_size);
}
static void b___FD_SET_chk(int fd, unsigned long *set, size_t set_size) {
    check_fd_set("FD_SET", fd, set_size);
    set[fd / B_NFDBITS] |= 1UL << (fd % B_NFDBITS);
}
static void b___FD_CLR_chk(int fd, unsigned long *set, size_t set_size) {
    check_fd_set("FD_CLR", fd, set_size);
    set[fd / B_NFDBITS] &= ~(1UL << (fd % B_NFDBITS));
}
static int b___FD_ISSET_chk(int fd, const unsigned long *set, size_t set_size) {
    check_fd_set("FD_ISSET", fd, set_size);
    return (set[fd / B_NFDBITS] >> (fd % B_NFDBITS)) & 1;
}

/* --------------------------------------------------------- system props --- */
// A generic, honest device description. Grows as the client asks for more.

static const struct { const char *k, *v; } props[] = {
    { "ro.build.version.sdk",     "33" },
    { "ro.build.version.release", "13" },
    { "ro.product.cpu.abi",       "x86_64" },
    { "ro.product.manufacturer",  "OpenRoLauncher" },
    { "ro.product.model",         "Linux Desktop" },
    { "ro.product.brand",         "orl" },
    { "ro.hardware",              "orl" },
};

static int b___system_property_get(const char *name, char *value) {
    for (size_t i = 0; i < sizeof props / sizeof props[0]; i++) {
        if (strcmp(props[i].k, name) == 0) {
            strncpy(value, props[i].v, 91); // PROP_VALUE_MAX = 92
            value[91] = 0;
            return (int)strlen(value);
        }
    }
    if (getenv("ORL_TRACE")) fprintf(stderr, "[shim] unknown property %s\n", name);
    value[0] = 0;
    return 0;
}

/* -------------------------------------------------------------- liblog --- */

static char prio_char(int prio) {
    static const char tbl[] = "??VDIWEFS"; // ANDROID_LOG_VERBOSE = 2 ...
    return (prio >= 0 && prio < (int)sizeof tbl - 1) ? tbl[prio] : '?';
}

static int b___android_log_write(int prio, const char *tag, const char *msg) {
    return fprintf(stderr, "%c/%s: %s\n", prio_char(prio), tag ? tag : "", msg ? msg : "");
}

static int b___android_log_buf_write(int buf_id, int prio, const char *tag, const char *msg) {
    (void)buf_id;
    return b___android_log_write(prio, tag, msg);
}

static int b___android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap) {
    char buf[4096];
    vsnprintf(buf, sizeof buf, fmt, ap);
    return b___android_log_write(prio, tag, buf);
}

static int b___android_log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = b___android_log_vprint(prio, tag, fmt, ap);
    va_end(ap);
    return r;
}

static void b___android_log_assert(const char *cond, const char *tag, const char *fmt, ...) {
    char buf[4096] = "";
    if (fmt) { va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap); }
    fprintf(stderr, "F/%s: assertion %s: %s\n", tag ? tag : "", cond ? cond : "", buf);
    abort();
}

/* ---------------------------------------------------------------- table --- */

const shim_entry shims_core[] = {
    SHIM(__errno), SHIM(android_set_abort_message),
    SHIM(__assert), SHIM(__assert2),
    SHIM(strerror_r), SHIM(__gnu_strerror_r),
    { "__stack_chk_guard", &b___stack_chk_guard },
    SHIM(__strlen_chk), SHIM(__strchr_chk), SHIM(__strrchr_chk), SHIM(__strncpy_chk2),
    SHIM(__write_chk), SHIM(__sendto_chk),
    SHIM(__FD_SET_chk), SHIM(__FD_CLR_chk), SHIM(__FD_ISSET_chk),
    SHIM(__system_property_get),
    SHIM(__android_log_write), SHIM(__android_log_buf_write), SHIM(__android_log_print),
    SHIM(__android_log_vprint), SHIM(__android_log_assert),
    { NULL, NULL }
};

static const shim_entry *const tables[] = {
    shims_core, shims_stdio, shims_signal, shims_net, shims_sys, shims_dl,
};

void *shim_lookup(const char *name) {
    for (size_t t = 0; t < sizeof tables / sizeof tables[0]; t++)
        for (const shim_entry *e = tables[t]; e->name; e++)
            if (strcmp(e->name, name) == 0) return e->addr;
    return NULL;
}

// Same name in glibc, different ABI. Shimmed relatives of these live in the
// tables above; these are the ones we haven't needed yet.
static const char *const blocked[] = {
    // sigset_t is 8 bytes in bionic, 128 in glibc
    "sigprocmask", "sigsuspend", "sigpending", "sigwait", "sigwaitinfo", "sigtimedwait",
    "signalfd", "pselect", "ppoll", "epoll_pwait", "sigandset", "sigorset", "sigisemptyset",
    // our sem_t is our own futex counter
    "sem_timedwait", "sem_clockwait", "sem_timedwait_monotonic_np",
    "sem_open", "sem_close", "sem_unlink",
    // struct termios is 36 bytes in bionic (kernel layout), 60 in glibc
    "cfgetispeed", "cfgetospeed", "cfsetispeed", "cfsetospeed", "cfsetspeed", "cfmakeraw",
    // long double is IEEE quad in Android x86_64, x87 80-bit in glibc
    "wcstold", "wcstold_l", "nexttoward", "nexttowardf",
    "acosl", "acoshl", "asinl", "asinhl", "atanl", "atanhl", "atan2l", "cbrtl", "ceill",
    "copysignl", "cosl", "coshl", "erfl", "erfcl", "expl", "exp2l", "expm1l", "fabsl",
    "fdiml", "floorl", "fmaxl", "fminl", "fmodl", "frexpl", "hypotl", "ilogbl", "ldexpl",
    "lgammal", "llrintl", "llroundl", "logl", "log10l", "log1pl", "log2l", "logbl",
    "lrintl", "lroundl", "modfl", "nanl", "nearbyintl", "nextafterl", "nexttowardl",
    "remainderl", "remquol", "rintl", "roundl", "scalblnl", "scalbnl", "sinl", "sinhl",
    "sqrtl", "tanl", "tanhl", "tgammal", "truncl",
};

int shim_host_blocked(const char *name) {
    for (size_t i = 0; i < sizeof blocked / sizeof blocked[0]; i++)
        if (strcmp(blocked[i], name) == 0) return 1;
    return 0;
}

void *shim_resolve(const char *name) {
    void *p = shim_lookup(name);
    if (p || shim_host_blocked(name)) return p;
    return dlsym(RTLD_DEFAULT, name);
}

void shims_init(void) {
    uintptr_t guard;
    __asm__("movq %%fs:0x28, %0" : "=r"(guard));
    b___stack_chk_guard = guard;
    // bionic's multibyte functions always speak UTF-8, whatever the locale.
    if (!setlocale(LC_CTYPE, "C.UTF-8"))
        fprintf(stderr, "[shim] warning: no C.UTF-8 locale, multibyte text will break\n");
}
