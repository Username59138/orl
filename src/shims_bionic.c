// SPDX-License-Identifier: GPL-3.0-or-later
// Replacements for bionic / Android NDK symbols that glibc lacks or that
// behave differently. Anything not listed here falls back to the host libc,
// so this table grows as the target library asks for more.

#define _GNU_SOURCE
#include "shims.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ libc bits --- */

// bionic exposes errno through __errno(); glibc through __errno_location().
// Both use kernel errno numbers on x86_64, so values are compatible.
static int *b___errno(void) { return &errno; }

// FORTIFY helpers that exist in bionic but not in glibc.
static size_t b___strlen_chk(const char *s, size_t n) {
    size_t len = strlen(s);
    if (len >= n) { fprintf(stderr, "[shim] __strlen_chk overflow\n"); abort(); }
    return len;
}
static char *b___strchr_chk(const char *s, int c, size_t n) { (void)n; return strchr(s, c); }
static char *b___strrchr_chk(const char *s, int c, size_t n) { (void)n; return strrchr(s, c); }

static void b_android_set_abort_message(const char *msg) {
    fprintf(stderr, "[abort message] %s\n", msg);
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

#define S(name) { #name, (void *)b_##name }
static const struct { const char *name; void *fn; } table[] = {
    S(__errno),
    S(__strlen_chk), S(__strchr_chk), S(__strrchr_chk),
    S(android_set_abort_message),
    S(__system_property_get),
    S(__android_log_write), S(__android_log_print),
    S(__android_log_vprint), S(__android_log_assert),
};

void *shim_lookup(const char *name) {
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].name, name) == 0) return table[i].fn;
    return NULL;
}
