// SPDX-License-Identifier: GPL-3.0-or-later
// printf family. The va_list layout is the same SysV one in both libcs, but
// `long double` isn't: Android x86_64 passes an IEEE quad in SSE registers,
// glibc's printf expects an x87 value in memory. Reading %Lf the glibc way
// gives a wrong number *and* shifts every argument after it.
//
// Formats without an L floating conversion (nearly all) go straight to
// glibc. The rest are walked here spec by spec: each argument is fetched
// with its bionic type, quads are narrowed to x87 long double (same exponent
// range, 64-bit instead of 113-bit mantissa), and glibc prints each spec.
// Positional arguments (%1$Lf) aren't supported in that slow path.

#define _GNU_SOURCE
#include "shims.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <wchar.h>

/* ------------------------------------------------------- format parsing --- */

typedef struct {
    char flags[8];
    int width, prec;             // -1 = not given
    int width_star, prec_star;
    char len[3];                 // "", "hh", "h", "l", "ll", "L", "q", "j", "z", "t"
    char conv;
    int positional;
} spec;

static int is_digit(char c) { return c >= '0' && c <= '9'; }

// p points just past '%'. Returns the end of the spec, or NULL if truncated.
static const char *parse_spec(const char *p, spec *s) {
    const char *start = p;
    memset(s, 0, sizeof *s);
    s->width = s->prec = -1;

    size_t nf = 0;
    while (*p && strchr("-+ #0'I", *p)) {
        if (nf < sizeof s->flags - 1) s->flags[nf++] = *p;
        p++;
    }
    if (*p == '*') {
        s->width_star = 1;
        p++;
    }
    for (; is_digit(*p); p++) s->width = (s->width < 0 ? 0 : s->width * 10) + (*p - '0');
    if (*p == '$') { s->positional = 1; return NULL; } // "%1$..." or "%*1$..."
    if (*p == '.') {
        p++;
        s->prec = 0;
        if (*p == '*') { s->prec_star = 1; p++; }
        for (; is_digit(*p); p++) s->prec = s->prec * 10 + (*p - '0');
    }
    if ((p[0] == 'h' && p[1] == 'h') || (p[0] == 'l' && p[1] == 'l')) {
        memcpy(s->len, p, 2);
        p += 2;
    } else if (*p && strchr("hlLqjzt", *p)) {
        s->len[0] = *p++;
    }
    if (!*p) return NULL;
    s->conv = *p++;
    if (memchr(start, '$', (size_t)(p - start))) s->positional = 1;
    return p;
}

static int is_float_conv(char c) { return c && strchr("aAeEfFgG", c); }

// Does this format pass a long double anywhere? (-1: yes, but positionally)
static int needs_quad(const char *fmt) {
    int quad = 0, positional = 0;
    for (const char *p = fmt; (p = strchr(p, '%')); ) {
        if (p[1] == '%') { p += 2; continue; }
        spec s;
        const char *end = parse_spec(p + 1, &s);
        if (s.positional) positional = 1;
        if (!end) break;
        if (s.len[0] == 'L' && is_float_conv(s.conv)) quad = 1;
        p = end;
    }
    if (quad && positional) {
        if (getenv("ORL_TRACE"))
            fprintf(stderr, "[shim] printf: positional long double not supported: %s\n", fmt);
        return -1;
    }
    return quad;
}

/* ------------------------------------------------------------ formatting --- */

typedef struct { char *p; size_t len, cap; } sbuf;

static int sb_reserve(sbuf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra + 1) cap *= 2;
    char *p = realloc(b->p, cap);
    if (!p) return -1;
    b->p = p;
    b->cap = cap;
    return 0;
}

static int sb_add(sbuf *b, const char *s, size_t n) {
    if (sb_reserve(b, n)) return -1;
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
    return 0;
}

// Print one argument with the rebuilt spec `f`.
#define EMIT(v) do {                                                         \
        int n_ = snprintf(NULL, 0, f, v);                                    \
        if (n_ < 0 || sb_reserve(b, (size_t)n_)) return -1;                  \
        snprintf(b->p + b->len, (size_t)n_ + 1, f, v);                       \
        b->len += (size_t)n_;                                                \
    } while (0)

static int vformat(sbuf *b, const char *fmt, va_list ap) {
    int saved_errno = errno; // for %m
    if (sb_reserve(b, 0)) return -1;
    b->p[0] = 0;
    for (const char *p = fmt; *p; ) {
        const char *pct = strchr(p, '%');
        if (!pct) return sb_add(b, p, strlen(p));
        if (sb_add(b, p, (size_t)(pct - p))) return -1;
        if (pct[1] == '%') {
            if (sb_add(b, "%", 1)) return -1;
            p = pct + 2;
            continue;
        }
        spec s;
        const char *end = parse_spec(pct + 1, &s);
        if (!end) return sb_add(b, pct, strlen(pct)); // truncated spec: print as is

        int width = s.width, prec = s.prec;
        char flags[sizeof s.flags + 1];
        strcpy(flags, s.flags);
        if (s.width_star) {
            width = va_arg(ap, int);
            if (width < 0) { strcat(flags, "-"); width = -width; }
        }
        if (s.prec_star) {
            prec = va_arg(ap, int);
            if (prec < 0) prec = -1;
        }
        char f[48], w[16] = "", pr[16] = "";
        if (width >= 0) snprintf(w, sizeof w, "%d", width);
        if (prec >= 0) snprintf(pr, sizeof pr, ".%d", prec);
        const char *len = s.len[0] == 'q' ? "ll" : s.len;
        snprintf(f, sizeof f, "%%%s%s%s%s%c", flags, w, pr, len, s.conv);
        int wide = s.len[0] == 'l' && !s.len[1];

        switch (s.conv) {
        case 'd': case 'i': case 'o': case 'u': case 'x': case 'X':
            if (!s.len[0] || s.len[0] == 'h') { int v = va_arg(ap, int); EMIT(v); }
            else { long long v = va_arg(ap, long long); EMIT(v); } // every other size is 8 bytes
            break;
        case 'c':
            if (wide) { wint_t v = va_arg(ap, wint_t); EMIT(v); }
            else { int v = va_arg(ap, int); EMIT(v); }
            break;
        case 'C': { wint_t v = va_arg(ap, wint_t); EMIT(v); break; }
        case 's':
            if (wide) { const wchar_t *v = va_arg(ap, const wchar_t *); EMIT(v); }
            else { const char *v = va_arg(ap, const char *); EMIT(v); }
            break;
        case 'S': { const wchar_t *v = va_arg(ap, const wchar_t *); EMIT(v); break; }
        case 'p': { void *v = va_arg(ap, void *); EMIT(v); break; }
        case 'a': case 'A': case 'e': case 'E': case 'f': case 'F': case 'g': case 'G':
            if (s.len[0] == 'L') { long double v = (long double)va_arg(ap, _Float128); EMIT(v); }
            else { double v = va_arg(ap, double); EMIT(v); }
            break;
        case 'm': {
            const char *msg = strerror(saved_errno);
            if (sb_add(b, msg, strlen(msg))) return -1;
            break;
        }
        case 'n':
            shim_fortify_fail("%%n not allowed on Android");
        default: // unknown conversion: copy it through
            if (sb_add(b, pct, (size_t)(end - pct))) return -1;
        }
        p = end;
    }
    return 0;
}

static int too_long(size_t len) {
    if (len <= 0x7fffffff) return 0;
    errno = EOVERFLOW;
    return 1;
}

/* ----------------------------------------------------- shared entry points --- */

int shim_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap) {
    if (needs_quad(fmt) <= 0) return vsnprintf(buf, n, fmt, ap);
    sbuf b = { 0 };
    int r = -1;
    if (vformat(&b, fmt, ap) == 0 && !too_long(b.len)) {
        if (n) {
            size_t k = b.len < n - 1 ? b.len : n - 1;
            memcpy(buf, b.p, k);
            buf[k] = 0;
        }
        r = (int)b.len;
    }
    free(b.p);
    return r;
}

int shim_vfprintf(FILE *fp, const char *fmt, va_list ap) {
    if (needs_quad(fmt) <= 0) return vfprintf(fp, fmt, ap);
    sbuf b = { 0 };
    int r = -1;
    if (vformat(&b, fmt, ap) == 0 && !too_long(b.len) && fwrite(b.p, 1, b.len, fp) == b.len)
        r = (int)b.len;
    free(b.p);
    return r;
}

static int b_vasprintf(char **out, const char *fmt, va_list ap) {
    if (needs_quad(fmt) <= 0) return vasprintf(out, fmt, ap);
    sbuf b = { 0 };
    if (vformat(&b, fmt, ap) != 0 || too_long(b.len)) { free(b.p); *out = NULL; return -1; }
    *out = b.p;
    return (int)b.len;
}

/* ---------------------------------------------------------------- shims --- */

static int b_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap) {
    return shim_vsnprintf(buf, n, fmt, ap);
}
static int b_vsprintf(char *buf, const char *fmt, va_list ap) {
    return shim_vsnprintf(buf, (size_t)0x7fffffff, fmt, ap);
}
static int b_vprintf(const char *fmt, va_list ap) { return shim_vfprintf(stdout, fmt, ap); }

#define VARIADIC(call) ({ va_list ap; va_start(ap, fmt); int r_ = (call); va_end(ap); r_; })
static int b_printf(const char *fmt, ...) { return VARIADIC(shim_vfprintf(stdout, fmt, ap)); }
static int b_snprintf(char *buf, size_t n, const char *fmt, ...) {
    return VARIADIC(shim_vsnprintf(buf, n, fmt, ap));
}
static int b_sprintf(char *buf, const char *fmt, ...) { return VARIADIC(b_vsprintf(buf, fmt, ap)); }
static int b_asprintf(char **out, const char *fmt, ...) { return VARIADIC(b_vasprintf(out, fmt, ap)); }

// bionic FORTIFY: (buf, supplied size, flags, compiler-known size, fmt, ap)
static int b___vsnprintf_chk(char *buf, size_t n, int flags, size_t dst_len,
                             const char *fmt, va_list ap) {
    (void)flags;
    if (n > dst_len)
        shim_fortify_fail("vsnprintf: prevented %zu-byte write into %zu-byte buffer", n, dst_len);
    return shim_vsnprintf(buf, n, fmt, ap);
}
static int b___vsprintf_chk(char *buf, int flags, size_t dst_len, const char *fmt, va_list ap) {
    (void)flags;
    int r = shim_vsnprintf(buf, dst_len, fmt, ap);
    if (r >= 0 && (size_t)r >= dst_len)
        shim_fortify_fail("vsprintf: prevented %d-byte write into %zu-byte buffer", r + 1, dst_len);
    return r;
}

static void b_syslog(int prio, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    shim_vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    syslog(prio, "%s", buf);
}

const shim_entry shims_printf[] = {
    SHIM(printf), SHIM(vprintf), SHIM(snprintf), SHIM(vsnprintf), SHIM(sprintf), SHIM(vsprintf),
    SHIM(asprintf), SHIM(vasprintf), SHIM(__vsnprintf_chk), SHIM(__vsprintf_chk), SHIM(syslog),
    { NULL, NULL }
};
