// SPDX-License-Identifier: GPL-3.0-or-later
// stdio. FILE is opaque to Android code, so glibc streams can be handed out
// as they are, with one exception: code built against pre-M headers names
// the standard streams &__sF[0..2], an array of bionic's struct __sFILE
// (152 bytes on LP64; libroblox computes stderr as __sF + 0x130).
// We export a dummy array and translate those addresses back to glibc's
// streams in every FILE* function the client imports.

#define _GNU_SOURCE
#include "shims.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define B_SFILE_SIZE 152
static unsigned char b___sF[3 * B_SFILE_SIZE] __attribute__((aligned(16)));

static FILE *F(FILE *fp) {
    uintptr_t off = (uintptr_t)fp - (uintptr_t)b___sF;
    if (off >= sizeof b___sF) return fp;
    switch (off / B_SFILE_SIZE) {
    case 0:  return stdin;
    case 1:  return stdout;
    default: return stderr;
    }
}

static int b_fclose(FILE *fp) { return fclose(F(fp)); }
static int b_fflush(FILE *fp) { return fflush(fp ? F(fp) : NULL); }
static int b_feof(FILE *fp) { return feof(F(fp)); }
static int b_ferror(FILE *fp) { return ferror(F(fp)); }
static void b_clearerr(FILE *fp) { clearerr(F(fp)); }
static int b_fileno(FILE *fp) { return fileno(F(fp)); }
static int b_setvbuf(FILE *fp, char *buf, int mode, size_t size) { return setvbuf(F(fp), buf, mode, size); }

static int b_fseek(FILE *fp, long off, int whence) { return fseek(F(fp), off, whence); }
static int b_fseeko(FILE *fp, off_t off, int whence) { return fseeko(F(fp), off, whence); }
static long b_ftell(FILE *fp) { return ftell(F(fp)); }
static off_t b_ftello(FILE *fp) { return ftello(F(fp)); }

static size_t b_fread(void *buf, size_t size, size_t n, FILE *fp) { return fread(buf, size, n, F(fp)); }
static size_t b_fwrite(const void *buf, size_t size, size_t n, FILE *fp) { return fwrite(buf, size, n, F(fp)); }
static int b_getc(FILE *fp) { return getc(F(fp)); }
static int b_ungetc(int c, FILE *fp) { return ungetc(c, F(fp)); }
static char *b_fgets(char *s, int n, FILE *fp) { return fgets(s, n, F(fp)); }
static int b_fputc(int c, FILE *fp) { return fputc(c, F(fp)); }
static int b_fputs(const char *s, FILE *fp) { return fputs(s, F(fp)); }
static wint_t b_getwc(FILE *fp) { return getwc(F(fp)); }
static wint_t b_ungetwc(wint_t c, FILE *fp) { return ungetwc(c, F(fp)); }
static wint_t b_fputwc(wchar_t c, FILE *fp) { return fputwc(c, F(fp)); }

static int b_vfprintf(FILE *fp, const char *fmt, va_list ap) { return shim_vfprintf(F(fp), fmt, ap); }
static int b_fprintf(FILE *fp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = shim_vfprintf(F(fp), fmt, ap);
    va_end(ap);
    return r;
}
static int b_fscanf(FILE *fp, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int r = vfscanf(F(fp), fmt, ap);
    va_end(ap);
    return r;
}

// bionic's argument order: (buf, size, count, stream, buf_size).
// glibc's __fread_chk is (buf, buf_size, size, count, stream), so no fallback.
static size_t b___fread_chk(void *buf, size_t size, size_t n, FILE *fp, size_t buf_size) {
    size_t total;
    if (!__builtin_mul_overflow(size, n, &total) && total > buf_size)
        shim_fortify_fail("fread: prevented %zu-byte write into %zu-byte buffer", total, buf_size);
    return fread(buf, size, n, F(fp));
}
static size_t b___fwrite_chk(const void *buf, size_t size, size_t n, FILE *fp, size_t buf_size) {
    size_t total;
    if (!__builtin_mul_overflow(size, n, &total) && total > buf_size)
        shim_fortify_fail("fwrite: prevented %zu-byte read from %zu-byte buffer", total, buf_size);
    return fwrite(buf, size, n, F(fp));
}

const shim_entry shims_stdio[] = {
    { "__sF", b___sF },
    SHIM(fclose), SHIM(fflush), SHIM(feof), SHIM(ferror), SHIM(clearerr), SHIM(fileno),
    SHIM(setvbuf), SHIM(fseek), SHIM(fseeko), SHIM(ftell), SHIM(ftello),
    SHIM(fread), SHIM(fwrite), SHIM(getc), SHIM(ungetc), SHIM(fgets), SHIM(fputc), SHIM(fputs),
    SHIM(getwc), SHIM(ungetwc), SHIM(fputwc),
    SHIM(vfprintf), SHIM(fprintf), SHIM(fscanf),
    SHIM(__fread_chk), SHIM(__fwrite_chk),
    { NULL, NULL }
};
