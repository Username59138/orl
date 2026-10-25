// SPDX-License-Identifier: GPL-3.0-or-later
// The dynamic linker interface. glibc doesn't know about libraries we map
// ourselves, so these have to consult our module registry first:
//   dl_iterate_phdr  - the NDK unwinder finds .eh_frame through it; without
//                      our modules, every C++ exception ends in terminate();
//   dladdr           - backtraces, crash reporters;
//   dlopen/dlsym     - Android system libraries are what shims + host libc
//                      provide (like DT_NEEDED), app libraries are our
//                      modules. Nothing else gets loaded behind our back.
// struct dl_phdr_info and Dl_info have the same layout in both libcs, and so
// do the RTLD_* constants on LP64.

#define _GNU_SOURCE
#include "shims.h"
#include "loader.h"

#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Handle for "a system library": symbols come from shims / host libc.
static char system_handle;

static const char *const system_libs[] = {
    "libc.so", "libm.so", "libdl.so", "liblog.so", "libandroid.so", "libc++.so",
    "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so", "libvulkan.so",
    "libOpenSLES.so", "libaaudio.so", "libmediandk.so", "libOpenMAXAL.so",
    "libnativewindow.so", "libjnigraphics.so", "libsync.so",
};

static __thread const char *dl_error;
static __thread char dl_error_buf[256];

static void set_error(const char *fmt, const char *arg) {
    snprintf(dl_error_buf, sizeof dl_error_buf, fmt, arg);
    dl_error = dl_error_buf;
}

static int is_module(void *h) {
    for (so_module *m = so_next(NULL); m; m = so_next(m))
        if ((void *)m == h) return 1;
    return 0;
}

static void trace(const char *what, const char *name, const void *result) {
    if (getenv("ORL_TRACE")) fprintf(stderr, "[shim] %s(%s) = %p\n", what, name, result);
}

static void *b_dlopen(const char *name, int flags) {
    void *h;
    if (!name) {
        h = &system_handle; // the main program: global lookup
    } else if ((h = so_find_name(name))) {
        // one of ours
    } else {
        const char *base = strrchr(name, '/') ? strrchr(name, '/') + 1 : name;
        h = NULL;
        for (size_t i = 0; i < sizeof system_libs / sizeof system_libs[0]; i++)
            if (strcmp(base, system_libs[i]) == 0) h = &system_handle;
        if (!h) set_error("dlopen failed: library \"%s\" not found", name);
    }
    (void)flags;
    trace("dlopen", name ? name : "NULL", h);
    return h;
}

static void *b_dlsym(void *h, const char *name) {
    void *p = NULL;
    if (is_module(h)) {
        p = so_sym(h, name);
    } else if (h == RTLD_DEFAULT || h == RTLD_NEXT || h == &system_handle) {
        p = shim_resolve(name);
        for (so_module *m = so_next(NULL); !p && m; m = so_next(m)) p = so_sym(m, name);
    } else {
        p = dlsym(h, name);
    }
    if (!p) set_error("undefined symbol: %s", name);
    trace("dlsym", name, p);
    return p;
}

static int b_dlclose(void *h) {
    if (h == &system_handle || is_module(h)) return 0; // never unloaded
    return dlclose(h);
}

static char *b_dlerror(void) {
    const char *e = dl_error;
    if (!e) return dlerror();
    dl_error = NULL;
    return (char *)e;
}

static int b_dladdr(const void *addr, Dl_info *info) {
    so_module *m = so_find_addr(addr);
    if (!m) return dladdr(addr, info);
    info->dli_fname = so_path(m);
    info->dli_fbase = so_base(m);
    if (!so_addr_sym(m, addr, &info->dli_sname, &info->dli_saddr)) {
        info->dli_sname = NULL;
        info->dli_saddr = NULL;
    }
    return 1;
}

static int b_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    for (so_module *m = so_next(NULL); m; m = so_next(m)) {
        int phnum;
        struct dl_phdr_info info = {
            .dlpi_addr = so_bias(m),
            .dlpi_name = so_path(m),
            .dlpi_phdr = so_phdr(m, &phnum),
        };
        info.dlpi_phnum = (ElfW(Half))phnum;
        int r = cb(&info, sizeof info, data);
        if (r) return r;
    }
    return dl_iterate_phdr(cb, data);
}

const shim_entry shims_dl[] = {
    SHIM(dlopen), SHIM(dlsym), SHIM(dlclose), SHIM(dlerror), SHIM(dladdr),
    SHIM(dl_iterate_phdr),
    { NULL, NULL }
};
