// SPDX-License-Identifier: GPL-3.0-or-later
// OpenRoLauncher - minimal ELF loader for Android (bionic) x86_64 shared objects.
#pragma once
#include <stddef.h>

typedef struct so_module so_module;

enum {
    SO_VERBOSE      = 1 << 0, // log mapping / relocation details
    SO_REPORT       = 1 << 1, // print how every imported symbol was resolved
};

// Map the library, apply relocations, bind imports. Does NOT run constructors.
so_module *so_load(const char *path, int flags);

// Run DT_INIT and DT_INIT_ARRAY (C++ static constructors etc.).
void so_run_init(so_module *m);

// Look up an exported symbol of the loaded library.
void *so_sym(so_module *m, const char *name);

// Counters from the import binding pass.
typedef struct {
    int shim, host, missing, unsupported_relocs;
} so_stats;
so_stats so_get_stats(so_module *m);
