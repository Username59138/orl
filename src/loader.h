// SPDX-License-Identifier: GPL-3.0-or-later
// OpenRoLauncher - minimal ELF loader for Android (bionic) x86_64 shared objects.
#pragma once
#include <stddef.h>
#include <stdint.h>

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
    int shim, host, weak, missing, blocked, unsupported_relocs;
} so_stats;
so_stats so_get_stats(so_module *m);

// Registry of loaded modules, for the dl* shims.
so_module *so_next(so_module *prev);           // NULL -> first module
so_module *so_find_addr(const void *addr);     // module whose mapping contains addr
so_module *so_find_name(const char *name);     // by file name, ignoring directories
const char *so_path(so_module *m);
void *so_base(so_module *m);                   // start of the mapping
uintptr_t so_bias(so_module *m);               // runtime address = bias + p_vaddr
const void *so_phdr(so_module *m, int *phnum); // Elf64_Phdr array
// Nearest exported symbol at or below addr; 0 if none covers it.
int so_addr_sym(so_module *m, const void *addr, const char **name, void **sym_addr);
