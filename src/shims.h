// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// One table per area (shims_*.c), each terminated by { NULL, NULL }.
// `addr` is a function or, for data symbols like __sF, a variable.
typedef struct { const char *name; void *addr; } shim_entry;
#define SHIM(name) { #name, (void *)b_##name }

extern const shim_entry shims_core[], shims_stdio[], shims_signal[],
                        shims_net[], shims_sys[], shims_dl[];

// Call once before loading anything.
void shims_init(void);

// Returns our replacement for a bionic/Android symbol, or NULL if we have none.
void *shim_lookup(const char *name);

// True if the host libc has this symbol but its ABI differs from bionic's,
// so falling back to it would silently corrupt memory.
int shim_host_blocked(const char *name);

// Full lookup as the library would see it: shim, else host unless blocked.
void *shim_resolve(const char *name);

// bionic-style FORTIFY failure: print and abort.
__attribute__((noreturn, format(printf, 1, 2)))
void shim_fortify_fail(const char *fmt, ...);
