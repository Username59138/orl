// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Returns our replacement for a bionic/Android symbol, or NULL if we have none.
void *shim_lookup(const char *name);
