// SPDX-License-Identifier: GPL-3.0-or-later
// clearhead-run: load an Android x86_64 .so and either report its imports
// or call an exported `int fn(const char *)` entry point.

#include "loader.h"

#include <stdio.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr,
        "usage: clearhead-run [-v] --imports <lib.so>\n"
        "       clearhead-run [-v] <lib.so> <entry> [arg]\n"
        "\n"
        "  --imports  list every imported symbol and how it was resolved\n"
        "             (shim / host / MISSING), without running any code\n"
        "  -v         verbose loader output\n");
}

int main(int argc, char **argv) {
    int flags = 0, report = 0, i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-v")) flags |= SO_VERBOSE;
        else if (!strcmp(argv[i], "--imports")) report = 1;
        else { usage(); return 2; }
    }
    if (i >= argc || (!report && i + 1 >= argc)) { usage(); return 2; }
    if (report) flags |= SO_REPORT;

    so_module *m = so_load(argv[i], flags);
    if (!m) return 1;
    so_stats st = so_get_stats(m);

    if (report) {
        printf("\nsummary: %d shim, %d host, %d MISSING, %d unsupported relocs\n",
               st.shim, st.host, st.missing, st.unsupported_relocs);
        return st.missing ? 3 : 0;
    }

    so_run_init(m);
    const char *entry = argv[i + 1];
    int (*fn)(const char *) = (int (*)(const char *))so_sym(m, entry);
    if (!fn) { fprintf(stderr, "symbol '%s' not exported\n", entry); return 1; }
    int r = fn(i + 2 < argc ? argv[i + 2] : "");
    printf("%s returned %d\n", entry, r);
    return r;
}
