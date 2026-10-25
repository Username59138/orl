// SPDX-License-Identifier: GPL-3.0-or-later
// orl-run: load an Android x86_64 .so and either report its imports
// or call an exported `int fn(const char *)` entry point.

#include "loader.h"
#include "shims.h"

#include <stdio.h>
#include <string.h>

static void usage(void) {
    fprintf(stderr,
        "usage: orl-run [-v] --imports <lib.so>\n"
        "       orl-run [-v] <lib.so> <entry> [arg]\n"
        "\n"
        "  --imports  list every imported symbol and how it was resolved\n"
        "             (shim / host / weak-null / MISSING / BLOCKED),\n"
        "             without running any code\n"
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

    shims_init();
    so_module *m = so_load(argv[i], flags);
    if (!m) return 1;
    so_stats st = so_get_stats(m);

    if (report) {
        printf("\nsummary: %d shim, %d host, %d weak-null, %d MISSING, %d BLOCKED, "
               "%d unsupported relocs\n", st.shim, st.host, st.weak, st.missing, st.blocked,
               st.unsupported_relocs);
        return st.missing || st.blocked ? 3 : 0;
    }

    so_run_init(m);
    const char *entry = argv[i + 1];
    int (*fn)(const char *) = (int (*)(const char *))so_sym(m, entry);
    if (!fn) { fprintf(stderr, "symbol '%s' not exported\n", entry); return 1; }
    int r = fn(i + 2 < argc ? argv[i + 2] : "");
    printf("%s returned %d\n", entry, r);
    return r;
}
