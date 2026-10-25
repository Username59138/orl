#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -u
BIN=./build/orl-run
fail=0

for lib in build/testlib_rela.so build/testlib_relr.so build/testlib_aps2.so; do
    echo "== $lib"
    if $BIN "$lib" test_entry "hi there" >/tmp/out.$$ 2>&1 && grep -q "returned 0" /tmp/out.$$; then
        echo "   run: ok"
    else
        echo "   run: FAIL"; cat /tmp/out.$$; fail=1
    fi
    # trap stub must fire with the symbol's name and abort
    $BIN "$lib" test_entry "!" >/tmp/out.$$ 2>&1
    if grep -q "unimplemented symbol 'definitely_not_implemented'" /tmp/out.$$; then
        echo "   trap: ok"
    else
        echo "   trap: FAIL"; cat /tmp/out.$$; fail=1
    fi
done
rm -f /tmp/out.$$
[ $fail = 0 ] && echo "all tests passed"
exit $fail
