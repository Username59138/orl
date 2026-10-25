#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Extract x86_64 native libraries from an APK, or from a split bundle
# (.xapk / .apks / .apkm containing base.apk + config.x86_64.apk).
#
#   tools/extract-apk.sh <file> [outdir]      (default outdir: ./apk-libs)
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <apk|xapk|apks> [outdir]" >&2; exit 2; }
in=$1
out=${2:-apk-libs}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$out"

extract_libs() { unzip -qo "$1" 'lib/x86_64/*' -d "$tmp/x" 2>/dev/null || true; }

extract_libs "$in"
# split bundle: look inside for nested APKs
if [ ! -d "$tmp/x/lib/x86_64" ]; then
    unzip -qo "$in" '*.apk' -d "$tmp/split" 2>/dev/null || true
    for apk in "$tmp"/split/*.apk; do
        [ -e "$apk" ] && extract_libs "$apk"
    done
fi

if [ ! -d "$tmp/x/lib/x86_64" ]; then
    echo "no lib/x86_64 found - this APK only ships ARM libraries." >&2
    echo "Get the x86_64 build (or the bundle that contains config.x86_64.apk)." >&2
    exit 1
fi
cp "$tmp"/x/lib/x86_64/*.so "$out"/
echo "extracted to $out:"
ls -la "$out"
