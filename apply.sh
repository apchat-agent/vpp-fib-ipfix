#!/bin/sh
# Apply the core patch and copy the plugin + test into a VPP tree.
# Usage: ./apply.sh /path/to/vpp
set -e
VPP=${1:?usage: $0 /path/to/vpp}
HERE=$(cd "$(dirname "$0")" && pwd)
test -f "$VPP/src/vnet/fib/fib_entry_src.c" || { echo "not a VPP tree: $VPP" >&2; exit 1; }
git -C "$VPP" apply --check "$HERE"/patches/*.patch
git -C "$VPP" apply "$HERE"/patches/*.patch
cp -r "$HERE/src/plugins/fibipfix" "$VPP/src/plugins/"
cp "$HERE/test/test_fibipfix.py" "$VPP/test/"
echo "applied; build VPP as usual, then: make test-debug TEST=test_fibipfix"
