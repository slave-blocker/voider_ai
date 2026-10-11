#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo 'Run with doas on your Alpine aarch64 build Pi.' >&2; exit 1; }
[ "$(uname -m)" = aarch64 ] || { echo 'An aarch64 build Pi is required.' >&2; exit 1; }
python3 scripts/locked-packages.py fetch all
# Install only the selected signed versions; all their dependencies are locked.
python3 scripts/locked-packages.py install build
python3 scripts/locked-packages.py installed build
echo 'Build tools and offline image packages are ready.'
