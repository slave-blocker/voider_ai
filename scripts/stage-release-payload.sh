#!/bin/sh
set -eu

OUT=${1:-release/voider-installer-payload.tar.gz}
BUILD_DIR=${BUILD_DIR:-build}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
need tar
need sha256sum
need mktemp
need gzip
[ -d "$BUILD_DIR" ] || die "native build directory missing: $BUILD_DIR"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
[ ! -e "$OUT" ] || die "output already exists: $OUT"

BINS=$(cat config/release-binaries)
for x in $BINS; do
    [ -x "$BUILD_DIR/$x" ] || die "missing native binary: $BUILD_DIR/$x"
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
ROOT="$WORK/voider-installer"
mkdir -p "$ROOT/assets/fonts" "$ROOT/build" "$ROOT/config" "$ROOT/openrc" "$ROOT/scripts"

for x in $BINS; do cp -p "$BUILD_DIR/$x" "$ROOT/build/$x"; done
cp -p assets/fonts/OFL.txt "$ROOT/assets/fonts/OFL.txt"
cp -p config/voider.conf "$ROOT/config/voider.conf"
cp -p config/release-binaries "$ROOT/config/release-binaries"
cp -p config/release-services "$ROOT/config/release-services"
cp -p scripts/pitft-bridge "$ROOT/scripts/pitft-bridge"
cp -p scripts/voider-factory-bootstrap "$ROOT/scripts/voider-factory-bootstrap"
cp -p scripts/voider-factory-dhcp "$ROOT/scripts/voider-factory-dhcp"
for x in $(cat config/release-services) voider-factory-bootstrap 01-quiet-pitft-console.start; do
    cp -p "openrc/$x" "$ROOT/openrc/$x"
done

printf 'VOIDER_OFFLINE_PAYLOAD=1\n' > "$ROOT/offline.ready"
find "$ROOT" -type f -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(
    cd "$ROOT"
    find . -type f ! -name MANIFEST.sha256 -print | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256
)
mkdir -p "$(dirname "$OUT")"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
    -C "$WORK" -cf - voider-installer | gzip -9 > "$OUT"
(
    cd "$(dirname "$OUT")"
    sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256"
)
echo "Payload: $OUT"
cat "$OUT.sha256"
