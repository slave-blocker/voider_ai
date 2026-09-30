#!/bin/sh
set -eu

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
usage(){ die "usage: $0 voider-aarch64.img[.gz] /dev/TARGET [--ssh-key PUBLIC_KEY] [--readback]"; }
[ "$#" -ge 2 ] || usage
IMAGE=$1
TARGET=$2
shift 2
SSH_KEY=
READBACK=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --ssh-key) [ "$#" -ge 2 ] || usage; SSH_KEY=$2; shift 2;;
        --readback) READBACK=1; shift;;
        *) usage;;
    esac
done

META="$IMAGE.meta"
SUM="$IMAGE.sha256"
for c in python3 sha256sum ssh-keygen lsblk findmnt blockdev dd awk grep mount umount mountpoint partprobe readlink cmp cp stat; do need "$c"; done
[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$IMAGE" ] || die "image missing: $IMAGE"
[ -f "$META" ] || die "metadata missing: $META"
[ -f "$SUM" ] || die "checksum missing: $SUM"
[ -b "$TARGET" ] || die "target is not a block device: $TARGET"
TARGET=$(readlink -f "$TARGET")
[ -b "$TARGET" ] || die "target did not resolve to a block device"
[ "$(lsblk -ndo TYPE "$TARGET")" = disk ] || die "target must be a whole disk, not a partition"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/var/tmp}/voider-flash.XXXXXX")
cleanup(){
    rc=$?; trap - EXIT; set +e
    if mountpoint -q "$WORK/boot"; then
        umount "$WORK/boot" || exit 1
    fi
    rm -rf "$WORK"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
# Fully validate and materialize a bounded source before any destructive action.
# No gzip pipeline can mask a decompression failure or overrun the agreed image.
python3 "$SCRIPT_DIR/check-release-image.py" "$IMAGE" --extract "$WORK/image.raw"
# Use only the private, verified staging file from this point onward.
EXPECTED_BYTES=$(stat -c %s "$WORK/image.raw")
RAW_SHA=$(sha256sum "$WORK/image.raw" | awk '{print $1}')

if [ -n "$SSH_KEY" ]; then
    [ -f "$SSH_KEY" ] && [ ! -L "$SSH_KEY" ] || die "SSH public key must be a regular, non-symlink file"
    [ "$(awk 'NF && $1 !~ /^#/ {n++} END {print n+0}' "$SSH_KEY")" -eq 1 ] || die "SSH key file must contain exactly one public key"
    key_type=$(awk 'NF && $1 !~ /^#/ {print $1}' "$SSH_KEY")
    case "$key_type" in ssh-ed25519|sk-ssh-ed25519@openssh.com|ecdsa-sha2-nistp256|sk-ecdsa-sha2-nistp256@openssh.com|ssh-rsa) ;; *) die "unsupported SSH public key type: $key_type";; esac
    key_info=$(ssh-keygen -lf "$SSH_KEY") || die "invalid SSH public key"
    if [ "$key_type" = ssh-rsa ]; then
        bits=$(printf '%s\n' "$key_info" | awk '{print $1}')
        [ "$bits" -ge 3072 ] || die "RSA installation keys must be at least 3072 bits"
    fi
    SSH_KEY=$(readlink -f "$SSH_KEY")
fi

TARGET_BYTES=$(blockdev --getsize64 "$TARGET")
python3 - "$TARGET_BYTES" "$EXPECTED_BYTES" <<'PY'
import sys
a,b=sys.argv[1:]
if not a.isascii() or not a.isdecimal() or len(a)>20 or not int(b)<=int(a)<=2**64-1:
    sys.exit('ERROR: invalid or insufficient target capacity')
PY
[ "$(blockdev --getss "$TARGET")" = 512 ] || die "target must use 512-byte logical sectors"
# Protect the running OS, source, selected key and staging storage, including
# ancestors behind device-mapper/LVM. Refuse ambiguous source-device discovery.
protect_path(){
    source=$(findmnt -n -o SOURCE -T "$1") || die "cannot identify filesystem for $1"
    source=${source%%\[*}
    [ -b "$source" ] || die "cannot safely identify backing block device for $1"
    parents=$(lsblk -snrpo NAME "$source") || die "cannot identify disk ancestors for $1"
    if printf '%s\n' "$parents" | grep -Fxq "$TARGET"; then die "target contains protected path: $1"; fi
}
for path in / /boot /boot/efi /home "$IMAGE" "$WORK" "$SCRIPT_DIR"; do [ ! -e "$path" ] || protect_path "$path"; done
[ -z "$SSH_KEY" ] || protect_path "$SSH_KEY"
if lsblk -nrpo TYPE "$TARGET" | grep -Evq '^(disk|part)$'; then die "target has active mapped devices"; fi
if lsblk -nrpo MOUNTPOINT "$TARGET" | grep -Fq '[SWAP]'; then die "target has active swap"; fi

echo "Validated source image and v3 partition metadata: $IMAGE"
lsblk -d -o NAME,SIZE,MODEL,SERIAL,TRAN,TYPE "$TARGET"
lsblk -o NAME,MOUNTPOINTS "$TARGET"
echo "Target capacity: $TARGET_BYTES bytes"
if [ -n "$SSH_KEY" ]; then echo "Initial management SSH key: $(ssh-keygen -lf "$SSH_KEY")";else echo "Initial management SSH: off (no SSH listener will start)";fi
[ "$READBACK" -eq 0 ] || echo "Readback: all 897 MiB, including MBR, BOOT, SYSTEM and STATE"
echo "This will overwrite exactly: $TARGET"
printf 'Type FLASH %s to continue: ' "$TARGET"
IFS= read -r answer
[ "$answer" = "FLASH $TARGET" ] || die "confirmation did not match; nothing was written"

# Unmount only this confirmed disk's children, deepest first; never force/lazy.
for node in $(lsblk -nrpo NAME "$TARGET" | awk '{a[NR]=$0} END {for(i=NR;i>0;i--)print a[i]}'); do
    while findmnt -rn -S "$node" >/dev/null; do umount -- "$node" || die "cannot safely unmount $node"; done
done
if lsblk -nrpo MOUNTPOINT "$TARGET" | grep -q '[^[:space:]]'; then die "target still in use"; fi
dd if="$WORK/image.raw" of="$TARGET" bs=4M iflag=fullblock oflag=direct conv=fsync
sync
partprobe "$TARGET" 2>/dev/null || true
blockdev --rereadpt "$TARGET" 2>/dev/null || true

if [ "$READBACK" -eq 1 ]; then
    blockdev --flushbufs "$TARGET"
    actual=$({
        if dd if="$TARGET" iflag=direct,count_bytes count="$EXPECTED_BYTES" bs=4M status=none; then
            echo 0 > "$WORK/readback.rc"
        else echo 1 > "$WORK/readback.rc"; fi
    } | sha256sum | awk '{print $1}')
    [ "$(cat "$WORK/readback.rc")" = 0 ] || die "readback I/O failed"
    [ "$actual" = "$RAW_SHA" ] || die "whole-image readback mismatch"
    echo "Verified all $EXPECTED_BYTES bytes: $actual"
fi

if [ -n "$SSH_KEY" ]; then
    case "$TARGET" in *[0-9]) BOOT_PART="${TARGET}p1";; *) BOOT_PART="${TARGET}1";; esac
    i=0;while [ ! -b "$BOOT_PART" ] && [ "$i" -lt 20 ]; do sleep 1;partprobe "$TARGET" 2>/dev/null || true;i=$((i+1));done
    [ -b "$BOOT_PART" ] || die "BOOT partition node did not appear: $BOOT_PART"
    [ "$(blockdev --getsize64 "$BOOT_PART")" = 134217728 ] &&
        [ "$(lsblk -dnro START "$BOOT_PART")" = 2048 ] || die "kernel BOOT partition mapping is stale"
    mkdir "$WORK/boot"
    mount -o rw,nosuid,nodev,noexec "$BOOT_PART" "$WORK/boot"
    cp "$SSH_KEY" "$WORK/boot/voider-authorized_keys"
    sync
    cmp -s "$SSH_KEY" "$WORK/boot/voider-authorized_keys" || die "injected SSH key did not verify"
    umount "$WORK/boot"
    echo "User-selected installation key injected into target BOOT only."
fi

echo "Flash complete. The distributable source image was not modified."
echo "Boot with wired Ethernet and the supported display attached, then hold INSTALL."
