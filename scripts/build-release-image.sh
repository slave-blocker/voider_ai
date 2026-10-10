#!/bin/sh
set -eu

PAYLOAD=${1:-release/voider-installer-payload.tar.gz}
OUT=${2:-release/voider-aarch64.img.gz}
# Fixed 897 MiB image; larger cards deliberately retain an unused tail.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$SCRIPT_DIR/../config/release-layout"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
ALPINE_BRANCH=${ALPINE_BRANCH:-v3.23}

die(){ echo "ERROR: $*" >&2; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
[ "$(id -u)" -eq 0 ] || die "run as root on an Alpine aarch64 builder"
[ "$(uname -m)" = aarch64 ] || die "the release image must be built natively on aarch64"
[ -f "$PAYLOAD" ] || die "payload missing: $PAYLOAD"
for path in "$OUT" "$OUT.sha256" "$OUT.meta"; do
    [ ! -e "$path" ] && [ ! -L "$path" ] || die "output already exists: $path"
done
for c in apk sfdisk losetup mkfs.vfat mkfs.ext4 mount umount tar sha256sum gzip truncate blkid python3 fsck.vfat e2fsck; do need "$c"; done
python3 "$SCRIPT_DIR/check-release-image.py" --layout-only

case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac
case "$PAYLOAD" in /*) ;; *) PAYLOAD="$PWD/$PAYLOAD" ;; esac
mkdir -p "$(dirname "$OUT")"
# Keep staging on the clone filesystem, not the RAM-backed /tmp.
WORK_BASE="$SCRIPT_DIR/../image-work"
mkdir -p "$WORK_BASE"
WORK=$(mktemp -d "$WORK_BASE/build.XXXXXX")
IMAGE="$WORK/voider-aarch64.img"
ROOT="$WORK/root"
LOOP=
complete=0
mounted_boot=0
mounted_root=0
mounted_state=0
refresh_devices(){
    [ "${VOIDER_BUILD_SKIP_MDEV:-0}" = 1 ] || mdev -s 2>/dev/null || true
}
cleanup(){
    rc=$?
    trap - EXIT
    set +e
    [ "$mounted_state" -eq 0 ] || umount "$ROOT/mnt/voider-state"
    [ "$mounted_boot" -eq 0 ] || umount "$ROOT/boot"
    [ "$mounted_root" -eq 0 ] || umount "$ROOT"
    [ -z "$LOOP" ] || losetup -d "$LOOP"
    rm -rf "$WORK"
    if [ "$complete" -eq 0 ]; then
        rm -f "$OUT" "$OUT.sha256" "$OUT.meta"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

truncate -s "$IMAGE_BYTES" "$IMAGE"
LOOP=$(losetup --find --show --partscan "$IMAGE")
[ "$(lsblk -ndo TYPE "$LOOP")" = loop ] || die "$LOOP is not a loop device"
BACK=$(losetup -n -O BACK-FILE "$LOOP" | sed -n '1p')
[ "$(readlink -f "$BACK")" = "$(readlink -f "$IMAGE")" ] || die "loop backing-file mismatch"

{
    printf 'label: dos\nlabel-id: 0x564f4944\nunit: sectors\nfirst-lba: 2048\n\n'
    printf 'start=%s, size=%s, type=c, bootable\n' "$((BOOT_OFFSET_BYTES/512))" "$((BOOT_SIZE_BYTES/512))"
    printf 'start=%s, size=%s, type=83\n' "$((SYSTEM_OFFSET_BYTES/512))" "$((SYSTEM_SIZE_BYTES/512))"
    printf 'start=%s, size=%s, type=83\n' "$((STATE_OFFSET_BYTES/512))" "$((STATE_SIZE_BYTES/512))"
} | sfdisk "$LOOP"
sfdisk --verify "$LOOP"
partprobe "$LOOP" 2>/dev/null || true
blockdev --rereadpt "$LOOP" 2>/dev/null || true
refresh_devices
for n in 1 2 3; do
    i=0
    while [ ! -b "${LOOP}p$n" ] && [ "$i" -lt 20 ]; do
        refresh_devices
        sleep 1
        i=$((i+1))
    done
    [ -b "${LOOP}p$n" ] || die "partition node ${LOOP}p$n did not appear"
done

mkfs.vfat --invariant -F 32 -i 564f4944 -n BOOT "${LOOP}p1"
E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -F -U 11111111-1111-4111-8111-111111111111 -L SYSTEM "${LOOP}p2"
E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -F -m 0 -T largefile4 \
    -U 22222222-2222-4222-8222-222222222222 -L STATE "${LOOP}p3"

mkdir -p "$ROOT"
mount "${LOOP}p2" "$ROOT"; mounted_root=1
mkdir -p "$ROOT/boot" "$ROOT/mnt/voider-state"
mount "${LOOP}p1" "$ROOT/boot"; mounted_boot=1
mount "${LOOP}p3" "$ROOT/mnt/voider-state"; mounted_state=1

mkdir -p "$ROOT/etc/apk/keys" "$ROOT/etc/apk"
cp -p /etc/apk/keys/*.rsa.pub "$ROOT/etc/apk/keys/"
REPOS="$WORK/repositories"
printf 'https://dl-cdn.alpinelinux.org/alpine/%s/main\nhttps://dl-cdn.alpinelinux.org/alpine/%s/community\n' \
    "$ALPINE_BRANCH" "$ALPINE_BRANCH" > "$REPOS"
cp "$REPOS" "$ROOT/etc/apk/repositories"

PACKAGES="alpine-base linux-rpi raspberrypi-bootloader linux-firmware-brcm linux-firmware-cypress \
ifupdown-ng iproute2 iptables ip6tables wireguard-tools tor tor-openrc openssh openssh-server-pam \
openssh-sftp-server conntrack-tools bridge-utils busybox busybox-extras netcat-openbsd wget curl \
openssl libstdc++ libnetfilter_queue libgpiod util-linux e2fsprogs dosfstools tar chrony"
apk --root "$ROOT" --arch aarch64 --initdb --keys-dir "$ROOT/etc/apk/keys" \
    --repositories-file "$REPOS" --no-cache --no-logfile add $PACKAGES

for service in devfs dmesg hwdrivers mdev; do
    chroot "$ROOT" rc-update add "$service" sysinit
done
for service in bootmisc hostname localmount modules networking seedrng sysctl syslog; do
    chroot "$ROOT" rc-update add "$service" boot
done
for service in killprocs mount-ro savecache; do
    chroot "$ROOT" rc-update add "$service" shutdown
done

mkdir -p "$ROOT/opt" "$ROOT/usr/local/bin" "$ROOT/usr/local/sbin" "$ROOT/etc/profile.d" "$ROOT/etc/network"
tar -xzf "$PAYLOAD" -C "$ROOT/opt"
(
    cd "$ROOT/opt/voider-installer"
    sha256sum -c MANIFEST.sha256
)
cat > "$ROOT/usr/local/bin/install" <<'EOF'
#!/bin/sh
set -eu
cd /opt/voider-installer
exec ./build/voider-install "$@"
EOF
chmod 755 "$ROOT/usr/local/bin/install"
cp -p "$ROOT/opt/voider-installer/scripts/voider-factory-bootstrap" "$ROOT/usr/local/sbin/voider-factory-bootstrap"
cp -p "$ROOT/opt/voider-installer/scripts/voider-factory-dhcp" "$ROOT/usr/local/sbin/voider-factory-dhcp"
cp -p "$ROOT/opt/voider-installer/openrc/voider-factory-bootstrap" "$ROOT/etc/init.d/voider-factory-bootstrap"
chmod 755 "$ROOT/usr/local/sbin/voider-factory-bootstrap" "$ROOT/usr/local/sbin/voider-factory-dhcp" "$ROOT/etc/init.d/voider-factory-bootstrap"
chroot "$ROOT" rc-update add voider-factory-bootstrap default
cat > "$ROOT/etc/profile.d/voider-install.sh" <<'EOF'
if [ ! -e /etc/voider/.installed ]; then
    echo
    echo 'VOIDER IS READY TO INSTALL'
    echo 'Run: install'
    echo
fi
EOF
cat > "$ROOT/etc/motd" <<'EOF'
VOIDER FACTORY IMAGE

A supported display and buttons are required. Hold INSTALL on the display.
If a public key was selected while flashing, restricted management SSH is
available before installation and remains available after the single reboot.
Setup is offline.
EOF
cat > "$ROOT/etc/hostname" <<'EOF'
voider-unconfigured
EOF
cat > "$ROOT/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback

# The factory bootstrap owns eth0 and its LAN-only DHCP handler.
iface eth0 inet manual

auto eth1
iface eth1 inet static
  address 172.16.19.86
  netmask 255.255.255.252
EOF
mkdir -p "$ROOT/etc/sysctl.d"
cat > "$ROOT/etc/sysctl.d/90-voider-factory-lan.conf" <<'EOF'
# Factory setup has IPv4 LAN management only; no learned IPv6 routes.
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.autoconf=0
net.ipv6.conf.default.autoconf=0
EOF
mkdir -p "$ROOT/etc/udhcpc"
printf 'RESOLV_CONF=/run/resolv.conf\n' > "$ROOT/etc/udhcpc/udhcpc.conf"
rm -f "$ROOT/etc/resolv.conf"
ln -s /run/resolv.conf "$ROOT/etc/resolv.conf"
cat > "$ROOT/etc/chrony/chrony.conf" <<'EOF'
# Voider: recover time after delayed DHCP/DNS on RTC-less hardware.
pool pool.ntp.org iburst
initstepslew 10 pool.ntp.org
makestep 10 5
driftfile /var/lib/chrony/chrony.drift
rtcsync
cmdport 0
EOF
cat > "$ROOT/etc/fstab" <<'EOF'
UUID=11111111-1111-4111-8111-111111111111 / ext4 rw,noatime 0 1
UUID=564F-4944 /boot vfat rw,noatime 0 2
UUID=22222222-2222-4222-8222-222222222222 /mnt/voider-state ext4 rw,noatime,nosuid,nodev 0 2
EOF
cat > "$ROOT/boot/config.txt" <<'EOF'
kernel=vmlinuz-rpi
initramfs initramfs-rpi
arm_64bit=1
include usercfg.txt
EOF
cat > "$ROOT/boot/cmdline.txt" <<'EOF'
root=UUID=11111111-1111-4111-8111-111111111111 modules=sd-mod,usb-storage,ext4 quiet rootfstype=ext4 rootwait
EOF
cat > "$ROOT/boot/usercfg.txt" <<'EOF'
# Loaded before installation so the mandatory supported HAT can provide setup.
dtparam=spi=on
dtoverlay=pitft28-resistive,rotate=270,speed=32000000,fps=20
EOF
: > "$ROOT/etc/machine-id"
find "$ROOT/etc/ssh" -maxdepth 1 -type f -name 'ssh_host_*_key*' -delete
chroot "$ROOT" passwd -d root >/dev/null
rm -rf "$ROOT/var/cache/apk"/* "$ROOT/tmp"/*
mkdir -p "$ROOT/mnt/voider-state/voider"
: > "$ROOT/etc/apk/repositories"

[ -f "$ROOT/boot/vmlinuz-rpi" ] || die "linux-rpi did not install vmlinuz-rpi"
[ -f "$ROOT/boot/initramfs-rpi" ] || die "linux-rpi did not install initramfs-rpi"
[ -x "$ROOT/opt/voider-installer/build/voider-install" ] || die "installer binary missing"
[ -x "$ROOT/usr/local/sbin/voider-factory-bootstrap" ] || die "factory bootstrap missing"
[ -x "$ROOT/usr/local/sbin/voider-factory-dhcp" ] || die "factory LAN-only DHCP handler missing"
[ ! -e "$ROOT/etc/ssh/ssh_host_ed25519_key" ] || die "factory image contains an SSH host private key"
[ ! -e "$ROOT/boot/voider-authorized_keys" ] || die "factory image contains an installation public key"
[ ! -e "$ROOT/etc/voider/certs/admin_authorized_keys" ] || die "factory image contains an admin public key"
[ ! -s "$ROOT/etc/machine-id" ] || die "factory image contains a machine identity"
for entry in \
    sysinit/devfs sysinit/dmesg sysinit/hwdrivers sysinit/mdev \
    boot/bootmisc boot/hostname boot/localmount boot/modules boot/networking \
    boot/seedrng boot/sysctl boot/syslog \
    shutdown/killprocs shutdown/mount-ro shutdown/savecache; do
    [ -L "$ROOT/etc/runlevels/$entry" ] || die "OpenRC runlevel entry missing: $entry"
done

find "$ROOT" -xdev -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
# Gate on available blocks (excluding reserved blocks), not nominal capacity.
python3 "$SCRIPT_DIR/check-release-image.py" --space "$ROOT/boot" "$ROOT" "$ROOT/mnt/voider-state"
sync
umount "$ROOT/mnt/voider-state"; mounted_state=0
umount "$ROOT/boot"; mounted_boot=0
umount "$ROOT"; mounted_root=0
e2fsck -pf "${LOOP}p2"
e2fsck -pf "${LOOP}p3"
fsck.vfat -n "${LOOP}p1"
BOOT_SHA256=$(sha256sum "${LOOP}p1" | awk '{print $1}')
SYSTEM_SHA256=$(sha256sum "${LOOP}p2" | awk '{print $1}')
STATE_SHA256=$(sha256sum "${LOOP}p3" | awk '{print $1}')
losetup -d "$LOOP"
LOOP=

[ "$(stat -c %s "$IMAGE")" = "$IMAGE_BYTES" ] || die "raw image size changed"
RAW_SHA256=$(sha256sum "$IMAGE" | awk '{print $1}')
gzip -n -1 < "$IMAGE" > "$OUT"
(
    cd "$(dirname "$OUT")"
    sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256"
)
cat > "$OUT.meta" <<EOF
FORMAT=voider-release-image-v3
ARCH=aarch64
IMAGE_BYTES=$IMAGE_BYTES
RAW_SHA256=$RAW_SHA256
PARTITIONS=BOOT-128MiB,SYSTEM-512MiB,STATE-256MiB
BOOT_OFFSET_BYTES=$BOOT_OFFSET_BYTES
BOOT_SIZE_BYTES=$BOOT_SIZE_BYTES
BOOT_SHA256=$BOOT_SHA256
SYSTEM_OFFSET_BYTES=$SYSTEM_OFFSET_BYTES
SYSTEM_SIZE_BYTES=$SYSTEM_SIZE_BYTES
SYSTEM_SHA256=$SYSTEM_SHA256
STATE_OFFSET_BYTES=$STATE_OFFSET_BYTES
STATE_SIZE_BYTES=$STATE_SIZE_BYTES
STATE_SHA256=$STATE_SHA256
PAYLOAD_SHA256=$(sha256sum "$PAYLOAD" | awk '{print $1}')
EOF
python3 "$SCRIPT_DIR/check-release-image.py" "$OUT"
complete=1
echo "Image: $OUT"
cat "$OUT.sha256"
