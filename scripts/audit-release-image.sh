#!/bin/sh
set -eu
image=$1
source_tree=$2
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: run audit as root in a private mount namespace' >&2; exit 1; }
mkdir -p "$source_tree/image-work" "$source_tree/output"
work=$(mktemp -d "$source_tree/image-work/audit.XXXXXX")
loop=
cleanup() {
    rc=$?
    trap - EXIT
    set +e
    for part in boot system state; do
        if mountpoint -q "$work/$part"; then umount "$work/$part" || exit 1; fi
    done
    [ -z "$loop" ] || losetup -d "$loop"
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || { echo "ERROR: use unshare -m for audit" >&2; exit 1; }
mount --make-rprivate /
python3 "$source_tree/scripts/check-release-image.py" "$image" --extract "$work/image.raw"
loop=$(losetup --find --show --read-only --partscan "$work/image.raw")
[ "$(lsblk -ndo TYPE "$loop")" = loop ]
[ "$(readlink -f "$(losetup -n -O BACK-FILE "$loop")")" = "$work/image.raw" ]
for n in 1 2 3; do
    i=0
    while [ ! -b "${loop}p$n" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i+1)); done
    [ -b "${loop}p$n" ]
done
[ "$(blkid -s LABEL -o value "${loop}p1")" = BOOT ]
[ "$(blkid -s LABEL -o value "${loop}p2")" = SYSTEM ]
[ "$(blkid -s LABEL -o value "${loop}p3")" = STATE ]
[ "$(blkid -s UUID -o value "${loop}p1")" = 564F-4944 ]
[ "$(blkid -s UUID -o value "${loop}p2")" = 11111111-1111-4111-8111-111111111111 ]
[ "$(blkid -s UUID -o value "${loop}p3")" = 22222222-2222-4222-8222-222222222222 ]
sfdisk --verify "$loop"
sfdisk --dump "$loop"
fsck.vfat -n "${loop}p1"
e2fsck -fn "${loop}p2"
e2fsck -fn "${loop}p3"
mkdir "$work/boot" "$work/system" "$work/state"
mount -o ro,nosuid,nodev,noexec "${loop}p1" "$work/boot"
mount -o ro,noload,nosuid,nodev,noexec "${loop}p2" "$work/system"
mount -o ro,noload,nosuid,nodev,noexec "${loop}p3" "$work/state"
python3 "$source_tree/scripts/check-release-image.py" --space "$work/boot" "$work/system" "$work/state"
python3 - "$work" "$source_tree" <<'PY'
from pathlib import Path
import hashlib,re,struct,sys
work,src=map(Path,sys.argv[1:]); root=work/'system'; boot=work/'boot'; state=work/'state'; payload=root/'opt/voider-installer'
def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(1024*1024): h.update(b)
    return h.hexdigest()
manifest={}
for line in (payload/'MANIFEST.sha256').read_text().splitlines():
    sha,path=line.split('  ',1); assert path.startswith('./') and '..' not in Path(path).parts
    manifest[path[2:]]=sha
actual={str(p.relative_to(payload)) for p in payload.rglob('*') if p.is_file() and p.name!='MANIFEST.sha256'}
assert actual==manifest.keys()
for path,sha in manifest.items(): assert digest(payload/path)==sha,path
for name in (src/'config/release-binaries').read_text().split():
    p=payload/'build'/name
    assert digest(p)==digest(src/'build'/name),name
    with p.open('rb') as f: header=f.read(20)
    assert header[:4]==b'\x7fELF' and header[4:6]==b'\x02\x01' and struct.unpack_from('<H',header,18)[0]==183,name
for path in actual:
    if not path.startswith('build/') and path!='offline.ready': assert digest(payload/path)==digest(src/path),path
for script in ('voider-factory-bootstrap','voider-factory-dhcp'):
    assert digest(root/'usr/local/sbin'/script)==digest(src/'scripts'/script)
assert digest(root/'etc/init.d/voider-factory-bootstrap')==digest(src/'openrc/voider-factory-bootstrap')
assert (root/'etc/runlevels/default/voider-factory-bootstrap').is_symlink()
assert sorted(p.name for p in (root/'etc/runlevels/default').iterdir())==['voider-factory-bootstrap']
assert (root/'etc/hostname').read_text().strip()=='voider-unconfigured'
assert (root/'etc/machine-id').stat().st_size==0
assert not list((root/'etc/ssh').glob('ssh_host_*'))
for path in ('root/.ssh','home/dollner','.voider-dev','etc/voider/.installed','etc/voider/certs/admin_authorized_keys','etc/voider/private','var/lib/tor/hidden_service','etc/wireguard/wg0.conf'):
    assert not (root/path).exists(),path
assert not (boot/'voider-authorized_keys').exists()
assert all(p.is_dir() and p.name in ('lost+found','voider') for p in state.rglob('*'))
assert 'root=UUID=11111111-1111-4111-8111-111111111111' in (boot/'cmdline.txt').read_text()
assert 'dtoverlay=pitft28-resistive,rotate=270' in (boot/'usercfg.txt').read_text()
for name in ('vmlinuz-rpi','initramfs-rpi'): assert (boot/name).stat().st_size>0
interfaces=(root/'etc/network/interfaces').read_text()
assert 'auto eth0' not in interfaces and 'iface eth0 inet manual' in interfaces and 'gateway' not in interfaces
assert '172.16.19.86' in interfaces and '255.255.255.252' in interfaces
assert 'net.ipv6.conf.default.accept_ra=0' in (root/'etc/sysctl.d/90-voider-factory-lan.conf').read_text()
assert not (root/'etc/apk/repositories').read_text()
assert (root/'etc/resolv.conf').is_symlink()
(src/'output/image-package-db.txt').write_bytes((root/'lib/apk/db/installed').read_bytes())
# Factory STATE has no archive or identity until the physical installation.
# No log/cache/runtime/test-harness files are allowed in the distributable.
for path in ('var/log','var/cache','tmp','run','var/lib/tor','var/lib/chrony','root'):
    base=root/path
    unexpected=[str(p.relative_to(root)) for p in base.rglob('*')
                if p.is_file() and not p.is_symlink() and p.stat().st_size]
    assert not unexpected,unexpected
private_header=re.compile(rb'(?m)^-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{16,}\r?\n')
for base in (boot,root,state):
    for p in base.rglob('*'):
        if p.is_symlink() or not p.is_file(): continue
        rel=p.relative_to(base)
        assert not any(x in ('.voider-dev','.git','__pycache__','authorized_keys','known_hosts','random-seed','.ash_history','.bash_history') for x in rel.parts),rel
        assert not private_header.search(p.read_bytes()),f'private key material: {rel}'
# Also inspect unallocated bytes: deleting a generated secret would not erase it.
with (work/'image.raw').open('rb') as f:
    tail=b''
    while block:=f.read(1024*1024):
        block=tail+block
        assert not private_header.search(block),'private key material in raw image'
        tail=block[-4096:]
print('PASS no credentials, private keys, device identity, logs, caches or harness files')
print('PASS complete payload manifest, native ARM binaries, LAN-only factory setup, identity-clean BOOT/SYSTEM/STATE')
PY
echo IMAGE_AUDIT_OK
