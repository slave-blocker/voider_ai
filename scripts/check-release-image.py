#!/usr/bin/env python3
"""Read-only release size, MBR, metadata, digest and filesystem-margin checks."""
import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import struct
import sys

MIB = 1024 * 1024
PARTS = ('BOOT', 'SYSTEM', 'STATE')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, value = line.split('=', 1)
        require(key not in result, f'duplicate metadata: {key}')
        result[key] = value
    return result


def layout():
    data = fields(Path(__file__).resolve().parent.parent / 'config/release-layout')
    require(all(re.fullmatch(r'[1-9][0-9]{0,9}', v) for v in data.values()),
            'layout numbers must be canonical bounded decimal bytes')
    data = {k: int(v) for k, v in data.items()}
    require(data['IMAGE_BYTES'] == 897 * MIB, 'image must be exactly 897 MiB')
    end = MIB
    for name, size in zip(PARTS, (128, 512, 256)):
        start, length = data[name + '_OFFSET_BYTES'], data[name + '_SIZE_BYTES']
        require(start == end and start % MIB == 0 and length == size * MIB,
                f'{name}: invalid alignment, start or size')
        require(start <= data['IMAGE_BYTES'] and length <= data['IMAGE_BYTES'] - start,
                f'{name}: outside image')
        end = start + length
    require(end == data['IMAGE_BYTES'], 'unexpected image tail')
    return data


def metadata(path, sizes):
    meta = fields(path)
    require(meta.get('FORMAT') == 'voider-release-image-v3', 'requires v3 metadata')
    require(meta.get('ARCH') == 'aarch64', 'requires aarch64 image')
    require(meta.get('PARTITIONS') == 'BOOT-128MiB,SYSTEM-512MiB,STATE-256MiB',
            'partition description mismatch')
    for key, value in sizes.items():
        # Compare canonical strings before parsing: reject signs, overflow,
        # leading zeroes, duplicate fields and foreign layouts.
        require(meta.get(key) == str(value), f'metadata mismatch: {key}')
    for name in ('RAW', 'BOOT', 'SYSTEM', 'STATE', 'PAYLOAD'):
        require(re.fullmatch(r'[0-9a-f]{64}', meta.get(name + '_SHA256', '')),
                f'invalid {name} digest')
    return meta


def check_mbr(mbr, sizes):
    require(len(mbr) == 512 and mbr[510:] == b'\x55\xaa', 'invalid MBR signature')
    require(struct.unpack_from('<I', mbr, 440)[0] == 0x564f4944, 'invalid disk ID')
    for i, name in enumerate(PARTS):
        offset = 446 + 16 * i
        actual = (mbr[offset], mbr[offset + 4], *struct.unpack_from('<II', mbr, offset + 8))
        expected = (128 if i == 0 else 0, 12 if i == 0 else 131,
                    sizes[name + '_OFFSET_BYTES'] // 512, sizes[name + '_SIZE_BYTES'] // 512)
        require(actual == expected, f'{name}: partition-table mismatch')
    require(mbr[494:510] == bytes(16), 'unexpected fourth partition')


def digest_file(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(MIB), b''):
            h.update(chunk)
    return h.hexdigest()


def check_image(image, extract=None):
    image = Path(image)
    sizes = layout()
    meta = metadata(str(image) + '.meta', sizes)
    lines = Path(str(image) + '.sha256').read_text().splitlines()
    require(len(lines) == 1 and lines[0].endswith('  ' + image.name), 'invalid checksum sidecar')
    require(digest_file(image) == lines[0].split('  ', 1)[0], 'source checksum mismatch')
    hashes = {k: hashlib.sha256() for k in ('RAW',) + PARTS}
    position = 0
    output = open(extract, 'xb') if extract else None
    complete = False
    try:
        with (gzip.open(image, 'rb') if image.name.endswith('.gz') else image.open('rb')) as f:
            while chunk := f.read(MIB):
                require(len(chunk) <= sizes['IMAGE_BYTES'] - position, 'raw image exceeds exact size')
                if position == 0:
                    check_mbr(chunk[:512], sizes)
                hashes['RAW'].update(chunk)
                for name in PARTS:
                    start = sizes[name + '_OFFSET_BYTES']
                    a, b = max(position, start), min(position + len(chunk), start + sizes[name + '_SIZE_BYTES'])
                    if a < b:
                        hashes[name].update(chunk[a - position:b - position])
                if output:
                    output.write(chunk)
                position += len(chunk)
        require(position == sizes['IMAGE_BYTES'], 'raw image is truncated')
        for name, h in hashes.items():
            require(h.hexdigest() == meta[name + '_SHA256'], f'{name} checksum mismatch')
        complete = True
    finally:
        if output:
            output.close()
            if not complete:
                Path(extract).unlink()
    print(f'PASS exact {position} bytes, aligned MBR, v3 metadata, source/raw/all-partition SHA256')
    return meta


def check_space(paths):
    root = Path(paths[1])
    # Installation retains the offline payload and copies all release binaries
    # and scripts to SYSTEM. Account for allocated blocks and directory slack.
    payload = root / 'opt/voider-installer'
    copy_bytes = sum(p.lstat().st_blocks * 512 for p in payload.rglob('*')) + 4 * MIB
    for name, path, minimum in zip(PARTS, paths, (32 * MIB, 128 * MIB, 192 * MIB)):
        st = os.statvfs(path)
        total = st.f_blocks * st.f_frsize
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        available = st.f_bavail * st.f_frsize
        reserve = st.f_bfree * st.f_frsize - available
        allowance = copy_bytes if name == 'SYSTEM' else 0
        print(f'{name}: total={total} used={used} available={available} reserved={reserve} '
              f'inodes_used={st.f_files-st.f_ffree} inodes_free={st.f_ffree} '
              f'install_allowance={allowance} remaining_after_install={available-allowance}', flush=True)
        require(available >= allowance and available - allowance >= minimum,
                f'{name}: insufficient future headroom (requires {minimum} bytes after installation allowance)')
        require(not st.f_files or st.f_ffree >= (1024 if name == 'SYSTEM' else 32),
                f'{name}: insufficient free inodes')
    print('PASS filesystem margins: BOOT >=32 MiB, SYSTEM >=128 MiB after install copy, STATE >=192 MiB')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', nargs='?')
    parser.add_argument('--extract', help='create this raw file exclusively; remove it if validation fails')
    parser.add_argument('--layout-only', action='store_true')
    parser.add_argument('--space', nargs=3, metavar=('BOOT', 'SYSTEM', 'STATE'))
    args = parser.parse_args()
    if args.layout_only:
        layout()
        print('PASS fixed 897 MiB layout')
    elif args.space:
        check_space(args.space)
    else:
        require(args.image, 'image path required')
        check_image(args.image, args.extract)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, EOFError) as e:
        sys.exit(f'ERROR: {e}')
