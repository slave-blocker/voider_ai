#!/usr/bin/env python3
"""Fetch and verify the signed package versions selected for this source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'config/build-dependencies.json'


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fetch', 'verify', 'install', 'paths', 'installed', 'epoch', 'hash'))
    parser.add_argument('group', nargs='?', choices=('build', 'image', 'all'), default='all')
    parser.add_argument('--cache', type=Path, default=ROOT / 'image-work/packages')
    parser.add_argument('--root', type=Path, default=Path('/'))
    args = parser.parse_args()
    lock = json.loads(LOCK.read_text())
    if lock['format'] != 1 or lock['arch'] != 'aarch64':
        raise ValueError('unsupported dependency lock')
    if args.action == 'epoch':
        print(lock['source_date_epoch'])
        return
    if args.action == 'hash':
        print(digest(LOCK))
        return
    groups = ('build', 'image') if args.group == 'all' else (args.group,)
    packages = {record['file']: record for group in groups for record in lock[group]}
    if args.action == 'installed':
        installed = {}
        for paragraph in (args.root / 'lib/apk/db/installed').read_text().split('\n\n'):
            fields = dict(line.split(':', 1) for line in paragraph.splitlines() if ':' in line)
            if 'P' in fields and 'V' in fields:
                installed[fields['P']] = fields['V']
        wrong = [record['name'] + '=' + record['version'] for record in packages.values()
                 if installed.get(record['name']) != record['version']]
        if wrong:
            raise ValueError('locked packages missing or different: ' + ', '.join(wrong))
        return
    if args.action == 'paths':
        for name in sorted(packages):
            print((args.cache / name).resolve())
        return
    args.cache.mkdir(parents=True, exist_ok=True)
    for name, record in sorted(packages.items()):
        if Path(name).name != name or not name.endswith('.apk'):
            raise ValueError('invalid package filename')
        path = args.cache / name
        if path.is_symlink():
            raise ValueError('linked package cache entry: ' + name)
        if args.action == 'fetch' and (not path.is_file() or digest(path) != record['sha256']):
            temporary = args.cache / (name + '.part.' + str(os.getpid()))
            print('Fetching ' + name, flush=True)
            try:
                with urllib.request.urlopen(record['url'], timeout=60) as source, temporary.open('wb') as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                if digest(temporary) != record['sha256']:
                    raise ValueError('checksum mismatch: ' + name)
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)
        if path.is_symlink() or not path.is_file() or digest(path) != record['sha256']:
            raise ValueError('missing or altered locked package: ' + name)
    subprocess.run(['apk', 'verify', *(str(args.cache / name) for name in sorted(packages))], check=True)
    print('Verified ' + str(len(packages)) + ' locked ' + args.group + ' packages', file=sys.stderr)
    if args.action == 'install':
        subprocess.run(['apk', '--root', str(args.root), '--arch', lock['arch'], '--initdb',
                        '--keys-dir', str(args.root / 'etc/apk/keys'),
                        '--repositories-file', '/dev/null', '--no-network', '--no-cache',
                        '--no-logfile', 'add',
                        *(str((args.cache / name).resolve()) for name in sorted(packages))], check=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit('ERROR: ' + str(error) + '\nKeep the verified package cache for future offline rebuilds. Never substitute newer packages silently.')
