#!/usr/bin/env python3
"""Private local credential entry and encrypted storage lifecycle on the media host."""

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import uuid

SETTINGS = Path('/etc/eufy-bridge/storage.json')
PARENT = 'media-pool/qolsys-credentials'
DATASET = PARENT + '/eufy'
ROOT = Path('/media-server/secure-eufy')
COMPOSE = Path('/etc/eufy-bridge/compose.yaml')
GUARD = Path('/etc/eufy-bridge/runtime-guard.json')
BACKUPS = Path('/srv/media-server-backups')
UID = 10001


def command(*args):
    return subprocess.run(list(map(str, args)), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, universal_newlines=True).stdout.strip()


def properties(dataset):
    result = command('/sbin/zfs', 'get', '-H', '-o', 'property,value',
                     'encryption,encryptionroot,keyformat,keylocation,keystatus,mounted,mountpoint', dataset)
    return dict(line.split('\t', 1) for line in result.splitlines())


def private_info(path, uid, directory=False):
    info = path.lstat()
    if (info.st_uid != uid or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise RuntimeError('Private storage permissions or file type are invalid')


def settings():
    private_info(SETTINGS, 0)
    value = json.loads(SETTINGS.read_text())
    if (value.get('version') != 1 or value.get('dataset') != DATASET
            or value.get('mountpoint') != str(ROOT)
            or not re.fullmatch(r'[0-9a-f]{32}', value.get('volume_id', ''))):
        raise RuntimeError('Invalid Eufy host storage settings')
    return value


def ready(require_credentials=False):
    config = settings()
    props = properties(DATASET)
    parent = properties(PARENT)
    if (props['encryption'] != 'aes-256-gcm' or props['encryptionroot'] != PARENT
            or props['keystatus'] != 'available' or props['mounted'] != 'yes'
            or props['mountpoint'] != str(ROOT) or not os.path.ismount(ROOT)
            or parent['keyformat'] != 'passphrase' or parent['keylocation'] != 'prompt'):
        raise RuntimeError('Unlock the encrypted credential volume before continuing')
    private_info(ROOT, UID, directory=True)
    marker = ROOT / '.eufy-volume-id'
    private_info(marker, UID)
    if marker.read_text().strip() != config['volume_id']:
        raise RuntimeError('Eufy volume identity mismatch')
    private_info(GUARD, UID)
    runtime = json.loads(GUARD.read_text())
    if runtime != {'version': 1, 'require_mount': True, 'dataset': DATASET,
                   'volume_id': config['volume_id']}:
        raise RuntimeError('Eufy runtime storage guard does not match')
    if require_credentials:
        private_info(ROOT / 'credentials.json', UID)
    return config


def save_private(path, value):
    # ROOT is checked immediately before creation, and the pinned directory FD
    # prevents a concurrent unmount from redirecting the write to its placeholder.
    ready()
    fd_root = os.open(str(ROOT), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.pending-' + uuid.uuid4().hex
    try:
        if not os.path.samestat(os.fstat(fd_root), ROOT.stat()):
            raise RuntimeError('Credential mount changed')
        try:
            private_info(path, UID)
        except FileNotFoundError:
            pass
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=fd_root)
        with os.fdopen(fd, 'w') as stream:
            os.fchown(stream.fileno(), UID, UID)
            json.dump(value, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=fd_root, dst_dir_fd=fd_root)
        os.fsync(fd_root)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd_root)
        except FileNotFoundError:
            pass
        os.close(fd_root)


def configure():
    ready()
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RuntimeError('Enter credentials only in a private interactive terminal')
    # Both username and password are hidden, and no credential is passed in argv,
    # environment, Compose configuration, command output or an unencrypted backup.
    email = getpass.getpass('Eufy account email (hidden): ').strip()
    password = getpass.getpass('Eufy account password (hidden): ')
    country = input('Account country (two letters, e.g. CA): ').strip().upper()
    if ('@' not in email or len(email) > 320 or not password or len(password) > 4096
            or not re.fullmatch(r'[A-Z]{2}', country)):
        raise RuntimeError('Account fields are invalid; credentials were not saved')
    if (ROOT / 'credentials.json').exists():
        confirmation = input('Replace the existing encrypted credentials? Type replace: ')
        if confirmation != 'replace':
            raise RuntimeError('Existing credentials kept')
    save_private(ROOT / 'credentials.json', {
        'version': 1, 'eufy': {'email': email, 'password': password, 'country': country},
    })
    print('Credentials saved on encrypted storage. No login has been attempted.')
    print('Run sudo /usr/local/sbin/eufy-storage start to connect, then add the HA integration.')


def compose(*args):
    return command('docker', 'compose', '-p', 'media-eufy', '-f', COMPOSE, *args)


def start():
    config = ready(require_credentials=True)
    # Mounts and paths are nonsecret. Network is disabled for this readiness
    # command, so it cannot sign in or operate a physical device.
    command('docker', 'run', '--rm', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--ulimit', 'core=0', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
            '--mount', 'type=bind,source=' + str(ROOT) + ',target=/data',
            '--mount', 'type=bind,source=' + str(GUARD) + ',target=/run/eufy-storage.json,readonly',
            config['image'], 'node', '/app/bin/check-storage.mjs')
    compose('up', '-d', '--force-recreate')
    print('Eufy bridge started using encrypted credential storage.')


def resume():
    settings()
    if properties(PARENT)['keystatus'] != 'available':
        raise RuntimeError('Unlock the shared credential volume first')
    if properties(DATASET)['mounted'] != 'yes':
        command('/sbin/zfs', 'mount', DATASET)
    ready()
    if (ROOT / 'credentials.json').is_file():
        start()
    else:
        print('Eufy storage mounted; waiting for private credential configuration.')


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def checkpoint():
    ready()
    name = 'eufy-encrypted-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    snapshot = DATASET + '@' + name
    directory = BACKUPS / name
    directory.mkdir(mode=0o700)
    command('/sbin/zfs', 'snapshot', snapshot)
    target = directory / 'eufy-credentials.zfs'
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        subprocess.run(['/sbin/zfs', 'send', '-w', snapshot], stdout=stream,
                       stderr=subprocess.PIPE, check=True)
        stream.flush()
        os.fsync(stream.fileno())
    # Guard metadata is nonsecret; include a private recovery copy explicitly.
    (directory / 'runtime-guard.json').write_bytes(GUARD.read_bytes())
    (directory / 'runtime-guard.json').chmod(0o600)
    report = {'dataset': DATASET, 'snapshot': snapshot, 'backup': str(target),
              'bytes': target.stat().st_size,
              'sha256': sha256(target),
              'format': 'ZFS raw encrypted send', 'shared_passphrase_required': True}
    (directory / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['configure', 'start', 'stop', 'resume', 'status', 'checkpoint'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('Run with sudo')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if args.command == 'configure':
        configure()
    elif args.command == 'start':
        start()
    elif args.command == 'stop':
        compose('stop', '--timeout', '30')
    elif args.command == 'resume':
        resume()
    elif args.command == 'checkpoint':
        checkpoint()
    else:
        settings()
        props = properties(DATASET)
        print(json.dumps({'dataset': DATASET, 'encryption': props['encryption'],
                          'encryptionroot': props['encryptionroot'],
                          'mounted': props['mounted'], 'keystatus': props['keystatus'],
                          'credentials_configured': (ROOT / 'credentials.json').is_file()
                          if props['mounted'] == 'yes' else False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Exception text may contain subprocess stderr or parser excerpts. Never
        # echo it on a credential-handling command's terminal/log boundary.
        print('Eufy operation could not complete. Check storage readiness and private configuration.', file=sys.stderr)
        sys.exit(1)
