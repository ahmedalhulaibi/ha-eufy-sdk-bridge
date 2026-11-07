#!/usr/bin/env python3
"""Prepare encrypted Eufy storage without configuring or signing into an account."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

SOURCE = Path('/home/ahmed/media-server-sources/ha-eufy-sdk-bridge')
CONFIG = Path('/etc/eufy-bridge')
ROOT = Path('/media-server/secure-eufy')
PARENT = 'media-pool/qolsys-credentials'
DATASET = PARENT + '/eufy'
UID = 10001


def command(*args):
    return subprocess.check_output(list(map(str, args)), universal_newlines=True).strip()


def props(dataset):
    result = command('/sbin/zfs', 'get', '-H', '-o', 'property,value',
                     'encryption,encryptionroot,keystatus,keyformat,keylocation,mountpoint,mounted', dataset)
    return dict(line.split('\t', 1) for line in result.splitlines())


def save(path, value, uid=0):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchown(stream.fileno(), uid, uid)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    os.umask(0o077)
    assert re.fullmatch(r'[0-9a-f]{40}', args.commit)
    git = ['git', '-c', 'safe.directory=' + str(SOURCE), '-C', str(SOURCE)]
    assert command(*git, 'config', '--get', 'remote.origin.url') == 'https://github.com/ahmedalhulaibi/ha-eufy-sdk-bridge.git'
    assert command(*git, 'rev-parse', 'HEAD') == args.commit
    assert not command(*git, 'status', '--porcelain')
    assert not CONFIG.exists(), 'Inspect an existing deployment before changing it'
    assert not ROOT.exists(), 'Inspect an existing storage path before changing it'
    assert subprocess.run(['/sbin/zfs', 'list', '-H', DATASET], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0
    parent = props(PARENT)
    assert parent['encryption'] == 'aes-256-gcm' and parent['keystatus'] == 'available'
    assert parent['encryptionroot'] == PARENT and parent['keyformat'] == 'passphrase'
    assert parent['keylocation'] == 'prompt'
    image = 'eufy-bridge-secure:' + args.commit[:12]
    log = Path('/var/log/eufy-bridge-build-' + args.commit[:12] + '.log')
    with log.open('w') as output:
        subprocess.run(['docker', 'build', '--label', 'org.opencontainers.image.revision=' + args.commit,
                        '-t', image, '.'], cwd=str(SOURCE), stdout=output,
                       stderr=subprocess.STDOUT, check=True)
    info = json.loads(command('docker', 'image', 'inspect', image))[0]
    assert info['Config']['User'] == '10001:10001'
    assert not any(item.split('=', 1)[0] in {'EUFY_EMAIL', 'EUFY_PASSWORD', 'SOLIX_EMAIL', 'SOLIX_PASSWORD'}
                   for item in info['Config'].get('Env', []))
    CONFIG.mkdir(mode=0o700)
    ROOT.mkdir(mode=0o700)
    command('/sbin/zfs', 'create', '-o', 'canmount=noauto', '-o', 'quota=256M',
            '-o', 'compression=lz4', '-o', 'snapdir=hidden', '-o', 'mountpoint=' + str(ROOT), DATASET)
    if props(DATASET)['mounted'] != 'yes':
        command('/sbin/zfs', 'mount', DATASET)
    actual = props(DATASET)
    assert actual['encryption'] == 'aes-256-gcm' and actual['encryptionroot'] == PARENT
    assert os.path.ismount(ROOT) and actual['mountpoint'] == str(ROOT)
    ROOT.chmod(0o700)
    os.chown(str(ROOT), UID, UID)
    volume_id = uuid.uuid4().hex
    save(ROOT / '.eufy-volume-id', volume_id + '\n', UID)
    guard = {'version': 1, 'require_mount': True, 'dataset': DATASET, 'volume_id': volume_id}
    save(CONFIG / 'runtime-guard.json', json.dumps(guard) + '\n', UID)
    save(ROOT / 'storage-guard-recovery.json', json.dumps(guard) + '\n', UID)
    (ROOT / 'state').mkdir(mode=0o700)
    os.chown(str(ROOT / 'state'), UID, UID)
    settings = {'version': 1, 'dataset': DATASET, 'mountpoint': str(ROOT),
                'volume_id': volume_id, 'image': image, 'source_commit': args.commit,
                'source_repository': 'https://github.com/ahmedalhulaibi/ha-eufy-sdk-bridge',
                'image_id': info['Id']}
    save(CONFIG / 'storage.json', json.dumps(settings, indent=2) + '\n')
    template = (SOURCE / 'docker-compose.yml').read_text()
    template = template.replace('    build: .\n', '').replace('eufy-bridge-secure:0.7.3', image)
    save(CONFIG / 'compose.yaml', template)
    target = Path('/usr/local/sbin/eufy-storage')
    assert not target.exists()
    shutil.copyfile(str(SOURCE / 'deploy/eufy-storage.py'), str(target))
    target.chmod(0o755)
    os.chown(str(target), 0, 0)
    command('docker', 'compose', '-p', 'media-eufy', '-f', CONFIG / 'compose.yaml', 'config', '--quiet')
    report = {'repository': settings['source_repository'], 'commit': args.commit,
              'image': image, 'image_id': info['Id'], 'dataset': DATASET,
              'encryption': actual['encryption'], 'encryptionroot': actual['encryptionroot'],
              'cloud_credentials_in_docker_environment': False,
              'manual_unlock_after_reboot': True, 'separate_qolsys_mount': True,
              'bridge_port': 3012, 'rtsp_port': 8556, 'credentials_configured': False,
              'account_login_attempted': False, 'device_commands_sent': False}
    save(CONFIG / 'deployment.json', json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
