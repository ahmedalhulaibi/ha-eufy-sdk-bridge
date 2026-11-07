#!/usr/bin/env python3
"""Add Eufy resume to the existing manual-unlock helper without changing its key prompt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

TARGET = Path('/usr/local/sbin/qolsys-storage')
CONFIG = Path('/etc/eufy-bridge')
ANCHOR = "    run('docker', 'restart', '--time', '60', 'homeassistant')\n"
HOOK = '''    # The Eufy child dataset inherits this manually unlocked encryption key.
    # Its failure must never prevent unrelated HA integrations from restarting.
    if Path('/etc/eufy-bridge/storage.json').is_file():
        result = subprocess.run(['/usr/local/sbin/eufy-storage', 'resume'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            print('Eufy storage is not ready; Home Assistant will still restart.')
'''


def transformed(source):
    if source.count(ANCHOR) != 1 or 'eufy-storage' in source:
        raise RuntimeError('Unexpected unlock helper source')
    result = source.replace(ANCHOR, HOOK + ANCHOR)
    compile(result, str(TARGET), 'exec')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0
    os.umask(0o077)
    info = TARGET.lstat()
    assert not TARGET.is_symlink() and info.st_uid == 0 and info.st_mode & 0o022 == 0
    old = TARGET.read_bytes()
    assert hashlib.sha256(old).hexdigest() == args.expected_sha256
    result = transformed(old.decode()).encode()
    backup = CONFIG / 'qolsys-storage-before-eufy.py'
    fd = os.open(str(backup), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(old)
        stream.flush()
        os.fsync(stream.fileno())
    fd, temporary = tempfile.mkstemp(prefix='.qolsys-eufy-', dir=str(TARGET.parent))
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(result)
            os.fchmod(stream.fileno(), 0o755)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, TARGET)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(json.dumps({'unlock_helper_updated': True, 'old_sha256': args.expected_sha256,
                      'new_sha256': hashlib.sha256(result).hexdigest(),
                      'native_passphrase_prompt_unchanged': True,
                      'eufy_failure_blocks_homeassistant': False}))


if __name__ == '__main__':
    main()
