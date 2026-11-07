"""Host-helper security tests, using synthetic credentials and mocked ZFS/Docker."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('eufy_storage', Path(__file__).with_name('eufy-storage.py'))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class HostStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'encrypted'
        self.root.mkdir(mode=0o700)
        self.guard = self.base / 'guard.json'
        self.config = {'version': 1, 'dataset': storage.DATASET,
                       'mountpoint': str(self.root), 'volume_id': 'ab' * 16,
                       'image': 'eufy-bridge-secure:' + 'cd' * 6}
        (self.root / '.eufy-volume-id').write_text(self.config['volume_id'])
        (self.root / '.eufy-volume-id').chmod(0o600)
        self.guard.write_text(json.dumps({'version': 1, 'require_mount': True,
                                         'dataset': storage.DATASET,
                                         'volume_id': self.config['volume_id']}))
        self.guard.chmod(0o600)
        self.props = {'encryption': 'aes-256-gcm', 'encryptionroot': storage.PARENT,
                      'keystatus': 'available', 'mounted': 'yes',
                      'mountpoint': str(self.root), 'keyformat': 'passphrase',
                      'keylocation': 'prompt'}
        self.patches = [patch.multiple(storage, ROOT=self.root, GUARD=self.guard, UID=os.geteuid()),
                        patch.object(storage, 'settings', return_value=self.config),
                        patch.object(storage, 'properties', return_value=self.props),
                        patch.object(storage.os.path, 'ismount', return_value=True)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_refuses_locked_plaintext_and_wrong_volume_without_writing(self):
        for key, value in [('mounted', 'no'), ('encryption', 'off'),
                           ('encryptionroot', 'unexpected/dataset')]:
            props = dict(self.props, **{key: value})
            with patch.object(storage, 'properties', return_value=props):
                with self.assertRaises(RuntimeError):
                    storage.save_private(self.root / 'credentials.json', {'password': 'synthetic-secret'})
            self.assertFalse((self.root / 'credentials.json').exists())

    def test_private_atomic_write_and_replacement(self):
        record = {'version': 1, 'eufy': {'password': 'synthetic-secret'}}
        target = self.root / 'credentials.json'
        storage.save_private(target, record)
        self.assertEqual(json.loads(target.read_text()), record)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        storage.save_private(target, {'version': 1})
        self.assertEqual(json.loads(target.read_text()), {'version': 1})
        self.assertFalse(list(self.root.glob('.pending-*')))

    def test_failed_write_preserves_existing_record(self):
        target = self.root / 'credentials.json'
        storage.save_private(target, {'password': 'old-synthetic-secret'})
        with patch.object(storage.os, 'replace', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                storage.save_private(target, {'password': 'new-synthetic-secret'})
        self.assertEqual(json.loads(target.read_text()), {'password': 'old-synthetic-secret'})
        self.assertFalse(list(self.root.glob('.pending-*')))

    def test_symlink_and_hardlink_destinations_are_refused(self):
        target = self.root / 'credentials.json'
        original = self.root / 'original'
        original.write_text('synthetic-secret')
        original.chmod(0o600)
        for hardlink in [False, True]:
            if hardlink:
                os.link(original, target)
            else:
                target.symlink_to(original)
            with self.assertRaises(RuntimeError):
                storage.save_private(target, {'password': 'replacement'})
            target.unlink()
            self.assertEqual(original.read_text(), 'synthetic-secret')

    def test_noninteractive_configuration_cannot_accept_credentials(self):
        with patch.object(storage.sys.stdin, 'isatty', return_value=False), patch.object(storage.getpass, 'getpass') as prompt:
            with self.assertRaises(RuntimeError):
                storage.configure()
            prompt.assert_not_called()

    def test_configuration_does_not_echo_credentials_or_start_a_service(self):
        output = io.StringIO()
        with (patch.object(storage.sys.stdin, 'isatty', return_value=True),
              patch.object(storage.sys.stderr, 'isatty', return_value=True),
              patch.object(storage.getpass, 'getpass', side_effect=['fixture@example.com', 'synthetic-password']),
              patch('builtins.input', return_value='CA'),
              patch.object(storage, 'command') as command,
              contextlib.redirect_stdout(output)):
            storage.configure()
        self.assertNotIn('synthetic-password', output.getvalue())
        self.assertNotIn('fixture@example.com', output.getvalue())
        command.assert_not_called()
        self.assertEqual(json.loads((self.root / 'credentials.json').read_text())['eufy']['country'], 'CA')

    def test_start_checks_storage_with_network_disabled_and_no_secret_arguments(self):
        storage.save_private(self.root / 'credentials.json', {'password': 'synthetic-password'})
        with patch.object(storage, 'command') as command, patch.object(storage, 'compose') as compose:
            storage.start()
        arguments = command.call_args.args
        self.assertIn('none', arguments)
        self.assertNotIn('synthetic-password', str(arguments))
        self.assertNotIn('--env', arguments)
        self.assertIn('no-new-privileges', arguments)
        compose.assert_called_once_with('up', '-d', '--force-recreate')

    def test_missing_credentials_refuse_start_before_docker(self):
        with patch.object(storage, 'command') as command, patch.object(storage, 'compose') as compose:
            with self.assertRaises(FileNotFoundError):
                storage.start()
        command.assert_not_called()
        compose.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
