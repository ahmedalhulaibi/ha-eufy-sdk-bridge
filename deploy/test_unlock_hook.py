import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('unlock_hook', Path(__file__).with_name('install-unlock-hook.py'))
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class UnlockHookTests(unittest.TestCase):
    def source(self):
        return '''from pathlib import Path
import subprocess
def unlock():
    run('docker', 'restart', '--time', '60', 'homeassistant')
'''

    def test_eufy_resume_precedes_ha_restart_and_failure_does_not_block_it(self):
        for returncode in [0, 1]:
            events = []
            namespace = {'run': lambda *args: events.append(('ha', args))}
            exec(hook.transformed(self.source()), namespace)
            def resume(*args, **kwargs):
                events.append(('eufy', args))
                return subprocess.CompletedProcess(args, returncode)
            with patch.object(Path, 'is_file', return_value=True), patch.object(subprocess, 'run', side_effect=resume):
                namespace['unlock']()
            self.assertEqual([event[0] for event in events], ['eufy', 'ha'])

    def test_absent_eufy_setup_keeps_original_restart(self):
        events = []
        namespace = {'run': lambda *args: events.append(args)}
        exec(hook.transformed(self.source()), namespace)
        with patch.object(Path, 'is_file', return_value=False), patch.object(subprocess, 'run') as resume:
            namespace['unlock']()
        resume.assert_not_called()
        self.assertEqual(len(events), 1)

    def test_unexpected_or_already_patched_source_is_refused(self):
        for source in ['', self.source() + self.source(), hook.transformed(self.source())]:
            with self.assertRaises(RuntimeError):
                hook.transformed(source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
