"""Composition boundaries; only trusted host mocks and source inspection."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation/worker'))
import build_guest
import diagnostic_operator
import prepare
import profile_contract
import profile_release
import runtime
import sanitizers
import staging


class Composition(unittest.TestCase):
    def test_frontend_and_packaging_reject_combined_modes_before_inputs(self):
        for mode in ('timeline', 'heaptrack', 'perf'):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-B', str(ROOT/'scripts/validate-worker-candidate'),
                    '--profile', sanitizers.PROFILE, '--profiling', mode, '--prepare-only', '/nonexistent/output'],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn('mutually exclusive', result.stderr)
                with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                    prepare.prepare(None, None, None, None, None, None,
                        diagnostic_profile=sanitizers.PROFILE, profiling=mode)

    def test_build_request_fields_reject_null_and_combined_modes_before_vm(self):
        base = dict(version=1, operation='build', candidate='a'*40, tree='b'*40, bytes=1, sha256='c'*64)
        for fields, selected in [({'profiling':None}, {}), ({'diagnostic_profile':None}, {}),
                *[(dict(profiling=mode, diagnostic_profile=sanitizers.PROFILE),
                   dict(diagnostic_profile=sanitizers.PROFILE)) for mode in ('timeline','heaptrack','perf')]]:
            with self.subTest(fields=fields):
                # Separate real sockets exercise the actual bounded request parser.
                left, right = socket.socketpair()
                try:
                    right.sendall((json.dumps(dict(base, **fields))+'\n').encode())
                    import pwd
                    value = dict(submitter=pwd.getpwuid(os.getuid()).pw_name, **selected)
                    with patch.object(runtime, 'run_vm') as launch, self.assertRaises(ValueError):
                        runtime.request(left, value)
                    launch.assert_not_called()
                finally:
                    left.close(); right.close()

    def test_build_modes_keep_rust_flags_and_native_switch_separate(self):
        with patch.dict(build_guest.ENV, {}, clear=True), patch.object(build_guest, 'prepare_source', return_value=(Path('/src'),Path('/registry'))), \
                patch.object(build_guest,'prepare_rust',return_value='/cargo'), patch.object(build_guest,'command',side_effect=RuntimeError('stop before compiling')):
            for profile, mode in ((None,'timeline'),(sanitizers.PROFILE,None),(None,None)):
                with patch.object(build_guest,'PROFILE',profile), patch.object(build_guest,'PROFILING',mode):
                    with self.assertRaisesRegex(RuntimeError,'stop before compiling'): build_guest.build()
                    self.assertEqual('RUSTFLAGS' in build_guest.ENV, mode is not None)
        with patch.object(build_guest,'PROFILE',sanitizers.PROFILE), patch.object(build_guest,'PROFILING','heaptrack'), \
                patch.object(build_guest,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'mutually exclusive'):
                build_guest.configure_native(Path('/src'),Path('/registry'))
            command.assert_not_called()

    def test_combined_release_closure_is_finite_and_retained_closure_stays_original(self):
        self.assertEqual(set(profile_contract.SOURCE_FILES),set(profile_release.SOURCE_FILES))
        self.assertTrue(set(staging.FILES) <= set(profile_contract.SOURCE_FILES))
        self.assertIn('validation/worker/sanitizers.py',profile_contract.SOURCE_FILES)
        self.assertEqual(len(diagnostic_operator.RETAINED_FILES),15)
        self.assertFalse(any('profil' in name for name in diagnostic_operator.RETAINED_FILES))
        for name in profile_contract.SOURCE_FILES: self.assertTrue((ROOT/name).is_file())
