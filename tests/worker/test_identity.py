"""Identity is independent of candidate source and sensitive to execution inputs."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import identity


class Identity(unittest.TestCase):
    def test_stability_and_each_bound_file_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / 'config.json'
            config.write_text(json.dumps({'code_dir': str(root / 'worker'),
                                          'base_image': str(root / 'base.qcow2')}))
            paths = []
            def fixture_record(path):
                paths.append(path)
                return {'bytes': 1, 'sha256': 'original'}
            with patch.object(identity, 'record', side_effect=fixture_record):
                original = identity.identity(root, config, root / 'native.iso', root / 'rust.tar')
                self.assertEqual(original, identity.identity(root, config, root / 'native.iso', root / 'rust.tar'))
            self.assertEqual(set(original), {'schema_version', 'identity'})
            self.assertEqual(original['schema_version'], 1)
            self.assertLessEqual(len(original['identity'].encode()), 256)
            for changed in set(paths):
                with self.subTest(path=changed), patch.object(identity, 'record', side_effect=lambda p: {
                        'bytes': 1, 'sha256': 'changed' if p == changed else 'original'}):
                    self.assertNotEqual(original, identity.identity(root, config, root / 'native.iso', root / 'rust.tar'))
            self.assertNotIn(root / 'candidate', paths)

    def test_policy_files_bind_exact_ordinary_legacy_v1_and_explicit_slots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); config = root / 'config.json'
            baseline = dict(code_dir=str(root / 'worker'), base_image=str(root / 'base'))
            configurations = [({}, 'eqemu-validator'),
                ({'diagnostic_profile': 'asan-ubsan-native-v1'}, 'eqemu-validator-asan-v1'),
                *[({'diagnostic_profile': 'asan-ubsan-native-v1', 'diagnostic_policy': name}, name)
                    for name in ('eqemu-validator-asan-v1', 'eqemu-validator-asan-v2', 'eqemu-validator-asan-v3')]]
            for fields, policy in configurations:
                config.write_text(json.dumps(dict(baseline, **fields)))
                seen = []
                with patch.object(identity, 'record', side_effect=lambda path: seen.append(path) or
                        dict(bytes=1, sha256='a'*64)):
                    identity.identity(root, config, root / 'native', root / 'rust')
                policies = {path for path in seen if str(path).startswith('/etc/')}
                self.assertEqual(policies, {Path('/etc/systemd/system') / (policy + '@.service'),
                    Path('/etc/systemd/system') / (policy + '.socket'), Path('/etc/apparmor.d') / policy})
                self.assertEqual(any(path.name == 'sanitizers.py' for path in seen), bool(fields))
            for fields in ({'diagnostic_policy': 'eqemu-validator-asan-v2'},
                    {'diagnostic_profile': 'asan-ubsan-native-v1', 'diagnostic_policy': 'eqemu-validator-asan-v4'},
                    {'diagnostic_profile': 'other'}):
                config.write_text(json.dumps(dict(baseline, **fields)))
                with self.assertRaises(ValueError), patch.object(identity, 'record') as record:
                    identity.identity(root, config, root / 'native', root / 'rust')
                record.assert_not_called()

    def test_cli_identity_does_not_contact_worker_or_prepare_candidate(self):
        loader = importlib.machinery.SourceFileLoader('candidate_cli', str(ROOT / 'scripts/validate-worker-candidate'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        expected = {'schema_version': 1, 'identity': 'test'}
        with patch.object(sys, 'argv', ['validate-worker-candidate', '--identity']), \
                patch.object(cli, 'identity', return_value=expected), \
                patch.object(cli, 'exchange') as exchange, patch.object(cli, 'prepare') as prepare, \
                patch('builtins.print') as output:
            self.assertEqual(cli.main(), 0)
            self.assertEqual(json.loads(output.call_args.args[0]), expected)
            exchange.assert_not_called()
            prepare.assert_not_called()
        with patch.object(sys, 'argv', ['validate-worker-candidate', '--identity']), \
                patch.object(cli, 'identity', side_effect=OSError('unreadable input')), patch('builtins.print') as output:
            self.assertEqual(cli.main(), 2)
            self.assertNotIn('identity', json.loads(output.call_args.args[0]))


if __name__ == '__main__':
    unittest.main()
