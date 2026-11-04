"""Fresh real CLI imports, stopped before the first durable runner can spawn."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# This guard is test-only. Run the unchanged entry point with a fresh module
# cache; allow trusted Git metadata reads but never runner or socket execution.
PROBE = r'''
import json, runpy, sys
from pathlib import Path
script = sys.argv[1]
sys.argv = sys.argv[1:]
def audit(event, args):
    if event.startswith('socket.'):
        raise SystemExit('Unexpected socket operation: ' + event)
    if event == 'subprocess.Popen' and args[0] != '/usr/bin/git':
        argv = args[1]
        if (len(argv) != 6 or argv[:2] != ['/usr/bin/python3', '-I']
                or Path(argv[2]).name != 'runner.py' or argv[3] != '--run'):
            raise SystemExit('Unexpected process: ' + repr(argv))
        print(json.dumps(dict(boundary='before-runner-spawn', argv=argv,
            prepare=sys.modules['prepare'].__file__,
            identity=sys.modules['identity'].__file__,
            inputs=sys.modules['inputs'].__file__)))
        raise SystemExit(73)
sys.addaudithook(audit)
runpy.run_path(script, run_name='__main__')
'''


class JobsCLI(unittest.TestCase):
    def test_real_cli_snapshot_imports_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'; repo.mkdir()
            # A source-only empty commit supplies actual GitTree metadata. No
            # candidate or installed configuration is read or executed.
            subprocess.run(['/usr/bin/git', 'init', '--template=', str(repo)],
                           check=True, capture_output=True)
            subprocess.run(['/usr/bin/git', '-C', str(repo), '-c', 'user.name=Fixture',
                '-c', 'user.email=fixture@example.invalid', '-c', 'core.hooksPath=/dev/null',
                'commit', '--allow-empty', '-m', 'source-only fixture'], check=True, capture_output=True)
            commit = subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
            tree = subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
            config = root / 'diagnostic.json'
            config.write_text(json.dumps(dict(diagnostic_profile='asan-ubsan-native-v1')))
            for profile, rust in [('full', False), ('full', True), ('full-sanitizers', True)]:
                with self.subTest(profile=profile, rust=rust):
                    jobs = root / (profile + str(rust))
                    args = ['--jobs-dir', str(jobs), 'start', profile, '--repo', str(repo),
                        '--commit', commit, '--thread', 'fixture-thread', '--t3-base-dir', str(root),
                        '--websocketpp', str(root / 'websocketpp'), '--config', str(config)]
                    if rust: args += ['--rust-input', str(root / 'rust-inputs.tar')]
                    result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE,
                        str(ROOT / 'scripts/validation-job'), *args], capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 73, result.stderr)
                    receipt = json.loads(result.stdout)
                    self.assertEqual(receipt['boundary'], 'before-runner-spawn')
                    for module in ('prepare', 'identity'):
                        self.assertEqual(Path(receipt[module]), ROOT / 'validation/worker' / (module + '.py'))
                    self.assertEqual(Path(receipt['inputs']), ROOT / 'validation/inputs.py')
                    paths = list(jobs.iterdir()); self.assertEqual(len(paths), 1)
                    path = paths[0]
                    self.assertEqual(path.stat().st_mode & 0o777, 0o700)
                    spec = json.loads((path / 'job.json').read_text())
                    self.assertEqual((spec['candidate'], spec['tree'], spec['observed_head']), (commit, tree, commit))
                    expected = [str(path / 'client/scripts/validate-worker-candidate'), '--repo', str(repo),
                        '--commit', commit, '--websocketpp', str(root / 'websocketpp'), '--config', str(config)]
                    if rust: expected += ['--rust-input', str(root / 'rust-inputs.tar')]
                    if profile == 'full-sanitizers': expected += ['--profile', 'asan-ubsan-native-v1']
                    self.assertEqual(spec['command'], expected)
                    self.assertEqual(spec['profile'], profile)
                    self.assertEqual(spec['runner_sha256'], hashlib.sha256((path / 'runner.py').read_bytes()).hexdigest())
                    self.assertEqual(json.loads((path / 'state.json').read_text()), dict(status='starting'))
                    self.assertFalse((path / 'result.json').exists())
                    records = spec['client_files_sha256']
                    for name, digest in records.items():
                        data = (path / 'client' / name).read_bytes()
                        self.assertEqual(data, (ROOT / name).read_bytes())
                        self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
                    for name in ('validation/worker/prepare.py', 'validation/worker/identity.py',
                                 'validation/inputs.py'):
                        self.assertIn(name, records)
                    # The copied frontend performs every top-level import in a
                    # second fresh isolated process, then exits via argparse.
                    help_result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE,
                        expected[0], '--help'], capture_output=True, text=True, timeout=15)
                    self.assertEqual(help_result.returncode, 0, help_result.stderr)
                    self.assertIn('--identity', help_result.stdout)


if __name__ == '__main__': unittest.main()
