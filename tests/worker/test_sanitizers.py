"""Diagnostic policy/protocol regressions. No native/Cargo candidate or VM runs."""
import copy
import contextlib
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import build_guest
import guest
import identity
import normal_world
import runtime
import sanitizers
import diagnostic_operator as operator
from test_normal_world import baseline
from test_failure_evidence import failure


@contextlib.contextmanager
def restrictive_umask():
    prior = os.umask(0o077)
    try: yield
    finally: os.umask(prior)


class Sanitizers(unittest.TestCase):
    def test_identity_accepts_ordinary_installed_closure_and_requires_diagnostic_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); config = root/'config.json'; seen = []
            value = dict(code_dir=str(root/'worker'),base_image=str(root/'base'))
            config.write_text(json.dumps(value))
            def record(path):
                seen.append(path); return dict(bytes=1,sha256='a'*64)
            with patch.object(identity,'record',side_effect=record):
                identity.identity(root,config,root/'native',root/'rust')
            self.assertFalse(any(path.name == 'sanitizers.py' for path in seen))
            config.write_text(json.dumps(dict(value,diagnostic_profile=sanitizers.PROFILE)))
            seen.clear()
            with patch.object(identity,'record',side_effect=record):
                identity.identity(root,config,root/'native',root/'rust')
            self.assertTrue(any(path.name == 'sanitizers.py' for path in seen))

    def test_diagnostic_export_has_independent_profile_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = failure(); report['diagnostic_profile'] = sanitizers.PROFILE
            report['guest']['sanitizers'] = dict(environment=sanitizers.ENV,
                symbolizer=dict(path='/usr/bin/addr2line',sha256='c'*64),binaries={'zone':dict(sha256='d'*64)})
            directory = Path(temporary)/'evidence'
            path = normal_world.export_evidence(report,'a'*40,directory)
            artifact = json.loads(path.read_text())
            self.assertIn(sanitizers.PROFILE,path.name)
            self.assertEqual(artifact['diagnostic_profile'],sanitizers.PROFILE)
            self.assertEqual(artifact['sanitizer_identity']['environment'],sanitizers.ENV)
            for name in ('diagnostic-files.json','public-summary.json'):
                self.assertEqual(json.loads((directory/name).read_text())['profile'],sanitizers.PROFILE)
    def test_distinct_seed_checks_environment_and_no_virtual_address_limit(self):
        ordinary = json.loads(guest.build_user_data('a'*32).split('\n', 1)[1])
        selected = json.loads(guest.build_user_data('a'*32, sanitizers.PROFILE).split('\n', 1)[1])
        self.assertNotEqual(ordinary, selected)
        files = {item['path']: item['content'] for item in selected['write_files']}
        self.assertEqual(files['/opt/eqemu-worker-profile'], sanitizers.PROFILE)
        checks = json.loads(files['/opt/eqemu-worker-checks.json'])
        self.assertLess(checks.index('sanitizer-controls'), checks.index('native-utilities'))
        self.assertEqual(files['/opt/sanitizers.py'], (ROOT / 'validation/worker/sanitizers.py').read_text())
        self.assertNotIn('RLIMIT_AS', files['/opt/eqemu-worker-build-guest'] + files['/opt/normal_world.py'])
        with self.assertRaises(ValueError): guest.build_user_data('a'*32, 'unknown')

    def test_real_socket_profile_admission_mismatch_never_runs_vm(self):
        request = dict(version=1, operation='build', candidate='a'*40, tree='b'*40, bytes=1, sha256='c'*64)
        for admitted, selected in ((None, None), (sanitizers.PROFILE, sanitizers.PROFILE),
                                  (None, sanitizers.PROFILE), (sanitizers.PROFILE, None)):
            server, client = socket.socketpair()
            try:
                data = dict(request)
                if selected: data['diagnostic_profile'] = selected
                value = dict(submitter=__import__('pwd').getpwuid(os.getuid()).pw_name)
                if admitted: value['diagnostic_profile'] = admitted
                client.sendall(json.dumps(data).encode() + b'\n')
                with patch.object(runtime, 'run_vm', return_value={'test': 'transport-only'}) as execute:
                    if admitted == selected:
                        self.assertEqual(runtime.request(server, value), {'test': 'transport-only'})
                        self.assertEqual(execute.call_args.kwargs['build'], data)
                    else:
                        with self.assertRaises(ValueError): runtime.request(server, value)
                        execute.assert_not_called()
            finally: server.close(); client.close()

    def test_ordinary_and_diagnostic_configurations_share_exact_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            children = [parent / slot for slot in ('asan-v1', 'asan-v2')]
            for child in children: child.mkdir()
            configs = [dict(state_dir=str(parent)),
                *(dict(state_dir=str(child), diagnostic_profile=sanitizers.PROFILE) for child in children)]
            for owner in configs:
                fd = runtime.acquire(owner)
                try:
                    for contender in configs:
                        with self.assertRaisesRegex(RuntimeError, 'Another worker operation'):
                            runtime.acquire(contender)
                finally: os.close(fd)
            for child in children: self.assertFalse((child / 'worker.lock').exists())

    def test_readiness_requires_exact_selected_policy(self):
        limits = {'memory.max': '64', 'pids.max': '64', 'memory.swap.max': '0',
            'cpu.max': '200000 100000', 'no_new_privileges': '1', 'effective_capabilities': '0'}
        base = Mock(); base.stat.return_value.st_size = 1
        selected = [({}, 'eqemu-validator'),
            ({'diagnostic_profile': sanitizers.PROFILE}, sanitizers.POLICIES[0]),
            *[(dict(diagnostic_profile=sanitizers.PROFILE, diagnostic_policy=name), name)
                for name in sanitizers.POLICIES]]
        with patch.object(runtime, 'invocation', return_value='a'*32), \
                patch.object(runtime, 'resource_state', return_value=limits), \
                patch.object(runtime, 'root_file', return_value=base), \
                patch.object(runtime.os.path, 'isfile', return_value=True), \
                patch.object(runtime.os, 'access', side_effect=lambda path, mode: path != '/home/submitter'), \
                patch.object(runtime.os, 'open', return_value=42), patch.object(runtime.os, 'close'), \
                patch.object(runtime.pwd, 'getpwnam', return_value=Mock(pw_dir='/home/submitter')):
            for fields, expected in selected:
                for policy in ('eqemu-validator', *sanitizers.POLICIES):
                    for label in (policy, policy + '//&unconfined', 'unconfined//&' + policy):
                        with self.subTest(fields=fields, label=label), \
                                patch.object(Path, 'read_text', return_value=label + ' (enforce)'):
                            result = runtime.ready(dict(base_image='/base', submitter='submitter', **fields))
                            self.assertEqual(result['checks']['apparmor'], policy == expected)
                            self.assertEqual(result['exit_code'], 0 if policy == expected else 2)

    def test_root_config_accepts_only_bounded_policy_selection(self):
        import pwd
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); state = root / 'state'; state.mkdir(mode=0o700)
            path = root / 'config.json'; account = pwd.getpwuid(os.getuid())
            value = dict(version=1, user=account.pw_name, worker_uid=account.pw_uid,
                worker_gid=account.pw_gid, state_dir=str(state), code_dir=str(root),
                submitter=account.pw_name, socket='/run/test.sock', base_image='/public/base')
            for fields in ({}, {'diagnostic_profile': sanitizers.PROFILE},
                    *[dict(diagnostic_profile=sanitizers.PROFILE, diagnostic_policy=name)
                        for name in sanitizers.POLICIES]):
                path.write_text(json.dumps(dict(value, **fields)))
                with patch.object(runtime, 'root_file', return_value=path) as trusted:
                    self.assertEqual(runtime.config(path), dict(value, **fields))
                    trusted.assert_called_once_with(path)
            for fields in ({'diagnostic_policy': sanitizers.POLICIES[1]},
                    dict(diagnostic_profile=sanitizers.PROFILE, diagnostic_policy='eqemu-validator-asan-v3'),
                    dict(diagnostic_profile=sanitizers.PROFILE, diagnostic_policy=None)):
                path.write_text(json.dumps(dict(value, **fields)))
                with patch.object(runtime, 'root_file', return_value=path), self.assertRaises(ValueError):
                    runtime.config(path)
            with patch.object(runtime, 'root_file', side_effect=ValueError('Expected root-owned input')), \
                    self.assertRaisesRegex(ValueError, 'root-owned'):
                runtime.config(path)

    def test_generated_commands_check_flags_optimization_and_known_gaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            entries = [dict(file='/source/' + name + '/example.cpp',
                command='g++ -O2 ' + ' '.join(sanitizers.FLAGS) + ' -o ' + name + '/CMakeFiles/target.dir/example.o')
                for name in ('common', 'tests', 'world', 'zone')]
            database = output / 'compile_commands.json'; database.write_text(json.dumps(entries))
            value = sanitizers.verify_commands(output)
            self.assertEqual(value['native_compile_counts'], dict.fromkeys(('common','tests','world','zone'), 1))
            self.assertIn('Cargo-generated CXX and Rust archives', value['exclusions'])
            entries[0]['command'] += ' -O0'; database.write_text(json.dumps(entries))
            with self.assertRaisesRegex(RuntimeError, 'optimization'): sanitizers.verify_commands(output)

    def test_nonpass_control_receipts_cannot_be_missing_signalled_or_unsymbolized(self):
        report = dict(profile=sanitizers.PROFILE, environment=sanitizers.ENV, qualified=True,
            controls=[dict(mode=mode, returncode=0 if mode == 'pass' else 1, qualified=True,
                symbolized=mode != 'pass', output='sanitizer_controls.cpp:10') for mode in sanitizers.MODES],
            binaries={name: dict(sha256='a'*64, runtimes=['libasan','libubsan'])
                for name in ('tests','world','zone','shared_memory')})
        sanitizers.validate_controls(report)
        for field, value in (('returncode',0),('returncode',-11),('symbolized',False),('output','unknown')):
            changed = copy.deepcopy(report); changed['controls'][1][field] = value
            with self.assertRaises(RuntimeError): sanitizers.validate_controls(changed)
        changed = copy.deepcopy(report); changed['controls'].pop()
        with self.assertRaises(RuntimeError): sanitizers.validate_controls(changed)

    def test_late_native_nonzero_cannot_pass_normal_world_receipt(self):
        value = dict(baseline(), native_exit_codes=[dict(name='world',returncode=0),dict(name='zone',returncode=0)])
        normal_world.validate(value)
        for code in (1, -11, -15, None, False):
            changed = copy.deepcopy(value); changed['native_exit_codes'][1]['returncode'] = code
            with self.assertRaisesRegex(ValueError, 'native exit'): normal_world.validate(changed)

    def test_control_policy_uses_real_process_exits_and_retains_unexpected_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary); (output/'bin').mkdir()
            entries = [dict(file='/source/' + name + '/example.cpp',
                command='g++ ' + ' '.join(sanitizers.FLAGS) + ' -o ' + name + '/CMakeFiles/t.dir/example.o')
                for name in ('common','tests','world','zone')]
            (output/'compile_commands.json').write_text(json.dumps(entries))
            binary = output/'bin/tests_sanitizer_controls'
            fixture = ('#!/usr/bin/python3\nimport sys\nmode=sys.argv[1]\n'
                + 'text={"pass":"ok","use-after-free":"heap-use-after-free",'
                + '"out-of-bounds":"heap-buffer-overflow","undefined":"runtime error: overflow",'
                + '"leak":"LeakSanitizer detected memory leaks"}[mode]\n'
                + 'print(text+" sanitizer_controls.cpp:10",flush=True)\n'
                + 'raise SystemExit(0 if mode=="pass" else 1)\n')
            binary.write_text(fixture); binary.chmod(0o700)
            seen = []
            def command(name, argv, **kwargs):
                seen.append(name)
                if name.startswith('sanitizer-control-') and name not in ('sanitizer-control-build','sanitizer-control-linkage'):
                    return build_guest.command(name, argv, **kwargs)
                if name == 'sanitizer-control-linkage': return 'NEEDED libasan.so\nNEEDED libubsan.so\n'
                if '-print-file-name=' in ' '.join(argv): return str(binary)
                return 'trusted metadata fixture'
            fake = SimpleNamespace(command=command, COMPLETED=[])
            with patch.object(build_guest,'DEADLINE',time.monotonic()+30):
                report = sanitizers.controls(fake, output)
                self.assertTrue(report['qualified'])
                self.assertEqual([item['returncode'] for item in report['controls']],[0,1,1,1,1])
                self.assertEqual(fake.COMPLETED,['sanitizer-controls'])
                binary.write_text(fixture.replace('else 1','else 0'))
                with self.assertRaisesRegex(RuntimeError,'did not qualify') as caught:
                    sanitizers.controls(fake, output)
                self.assertFalse(caught.exception.sanitizers['qualified'])
                self.assertEqual(caught.exception.sanitizers['controls'][-1]['returncode'],0)


class Admission(unittest.TestCase):
    def test_isolated_operator_starts_at_printed_installation_depth_without_local_imports(self):
        # /tmp/file.py has the same two-parent depth as /root/file.py; no real
        # root directory, policy admission or VM execution is involved.
        fd, name = tempfile.mkstemp(prefix='eqemu-asan-operator-',suffix='.py',dir='/tmp')
        os.close(fd); path = Path(name)
        try:
            path.write_bytes(Path(operator.__file__).read_bytes())
            with tempfile.TemporaryDirectory() as temporary:
                (Path(temporary)/'argparse.py').write_text('raise RuntimeError("untrusted import executed")')
                result = subprocess.run(['/usr/bin/python3','-I',str(path),'--help'],cwd=temporary,
                    capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('apply,rollback',result.stdout)
        finally: path.unlink()

    def prepared(self, temporary):
        output = Path(temporary) / 'package'
        # Supply retained host inputs as data; tests never depend on installed
        # policy/runtime files and never publish onto actual system paths.
        import pwd
        from staging import FILES
        current = dict(version=1, user='worker', worker_uid=os.getuid(), worker_gid=os.getgid(),
            code_dir='/srv/eqemu-validator-code', state_dir='/var/lib/eqemu-validator',
            socket='/run/eqemu-validator.sock', base_image='/public/base',
            submitter=pwd.getpwuid(os.getuid()).pw_name)
        retained = {path: ('retained ' + str(path)).encode() for path in (*operator.ORDINARY, *operator.RETAINED_V1)}
        retained[operator.CONFIG] = json.dumps(current).encode()
        retained.update({Path(current['code_dir']) / name: ('ordinary ' + name).encode() for name in FILES})
        original_load = operator.load
        def load(path, *args):
            return retained[path] if path in retained else original_load(path, *args)
        with patch.object(operator, 'run', side_effect=['a'*40 + '\n', '']), \
                patch.object(operator, 'load', side_effect=load), patch.object(operator.os, 'geteuid', return_value=1000):
            summary = operator.prepare(output)
        return output, summary

    def test_package_is_finite_hashed_separate_and_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, summary = self.prepared(temporary)
            manifest, data, targets = operator.package(output, summary['manifest_sha256'])
            self.assertEqual(manifest['configuration']['diagnostic_profile'], sanitizers.PROFILE)
            self.assertEqual(manifest['configuration']['state_dir'], '/var/lib/eqemu-validator/asan-v2')
            self.assertEqual(manifest['configuration']['diagnostic_policy'], operator.NAME)
            self.assertEqual(manifest['configuration']['code_dir'], '/srv/eqemu-validator-asan-v2/' + 'a'*40)
            self.assertEqual(manifest['configuration']['socket'], '/run/eqemu-validator-asan-v2.sock')
            self.assertEqual(set(manifest['retained_v1_sha256']), {str(path) for path in operator.RETAINED_V1})
            self.assertTrue({str(path) for path in operator.ORDINARY} <= set(manifest['ordinary_sha256']))
            self.assertTrue(all(path not in targets.values() for path in (*operator.ORDINARY, *operator.RETAINED_V1)))
            self.assertEqual(targets['config.json'], Path('/etc/eqemu-validator/asan-v2.json'))
            self.assertEqual(targets['worker.socket'].name, operator.NAME + '.socket')
            self.assertEqual(targets['worker.service'].name, operator.NAME + '@.service')
            self.assertEqual(targets['apparmor'].name, operator.NAME)
            self.assertEqual(summary['apply'][:2], ['/usr/bin/python3', '-I'])
            self.assertEqual(summary['rollback'][:2], ['/usr/bin/python3', '-I'])
            self.assertIn(b'MemoryMax=6G', data['worker.service'])
            self.assertIn(b'CPUQuota=200%', data['worker.service'])
            self.assertIn(b'PrivateNetwork=yes', data['worker.service'])
            self.assertIn(b'/var/lib/eqemu-validator/worker.lock rwk,', data['apparmor'])
            self.assertNotIn(b'/var/lib/eqemu-validator/** rwk,', data['apparmor'])
            self.assertNotIn(Path('/etc/systemd/system/eqemu-validator.socket'), targets.values())
            (output / 'worker.service').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'bytes changed'): operator.package(output, summary['manifest_sha256'])

    def test_preconditions_preserve_all_assets_and_require_all_three_workers_idle(self):
        from staging import FILES
        current = dict(code_dir='/srv/eqemu-validator-code', state_dir='/var/lib/eqemu-validator',
            socket='/run/eqemu-validator.sock')
        assets = {path: str(path).encode() for path in (*operator.ORDINARY, *operator.RETAINED_V1,
            *(Path(current['code_dir']) / name for name in FILES if name != 'validation/worker/sanitizers.py'))}
        assets[operator.CONFIG] = json.dumps(current).encode()
        ordinary = {str(path): operator.sha(data) for path, data in assets.items() if path not in operator.RETAINED_V1}
        manifest = dict(configuration=dict(current, code_dir='/srv/eqemu-validator-asan-v2/' + 'a'*40,
            state_dir=str(operator.STATE), socket='/run/' + operator.NAME + '.sock',
            diagnostic_profile=operator.PROFILE, diagnostic_policy=operator.NAME),
            ordinary_sha256=ordinary, retained_v1_sha256={str(path): operator.sha(assets[path]) for path in operator.RETAINED_V1})
        with patch.object(operator.os, 'geteuid', return_value=0), \
                patch.object(operator, 'load', side_effect=lambda path: assets[path]), \
                patch.object(operator, 'run', return_value='') as run, \
                patch.object(Path, 'exists', return_value=False):
            self.assertEqual(operator.preconditions(manifest), current)
            self.assertEqual(run.call_args.args[0][-3:], ['eqemu-validator@*.service',
                'eqemu-validator-asan-v1@*.service', 'eqemu-validator-asan-v2@*.service'])
            for path in assets:
                original = assets[path]; assets[path] += b'changed'
                with self.subTest(changed=path), self.assertRaisesRegex(ValueError, 'policy changed'):
                    operator.preconditions(manifest)
                assets[path] = original
            for unit in run.call_args.args[0][-3:]:
                with patch.object(operator, 'run', return_value=unit), self.assertRaisesRegex(ValueError, 'connections'):
                    operator.preconditions(manifest)
            for state in (Path(current['state_dir']), operator.RETAINED_STATE, operator.STATE):
                with patch.object(Path, 'exists', lambda path: path == state / 'active.json'), \
                        self.assertRaisesRegex(ValueError, 'active record'):
                    operator.preconditions(manifest)
            incomplete = copy.deepcopy(manifest); incomplete['retained_v1_sha256'].pop(str(operator.RETAINED_V1[0]))
            with self.assertRaisesRegex(ValueError, 'inventory'): operator.preconditions(incomplete)

    def test_admission_contends_for_ordinary_lock_before_publishing(self):
        with tempfile.TemporaryDirectory() as temporary:
            output, summary = self.prepared(temporary)
            state = Path(temporary) / 'state'; state.mkdir()
            lock = state / 'worker.lock'; lock.touch(mode=0o600)
            fd = os.open(lock, os.O_RDWR)
            current = dict(state_dir=str(state), worker_uid=os.getuid(), worker_gid=os.getgid())
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(operator, 'root_operator'), \
                        patch.object(operator, 'preconditions', return_value=current), \
                        patch.object(operator, 'publish') as publish, patch.object(operator, 'run') as run:
                    with self.assertRaises(BlockingIOError): operator.operate(output, summary['manifest_sha256'])
                    publish.assert_not_called(); run.assert_not_called()
            finally: os.close(fd)
            lock.chmod(0o644)
            with patch.object(operator, 'root_operator'), \
                    patch.object(operator, 'preconditions', return_value=current), \
                    patch.object(operator, 'publish') as publish, patch.object(operator, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'lock ownership/mode'):
                    operator.operate(output, summary['manifest_sha256'])
                publish.assert_not_called(); run.assert_not_called()

    def test_partial_publish_policy_and_socket_failures_roll_back_only_matching_additions(self):
        for failure in ('publish-first', 'publish-middle', 'publish-last', 'sync-first', 'sync-after-link', 'apparmor', 'socket'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                output, summary = self.prepared(temporary)
                root = Path(temporary) / 'host'; root.mkdir()
                parent = root / 'srv'; parent.mkdir()
                state = root / 'state'; state.mkdir(); (state / 'worker.lock').touch(mode=0o600)
                config = root / 'etc/asan.json'; config.parent.mkdir()
                retained = {root / 'ordinary-policy': b'ordinary retained', root / 'v1-policy': b'v1 retained'}
                for path, data in retained.items(): path.write_bytes(data)
                v1_state = state / 'asan-v1'; v1_state.mkdir(); (v1_state / 'audit').write_bytes(b'v1 evidence')
                loaded = False; published = 0
                real_publish = operator.publish
                manifest = json.loads((output / 'manifest.json').read_text())
                fail_index = {'publish-first':0,'publish-middle':5,'publish-last':len(manifest['files'])-1}.get(failure)
                failed = False
                syncs = 0; real_fsync = os.fsync
                def sync(fd):
                    nonlocal syncs, failed
                    syncs += 1
                    wanted = 1 if failure == 'sync-first' else 2 if failure == 'sync-after-link' else None
                    if syncs == wanted:
                        failed = True; raise OSError('injected fsync failure')
                    return real_fsync(fd)
                def publish(path, data, mode=0o644):
                    nonlocal published, failed
                    if not failed and published == fail_index:
                        failed = True; raise OSError('injected publish failure')
                    published += 1; real_publish(path,data,mode)
                def run(argv):
                    nonlocal loaded, failed
                    if '--replace' in argv:
                        if failure == 'apparmor' and not failed:
                            failed = True; raise RuntimeError('injected policy load failure')
                        loaded = True
                    if '--remove' in argv: loaded = False
                    if 'start' in argv and failure == 'socket' and not failed:
                        failed = True; raise RuntimeError('injected socket start failure')
                    return ''
                original_read = Path.read_text
                def read(path, *args, **kwargs):
                    if str(path) == '/sys/kernel/security/apparmor/profiles':
                        return operator.NAME + ' (enforce)\n' if loaded else ''
                    return original_read(path,*args,**kwargs)
                current = dict(state_dir=str(state),worker_uid=os.getuid(),worker_gid=os.getgid())
                with patch.object(operator,'PARENT',parent/'diagnostic'), patch.object(operator,'STATE',state/'asan-v2'), \
                     restrictive_umask(), \
                     patch.object(operator,'DIAGNOSTIC_CONFIG',config), \
                     patch.object(operator,'root_operator'), \
                     patch.object(operator,'preconditions',return_value=current), \
                     patch.object(operator,'protected'), patch.object(operator,'publish',side_effect=publish), \
                     patch.object(operator,'run',side_effect=run), patch.object(operator.os,'chown'), \
                     patch.object(operator.os,'fsync',side_effect=sync), \
                     patch.object(Path,'read_text',read):
                    # Map policy targets into the fake host, never actual /etc.
                    original_targets = operator.expected_targets
                    def targets(value):
                        found = original_targets(value)
                        for name in ('worker.socket','worker.service','apparmor'):
                            found[name] = config.parent / name
                        return found
                    with patch.object(operator,'expected_targets',side_effect=targets):
                        with self.assertRaises((OSError,RuntimeError)):
                            operator.operate(output,summary['manifest_sha256'])
                        self.assertTrue(failed)
                        result = operator.operate(output,summary['manifest_sha256'],rollback=True)
                        self.assertTrue(result['rolled_back'])
                        self.assertFalse(loaded)
                        self.assertFalse(config.exists())
                        self.assertTrue((state/'worker.lock').exists())
                        self.assertEqual((v1_state / 'audit').read_bytes(), b'v1 evidence')
                        for path, data in retained.items(): self.assertEqual(path.read_bytes(), data)
                        self.assertTrue((parent / 'diagnostic' / manifest['source_commit']).exists())
                        if failure in ('apparmor', 'socket'): self.assertTrue((state / 'asan-v2').exists())
                        for directory in (parent/'diagnostic').rglob('*'):
                            if directory.is_dir(): self.assertEqual(directory.stat().st_mode & 0o777,0o755)
                        self.assertTrue(operator.operate(output,summary['manifest_sha256'],rollback=True)['rolled_back'])


if __name__ == '__main__': unittest.main()
