"""Trusted Python/fake server controls only; no candidate binaries or VM launched."""
import contextlib
import io
import itertools
import json
import os
import sqlite3
import types
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import normal_world as normal
import guest
import staging


def suite(run_id='a'*32, failed=False):
    return dict(version=1, run_id=run_id, suite='zone', selected=1, started=1, completed=1,
                failed=int(failed), finalized=True, passed=not failed,
                tests=[dict(name='native.case', passed=not failed,
                            diagnostic='deliberate assertion' if failed else '')])


def baseline():
    return dict(exit_code=0, cleanup_complete=True, control=None, ready_seconds=1.0,
                baseline_seconds=5.1, responsive_samples=40, cpu_ticks=[1, 4], clock_ticks_per_second=100,
                fixture_manifest_sha256='a'*64, binaries={n: 'b'*64 for n in ('world', 'zone', 'shared_memory')},
                database_cleanup=True, inserver_tests=suite())


class Completion(unittest.TestCase):
    def test_success_requires_independent_observation_and_complete_cleanup(self):
        self.assertEqual(normal.validate(baseline()), baseline())
        for field, value in [('exit_code', True), ('control', 'assertion'), ('control', 'startup'),
                             ('control', 'cancel'), ('cleanup_complete', False), ('database_cleanup', False),
                             ('ready_seconds', float('nan')), ('baseline_seconds', 4.9),
                             ('responsive_samples', 0), ('cpu_ticks', [1, 0]), ('cpu_ticks', [0, True]),
                             ('binaries', {}), ('fixture_manifest_sha256', 'unknown')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                normal.validate(dict(baseline(), **{field: value}))
        for field in baseline():
            changed = baseline(); del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                normal.validate(changed)

    def test_seed_and_staging_include_every_guest_helper(self):
        config = json.loads(guest.build_user_data('a'*32).split('\n', 1)[1])
        files = {item['path']: item for item in config['write_files']}
        for name in ('normal_world.py', 'actor.py', 'actor_runtime.py', 'debugger.py', 'runtime-fixture.json'):
            self.assertIn('/opt/' + name, files)
        self.assertIn('normal-world', guest.BUILD_CHECKS)
        for name in ('validation/worker/normal_world.py', 'validation/actor_runtime.py', 'validation/runtime-fixture.json'):
            self.assertIn(name, staging.FILES)


class ActivityConfiguration(unittest.TestCase):
    def test_run_configures_native_zone_row_before_boot_and_refuses_bad_state(self):
        # Execute the production SQL against a small relational fixture, not a
        # mock returning the exact string the implementation wants to see.
        cases = ('valid', 'missing', 'wrong-id', 'wrong-version', 'wrong-name', 'duplicate',
                 'null-readback', 'ignored-write', 'write-error', 'missing-column')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp, sqlite3.connect(':memory:') as db:
                columns = 'zoneidnumber INTEGER, version INTEGER, short_name TEXT'
                if case != 'missing-column':
                    columns += ', idle_when_empty INTEGER, seconds_before_idle INTEGER'
                db.execute('CREATE TABLE zone (' + columns + ')')
                row = (203 if case == 'wrong-id' else 202, 1 if case == 'wrong-version' else 0,
                       'other' if case == 'wrong-name' else 'poknowledge', 1, 60)
                if case == 'missing-column':
                    row = row[:3]
                if case != 'missing':
                    db.execute('INSERT INTO zone VALUES (' + ','.join('?' for _ in row) + ')', row)
                if case == 'duplicate':
                    db.execute("INSERT INTO zone VALUES (202,0,'poknowledge',1,60)")
                # An unrelated version must never be modified.
                if case != 'missing-column':
                    db.execute("INSERT INTO zone VALUES (202,2,'poknowledge',1,90)")
                runtime = Mock()
                def query(label, sql):
                    if label == 'normal-activity':
                        if case == 'write-error':
                            raise RuntimeError('write refused')
                        if case in ('ignored-write', 'null-readback'):
                            if case == 'null-readback':
                                db.execute('UPDATE zone SET idle_when_empty=NULL')
                            return ''
                    cursor = db.execute(sql)
                    return '\n'.join('\t'.join('NULL' if v is None else str(v) for v in r) for r in cursor.fetchall())
                runtime.query.side_effect = query
                runtime.configure.side_effect = RuntimeError('configuration reached after readback')
                runtime.cleanup.return_value = True
                runtime.scrub.side_effect = str
                fake = types.SimpleNamespace(Runtime=Mock(return_value=runtime),
                    ROOT=Path(tmp)/'runtime', MEDIA=Path(tmp)/'media')
                build = Mock(DEADLINE=normal.time.monotonic()+10000, WORK=Path(tmp)/'build')
                with patch.dict(sys.modules, actor_runtime=fake), \
                        patch.object(normal.os, 'geteuid', return_value=0), \
                        patch.object(normal.Path, 'is_file', return_value=True), \
                        patch.object(normal.Path, 'read_text', return_value='{}'):
                    with self.assertRaises(RuntimeError):
                        normal.run(build, {})
                runtime.initialize_database.assert_called_once()
                runtime.import_database.assert_called_once()
                runtime.cleanup.assert_called_once()
                self.assertEqual(runtime.configure.call_count, int(case == 'valid'))
                # Neither shared_memory nor the observer/native children can run
                # after a refused write/readback. Mounting is the sole command.
                self.assertEqual([c.args[0] for c in runtime.command.call_args_list], ['normal-mount-runtime'])
                build.emit.assert_not_called()
                if case == 'valid':
                    self.assertEqual(db.execute('SELECT idle_when_empty,seconds_before_idle FROM zone ORDER BY version').fetchall(),
                                     [(0, 60), (1, 90)])


class Readiness(unittest.TestCase):
    def test_udp_socket_or_wrong_session_is_not_application_readiness(self):
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream); stream.__exit__ = Mock(return_value=False)
        stream.getsockname.return_value = ('127.0.0.1', 40000)
        challenge = b'abcd'
        for response, expected in [(b'', False), (b'\x00\x02xxxx', False), (b'\x00\x01abcd', False),
                                   (b'\x00\x02abcd', True)]:
            with self.subTest(response=response), patch.object(normal.os, 'urandom', return_value=challenge), \
                    patch.object(normal.socket, 'socket', return_value=stream):
                stream.recv.return_value = response
                self.assertIs(normal.probe(), expected)
        with patch.object(normal.socket, 'socket', return_value=stream):
            stream.recv.side_effect = TimeoutError
            self.assertFalse(normal.probe())

    def test_established_connection_must_belong_to_both_owned_native_pids(self):
        rows = ('header\n0: 0100007F:C001 0100007F:2328 01 0 0 0 0 0 11\n'
                '1: 0100007F:2328 0100007F:C001 01 0 0 0 0 0 22\n')
        with patch.object(normal.Path, 'read_text', return_value=rows), \
                patch.object(normal, 'socket_inodes', side_effect=[{'22'}, {'11'}]):
            self.assertTrue(normal.world_connected(1, 2))
        with patch.object(normal.Path, 'read_text', return_value=rows), \
                patch.object(normal, 'socket_inodes', side_effect=[{'99'}, {'11'}]):
            self.assertFalse(normal.world_connected(1, 2))


    def test_cleanup_checks_descendants_and_forced_rescue_is_not_success(self):
        process = Mock(pid=101)
        with patch.object(normal, 'owned_members', return_value=[]), patch.object(normal.os, 'kill') as kill:
            self.assertTrue(normal.stop([process]))
            kill.assert_not_called()
        with patch.object(normal, 'owned_members', return_value=[101, 102]), \
                patch.object(normal.os, 'kill') as kill, \
                patch.object(normal.time, 'monotonic', side_effect=itertools.count(0, 20)), \
                patch.object(normal.time, 'sleep'):
            self.assertFalse(normal.stop([process]))
            self.assertTrue(any(call.args[0] == 102 for call in kill.call_args_list))
            self.assertTrue(any(call.args[1] == normal.signal.SIGKILL for call in kill.call_args_list))

    def run_observer(self, control=None, died=False, interrupt=False, mode="valid", clean=True, sanitizer=False):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp)
            if sanitizer:
                (server/'eqemu_config.json').write_text(json.dumps({'server': {
                    'database': {'password': '0123456789abcdef'*3},
                    'world': {'key': 'fedcba9876543210'*3}}}))
            world, zone = Mock(pid=101), Mock(pid=102)
            world.poll.return_value = 1 if died else None
            zone.poll.return_value = None
            if mode == 'crash':
                zone.poll.side_effect = itertools.chain([None]*10, itertools.repeat(1))
            output = io.StringIO()
            probes = [True, RuntimeError('cancelled')] if interrupt else None
            if mode == 'baseline-response-loss':
                probes = [True, False]
            if mode == 'probe-allocation-exhausted':
                def probes(*, used_ports, diagnostics):
                    diagnostics.update(condition='udp-allocation-exhausted', source_port=40000,
                                       discarded_allocations=normal.PROBE_ALLOCATION_ATTEMPTS)
                    raise RuntimeError('Unused UDP probe source port allocation exhausted')
            connections = [True, False] if mode == 'baseline-world-loss' else None
            if mode == 'observer-cancel':
                def connections(*_):
                    normal.signal.raise_signal(normal.signal.SIGTERM)
                    return True
            children = []
            reports = []
            def launch(args, **kwargs):
                env = kwargs['env']
                if sanitizer:
                    kwargs['stdout'].write(b'runtime error: ' + b'x'*960
                        + ('0123456789abcdef'*3).encode() + b' later\n'*1200)
                    kwargs['stdout'].flush()
                if Path(args[0]).name == 'world':
                    self.assertFalse(any(key.startswith('EQEMU_INSERVER_TEST_') for key in env))
                    process = world
                else:
                    self.assertEqual(env.get('EQEMU_INSERVER_TEST_CONTROL'),
                                     'assertion' if control == 'assertion' else None)
                    path = Path(env['EQEMU_INSERVER_TEST_RESULT'])
                    self.assertFalse(path.exists())
                    value = suite(env['EQEMU_INSERVER_TEST_RUN'], control == 'assertion' and mode != 'unexpected-pass')
                    if mode not in ('missing', 'progress-hang'):
                        path.write_text('{bad' if mode == 'malformed' else json.dumps(value))
                    if mode == 'progress-hang':
                        events = [dict(version=1, run_id=env['EQEMU_INSERVER_TEST_RUN'], event=event,
                                       name=name, elapsed_ms=elapsed, **extra) for event, name, elapsed, extra in (
                            ('case-start', 'completed-case', 0, {}),
                            ('case-end', 'completed-case', 23, dict(passed=True, diagnostic='')),
                            ('case-start', 'hung-case', 0, {}))]
                        kwargs['stdout'].write(b'native-before-cleanup\n' + b'\n'.join(
                            b'EQEMU_INSERVER_PROGRESS '+json.dumps(event).encode() for event in events)+b'\n')
                        kwargs['stdout'].flush()
                    reports.append(path)
                    process = zone
                children.append(process)
                return process
            def cleanup(processes, *, diagnostics):
                if mode == 'cleanup-error':
                    raise RuntimeError('simulated stop failure')
                if mode == 'progress-hang':
                    (server/'zone-console.log').write_text('shutdown-noise'*10000)
                if mode == 'changed':
                    reports[0].write_text('{}')
                if mode == 'disappeared':
                    reports[0].unlink()
                if mode == 'replaced':
                    replacement = reports[0].with_suffix('.new')
                    replacement.write_bytes(reports[0].read_bytes())
                    replacement.replace(reports[0])
                return clean
            with patch.dict(os.environ, {'ASAN_OPTIONS': 'detect_leaks=1'} if sanitizer else {}), \
                    patch.object(normal.os, 'geteuid', return_value=65534), \
                    patch.object(normal.resource, 'setrlimit'), patch.object(normal.Path, 'is_file', return_value=True), \
                    patch.object(normal.subprocess, 'Popen', side_effect=launch) as popen, \
                    patch.object(normal, 'world_connected', side_effect=connections, return_value=True), \
                    patch.object(normal, 'probe', side_effect=probes, return_value=True) as probe, \
                    patch.object(normal, 'cpu_ticks', side_effect=[0, 0, 1, 4]), \
                    patch.object(normal, 'stop', side_effect=cleanup) as stop, \
                    patch.object(normal.time, 'monotonic', side_effect=itertools.count(0, .1)), \
                    patch.object(normal.time, 'sleep'), contextlib.redirect_stdout(output):
                normal.observe(Path('/never-execute-candidate'), server, control)
                stop.assert_called_once_with([world, zone], diagnostics=
                    {'error': 'simulated stop failure'} if mode == 'cleanup-error' else {})
                for call in popen.call_args_list:
                    self.assertNotIn('start_new_session', call.kwargs)
                if probe.call_args_list:
                    ports = probe.call_args_list[0].kwargs['used_ports']
                    self.assertIsInstance(ports, set)
                    self.assertTrue(all(call.kwargs['used_ports'] is ports for call in probe.call_args_list))
            if sanitizer:
                self.assertNotIn('0123456789', output.getvalue())
                self.assertNotIn('fedcba9876', output.getvalue())
            lines = output.getvalue().splitlines()
            frames = [json.loads(line.removeprefix('NORMAL_WORLD_RESULT ')) for line in lines
                      if line.startswith('NORMAL_WORLD_RESULT ')]
            self.assertEqual(len(frames), 1)
            return frames[0]

    def test_sanitized_observer_scrubs_config_credentials_before_excerpt_and_print(self):
        result = self.run_observer(died=True, sanitizer=True)
        self.assertEqual(result['exit_code'], 1)
        self.assertTrue(result['cleanup_complete'])
        first = result['failure_evidence']['first_sanitizer_diagnostic']['world-console.log']
        self.assertIn('*', first['text'])
        self.assertNotIn('0123456789', first['text'])
        self.assertIn('runtime error:', first['text'])

    def test_direct_observer_cancellation_keeps_precleanup_state(self):
        result = self.run_observer(mode='observer-cancel')
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['failure_evidence']['observation']['condition'], 'cancelled')
        self.assertTrue(result['failure_evidence']['processes'])

    def test_probe_allocation_exhaustion_is_infrastructure_with_private_diagnostics(self):
        result = self.run_observer(mode='probe-allocation-exhausted')
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['failure_evidence']['observation'], dict(
            condition='udp-allocation-exhausted', last_success_ms=None, source_port=40000,
            discarded_allocations=normal.PROBE_ALLOCATION_ATTEMPTS))

    def test_cleanup_exception_still_emits_precleanup_evidence_and_nonpass(self):
        result = self.run_observer(mode='cleanup-error')
        self.assertEqual(result['exit_code'], 2)
        self.assertFalse(result['cleanup_complete'])
        self.assertIn('simulated stop failure', result['cleanup_error'])
        self.assertIn('failure_evidence', result)
        self.assertTrue(result['failure_evidence']['processes'])

    def test_hung_case_retains_progress_and_precleanup_console(self):
        result = self.run_observer(mode='progress-hang')
        self.assertEqual(result['exit_code'], 1)
        self.assertTrue(result['cleanup_complete'])
        self.assertNotIn('inserver_tests', result)
        evidence = result['failure_evidence']
        self.assertEqual(evidence['observation']['condition'], 'deadline')
        self.assertIsNotNone(evidence['observation']['last_success_ms'])
        self.assertEqual(evidence['progress']['last_completed_case']['name'], 'completed-case')
        self.assertEqual(evidence['progress']['active_case']['name'], 'hung-case')
        self.assertIn('native-before-cleanup', evidence['console']['zone-console.log'])
        self.assertNotIn('shutdown-noise', json.dumps(evidence))
        self.assertTrue(evidence['processes'])

    def test_startup_fault_defeats_current_and_parent_config_discovery(self):
        for control in (None, 'startup'):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as tmp:
                server = Path(tmp)
                config = server / 'eqemu_config.json'
                config.write_text('{"server": {}}')
                # Reproduce native File::FindEqemuConfigPath's two-directory
                # search, with the real positive fixture config still present.
                def find_config(cwd):
                    return next((p / 'eqemu_config.json' for p in (cwd, cwd.parent)
                                 if (p / 'eqemu_config.json').is_file()), None)
                old_cwd = server / 'old-missing-config'; old_cwd.mkdir()
                self.assertEqual(find_config(old_cwd), config)
                children = []
                def launch(args, *, cwd, stdin, stdout, stderr, env):
                    found = find_config(cwd)
                    process = Mock(pid=101 + len(children))
                    process.poll.return_value = 1 if found is None else None
                    stdout.write(b'config loaded\n' if found else b'missing configuration\n')
                    if Path(args[0]).name == 'zone':
                        Path(env['EQEMU_INSERVER_TEST_RESULT']).write_text(json.dumps(suite(env['EQEMU_INSERVER_TEST_RUN'])))
                    children.append((Path(args[0]).name, cwd, found, process))
                    return process
                output = io.StringIO()
                with patch.object(normal.os, 'geteuid', return_value=65534), \
                        patch.object(normal.resource, 'setrlimit'), \
                        patch.object(normal.Path, 'is_file', autospec=True,
                                     side_effect=lambda p: True if str(p) == '/opt/eqemu-worker-build-guest' else p.exists()), \
                        patch.object(normal.subprocess, 'Popen', side_effect=launch), \
                        patch.object(normal, 'world_connected', return_value=True) as connected, \
                        patch.object(normal, 'probe', return_value=True) as probe, \
                        patch.object(normal, 'cpu_ticks', side_effect=[0, 0, 1, 4]) as ticks, \
                        patch.object(normal, 'stop', return_value=True) as stop, \
                        patch.object(normal.time, 'monotonic', side_effect=itertools.count(0, .1)), \
                        patch.object(normal.time, 'sleep'), contextlib.redirect_stdout(output):
                    normal.observe(Path('/never-execute-candidate'), server, control)
                lines = output.getvalue().splitlines()
                result = json.loads(next(line.removeprefix('NORMAL_WORLD_RESULT ')
                                         for line in lines if line.startswith('NORMAL_WORLD_RESULT ')))
                stop.assert_called_once_with([child[3] for child in children], diagnostics={})
                self.assertTrue(result['cleanup_complete'])
                self.assertEqual(children[1][1:3], (server, config))  # zone unchanged
                self.assertEqual(config.read_text(), '{"server": {}}')
                if control == 'startup':
                    self.assertIsNone(children[0][2])
                    self.assertEqual(result['exit_code'], 2)
                    self.assertEqual(result['error'], 'Normal server exited before assertion completed')
                    self.assertNotIn('NORMAL_WORLD_READY', lines)
                    self.assertNotIn('ready_seconds', result)
                    self.assertNotIn('baseline_seconds', result)
                    self.assertIn('world-console.log: missing configuration', lines)
                    connected.assert_not_called(); probe.assert_not_called(); ticks.assert_not_called()
                else:
                    self.assertEqual(children[0][1:3], (server, config))
                    self.assertEqual(result['exit_code'], 0)
                    self.assertIn('NORMAL_WORLD_READY', lines)
                    self.assertGreaterEqual(result['baseline_seconds'], normal.BASELINE_SECONDS)

    def test_positive_and_assertion_startup_and_interruption_are_nonpass_with_cleanup(self):
        self.assertEqual(self.run_observer()['exit_code'], 0)
        self.assertEqual(self.run_observer('assertion')['exit_code'], 1)
        for value in (self.run_observer('startup', died=True), self.run_observer('cancel', interrupt=True)):
            self.assertEqual(value['exit_code'], 2)
            self.assertTrue(value['cleanup_complete'])


    def test_suite_noncompletion_malformed_changed_and_failed_cleanup_cannot_pass(self):
        for mode in ('missing', 'malformed', 'changed', 'disappeared', 'replaced'):
            with self.subTest(mode=mode):
                result = self.run_observer(mode=mode)
                self.assertEqual(result['exit_code'], 1, result)
                self.assertTrue(result['cleanup_complete'])
                self.assertGreaterEqual(result['baseline_seconds'], normal.BASELINE_SECONDS)
        result = self.run_observer(mode='crash')
        self.assertEqual(result['exit_code'], 1)
        self.assertTrue(result['cleanup_complete'])
        result = self.run_observer(clean=False)
        self.assertEqual(result['exit_code'], 2)
        self.assertFalse(result['cleanup_complete'])

    def test_baseline_world_or_response_loss_after_readiness_is_candidate_failure(self):
        for mode in ('baseline-world-loss', 'baseline-response-loss'):
            with self.subTest(mode=mode):
                result = self.run_observer(mode=mode)
                self.assertEqual(result['exit_code'], 1, result)
                self.assertTrue(result['cleanup_complete'])
                self.assertIn('ready_seconds', result)
                self.assertNotIn('baseline_seconds', result)
                self.assertIn('lost world connection or application responsiveness', result['error'])

    def test_assertion_control_requires_source_suite_failure_not_wrapper_failure(self):
        failed = self.run_observer('assertion')
        self.assertEqual(failed['exit_code'], 1)
        self.assertFalse(failed['inserver_tests']['passed'])
        self.assertEqual(failed['inserver_tests']['tests'][0]['diagnostic'], 'deliberate assertion')
        unexpected = self.run_observer('assertion', mode='unexpected-pass')
        self.assertEqual(unexpected['exit_code'], 1)
        self.assertIn('unexpectedly completed', unexpected['error'])
        self.assertTrue(unexpected['inserver_tests']['passed'])


class InserverProtocol(unittest.TestCase):
    def test_valid_success_and_honest_failure(self):
        for failed in (False, True):
            value = suite(failed=failed)
            self.assertEqual(normal.validate_inserver(value, 'a'*32), value)
        failed = dict(baseline(), inserver_tests=suite(failed=True))
        with self.assertRaises(ValueError):
            normal.validate(failed)

    def test_identity_counts_completeness_duplicates_and_diagnostics(self):
        cases = [('version', True), ('run_id', 'b'*32), ('suite', 'other'), ('selected', 0),
                 ('selected', True), ('started', 0), ('completed', 0), ('failed', True),
                 ('failed', 1), ('finalized', False), ('passed', False), ('tests', []),
                 ('tests', [dict(name='duplicate', passed=True, diagnostic='')]*2),
                 ('tests', [dict(name='', passed=True, diagnostic='')]),
                 ('tests', [dict(name='x'*65, passed=True, diagnostic='')]),
                 ('tests', [dict(name='x', passed=1, diagnostic='')]),
                 ('tests', [dict(name='x', passed=True, diagnostic='x'*257)])]
        for name, value in cases:
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                normal.validate_inserver(dict(suite(), **{name: value}), 'a'*32)
        for name in suite():
            value = suite(); del value[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                normal.validate_inserver(value)
        for size in (0, 33):
            value = suite(); value.update(selected=size, started=size, completed=size,
                tests=[dict(name=str(n), passed=True, diagnostic='') for n in range(size)])
            with self.assertRaises(ValueError):
                normal.validate_inserver(value)
        value = suite(); value.update(selected=32, started=32, completed=32,
            tests=[dict(name=str(n), passed=True, diagnostic='x'*256) for n in range(32)])
        with self.assertRaises(ValueError):
            normal.validate_inserver(value)
        value = suite(); value.update(selected=2, started=2, completed=2, tests=value['tests']*2)
        with self.assertRaises(ValueError):
            normal.validate_inserver(value)

    def test_bounded_fresh_regular_result_file_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'result.json'
            self.assertIsNone(normal.read_inserver(path, 'a'*32))
            path.write_text(json.dumps(suite()))
            self.assertEqual(normal.read_inserver(path, 'a'*32)[0], suite())
            for data in ('{bad', '{}', 'x'*4097, json.dumps(suite()).replace('"version": 1', '"version": 1,"version": 1')):
                path.write_text(data)
                with self.subTest(data=data[:50]), self.assertRaises(normal.InserverFailure):
                    normal.read_inserver(path, 'a'*32)
            path.unlink(); target = Path(tmp) / 'target'; target.write_text(json.dumps(suite()))
            path.symlink_to(target)
            with self.assertRaises(normal.InserverFailure):
                normal.read_inserver(path, 'a'*32)
            path.unlink(); os.mkfifo(path)
            with self.assertRaises(normal.InserverFailure):
                normal.read_inserver(path, 'a'*32)
            path.unlink(); path.mkdir()
            with self.assertRaises(normal.InserverFailure):
                normal.read_inserver(path, 'a'*32)


if __name__ == '__main__':
    unittest.main()
