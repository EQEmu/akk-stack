"""Trusted Python process/adapter probes; no candidate binary or VM execution."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
sys.path.insert(0, str(ROOT / 'validation'))
import actor_runtime
import normal_world as normal
from test_normal_world import baseline


class AdapterDiagnostics(unittest.TestCase):
    def replay(self, cleanup, large=False, database_error=False, cancel_root=False, source=False, sanitizer=False, changed_config=False):
        """Reach run's real command/pipe/scrubbing seam with a harmless Python producer."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build = types.SimpleNamespace(DEADLINE=time.monotonic()+10000, WORK=root/'build',
                LOGS=root/'logs', ENV=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'),
                emit=Mock(), sha=lambda _: 'b'*64, CandidateFailure=type('CandidateFailure', (Exception,), {}))
            if sanitizer:
                build.ENV['ASAN_OPTIONS'] = 'detect_leaks=1'
            build.LOGS.mkdir()
            frame = baseline()
            for key in ('fixture_manifest_sha256', 'binaries', 'database_cleanup'):
                del frame[key]
            frame.update(exit_code=1 if cleanup else 2, control='assertion', cleanup_complete=cleanup,
                         error='In-server test assertions failed')
            frame['inserver_tests'].update(failed=1, passed=False)
            frame['inserver_tests']['tests'][0].update(passed=False,
                diagnostic='deliberate assertion guest-secret')
            if source:
                log = root/'zone-console.log'
                log.write_bytes((b'/fixture.cpp:1: runtime error: ' + b'x'*960 + b'guest-secret\n' if sanitizer else b'')
                    + b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT result=failed guest-secret\n'
                    b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n#0 native_function guest-secret\n'
                    b'EQEMU_NATIVE_DIAGNOSTIC_STACK_END\n' + b'later console\n'*11000)
                with patch.dict(os.environ, {'ASAN_OPTIONS': 'detect_leaks=1'} if sanitizer else {}):
                    frame['failure_evidence'] = normal.failure_snapshot(
                        [Mock(pid=2000000000, poll=Mock(return_value=None))], [log],
                        'c'*32, time.monotonic(), dict(condition='udp-timeout'), ('guest-secret',) if sanitizer else ())
            if not cleanup:
                frame['cleanup_diagnostics'] = dict(forced_kill=True,
                    survivors_before_kill=[dict(pid=123, name='python-child', state='S')],
                    survivors_after_kill=[], child_exits=[-15, -9])
            if large:
                frame['cleanup_diagnostics']['survivors_before_kill'] *= 8
                frame['inserver_tests'].update(selected=32, started=32, completed=32, failed=32)
                frame['inserver_tests']['tests'] = [dict(name='case-'+str(n), passed=False,
                    diagnostic='deliberate assertion guest-secret ' + 'x'*220) for n in range(32)]
            output = 'NORMAL_WORLD_READY\nNORMAL_WORLD_RESULT ' + json.dumps(frame) + '\n'
            class ReplayRuntime(actor_runtime.Runtime):
                def guard(self):
                    if cancel_root and self.cancelled: return super().guard()
                def verify_inputs(self): pass
                def install_packages(self): pass
                def initialize_database(self): pass
                def import_database(self): pass
                def query(self, label, sql):
                    return '202\t0\tpoknowledge\t0' if label == 'normal-activity-check' else ''
                def configure(self):
                    server = root/'runtime/server'; server.mkdir()
                    (server/'eqemu_config.json').write_text('{"server":{"world":{}}}')
                    shared = server/'shared'; shared.mkdir()
                    for name in ('items', 'spells'): (shared/name).write_text('fixture')
                    self.secrets.extend(('guest-secret', 'guest-key'))
                    return server
                def command(self, name, args, **kwargs):
                    if name == 'normal-shared-memory' and changed_config:
                        (root/'runtime/server/eqemu_config.json').write_text(
                            '{"server":{"database":{"password":"candidate-replacement"},"world":{"key":"candidate-replacement"}}}')
                    if name != 'normal-world': return ''
                    script = 'print('+repr(output)+',end="")'
                    if changed_config:
                        script = ('import sys,time,json; from pathlib import Path; '
                                  'sys.path.insert(0,'+repr(str(ROOT/'validation/worker'))+'); '
                                  'import normal_world as normal; '
                                  'original=normal.read_observer_secrets(); '
                                  'assert original == ["guest-secret","guest-key"]; '
                                  'frame='+repr(frame)+'; '
                                  'frame["failure_evidence"]=normal.failure_snapshot([], [Path('+repr(str(log))+')], '
                                  '"c"*32,time.monotonic(),dict(condition="child-exit"),original); '
                                  'print("NORMAL_WORLD_RESULT "+json.dumps(frame))')
                    if cancel_root:
                        script = ('import os,signal,time; from pathlib import Path; '
                                  'Path('+repr(str(root/'observer.pid'))+').write_text(str(os.getpid())); '
                                  'os.kill(os.getppid(),signal.SIGTERM); time.sleep(30)')
                    return super().command(name,
                        [sys.executable, '-c', script],
                        on_line=kwargs['on_line'], timeout=10,
                        **({'stdin': kwargs['stdin']} if 'stdin' in kwargs else {}))
                def cleanup(self):
                    if database_error: raise RuntimeError('database cleanup guest-secret failed')
                    return True
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if str(path) == '/opt/runtime-fixture.json':
                    return '{"manifest_sha256":"'+'a'*64+'"}'
                return original_read(path, *args, **kwargs)
            with patch.object(actor_runtime, 'Runtime', ReplayRuntime), \
                    patch.object(actor_runtime, 'ROOT', root/'runtime'), \
                    patch.object(actor_runtime, 'MEDIA', root/'media'), \
                    patch.object(normal.os, 'geteuid', return_value=0), \
                    patch.object(normal.os, 'chown'), \
                    patch.object(normal.Path, 'is_file', return_value=True), \
                    patch.object(normal.Path, 'read_text', read):
                try:
                    normal.run(build, dict(world_control='assertion'))
                except Exception as error:
                    if cancel_root:
                        pid = int((root/'observer.pid').read_text())
                        self.assertFalse(Path('/proc', str(pid)).exists())
                    return error, build.CandidateFailure
            self.fail('Assertion replay passed')

    def test_shared_memory_config_changes_cannot_replace_authoritative_scrub_snapshot(self):
        error, candidate_failure = self.replay(True, source=True, sanitizer=True, changed_config=True)
        self.assertIsInstance(error, candidate_failure)
        first = error.result['failure_evidence']['first_sanitizer_diagnostic']['zone-console.log']
        self.assertIn('*', first['text'])
        self.assertNotIn('guest', first['text'])
        self.assertNotIn('guest-secret', json.dumps(error.result))
        self.assertTrue(error.result['cleanup_complete'])
        self.assertTrue(error.result['database_cleanup'])

    def test_guest_root_cancellation_is_infrastructure_without_invented_observer_evidence(self):
        error, candidate_failure = self.replay(True, cancel_root=True)
        self.assertIs(type(error), RuntimeError)
        self.assertNotIsInstance(error, candidate_failure)
        self.assertIsNone(error.result)
        self.assertIn('interrupted', str(error))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(normal.export_evidence(dict(exit_code=2, candidate='a'*40,
                run_id='b'*32, guest={}), 'a'*40, tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_database_cleanup_exception_preserves_scrubbed_native_result(self):
        error, candidate_failure = self.replay(True, database_error=True)
        self.assertIs(type(error), RuntimeError)
        self.assertNotIsInstance(error, candidate_failure)
        self.assertIs(error.result['database_cleanup'], False)
        self.assertIs(error.result['cleanup_complete'], True)
        self.assertIn('database cleanup', error.result['adapter_error'])
        self.assertIn('deliberate assertion', json.dumps(error.result))
        self.assertNotIn('guest-secret', json.dumps(error.result))
        self.assertNotIn('guest-secret', str(error))

    def test_complete_failed_suite_with_cleanup_is_candidate_failure(self):
        error, candidate_failure = self.replay(True)
        self.assertIsInstance(error, candidate_failure)
        self.assertIn('deliberate assertion', str(error))
        self.assertNotIn('guest-secret', str(error))
        self.assertNotIn('guest-secret', json.dumps(error.result))

    def test_incomplete_cleanup_stays_infrastructure_and_retains_scrubbed_evidence(self):
        error, candidate_failure = self.replay(False)
        self.assertIs(type(error), RuntimeError)
        self.assertNotIsInstance(error, candidate_failure)
        for evidence in ('cleanup_complete', 'forced_kill', 'python-child', 'deliberate assertion'):
            self.assertIn(evidence, str(error))
        self.assertNotIn('guest-secret', str(error))
        self.assertNotIn('guest-secret', json.dumps(error.result))
        self.assertLessEqual(len(str(error)), 3500)
        error, _ = self.replay(False, large=True)
        self.assertIs(type(error), RuntimeError)
        self.assertIn('forced_kill', str(error))
        self.assertNotIn('guest-secret', str(error))
        self.assertNotIn('guest-secret', json.dumps(error.result))
        self.assertLessEqual(len(str(error)), 3500)


class RealOwnedShutdown(unittest.TestCase):
    def test_real_python_children_distinguish_graceful_shutdown_from_forced_rescue(self):
        # The controller owns a new session. Its harmless Python children exercise
        # the actual /proc membership scan, TERM grace, KILL rescue and wait chain.
        controller = r"""
import json, signal, subprocess, sys
sys.path.insert(0, sys.argv[1])
import normal_world
mode = sys.argv[2]
child = '''import signal, sys, time
mode = sys.argv[1]
def stop(*_):
    if mode == 'ignore': return
    if mode == 'delayed': time.sleep(.1)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
print('ready', flush=True)
while True: signal.pause()
'''
children = [subprocess.Popen([sys.executable, '-B', '-c', child, selected], stdout=subprocess.PIPE)
            for selected in ('immediate', mode)]
for process in children:
    assert process.stdout.readline() == b'ready\n'
diagnostics = {}
clean = normal_world.stop(children, diagnostics=diagnostics)
for process in children: process.stdout.close()
print(json.dumps(dict(clean=clean, diagnostics=diagnostics, pids=[p.pid for p in children])))
"""
        for mode in ('immediate', 'delayed', 'ignore'):
            with self.subTest(mode=mode):
                process = subprocess.Popen([sys.executable, '-B', '-c', controller,
                    str(ROOT/'validation/worker'), mode], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=True)
                try:
                    stdout, stderr = process.communicate(timeout=20)
                    self.assertEqual(process.returncode, 0, stderr.decode())
                    result = json.loads(stdout)
                    self.assertEqual(result['clean'], mode != 'ignore', result)
                    for pid in result['pids']:
                        self.assertFalse(Path('/proc', str(pid)).exists())
                    if mode == 'ignore':
                        diagnostic = result['diagnostics']
                        self.assertTrue(diagnostic['forced_kill'])
                        self.assertEqual(diagnostic['grace_seconds'], 10)
                        self.assertEqual(len(diagnostic['survivors_before_kill']), 1)
                        self.assertEqual(diagnostic['survivors_before_kill'][0]['pid'], result['pids'][1])
                        self.assertEqual(diagnostic['survivors_after_kill'], [])
                        self.assertEqual(diagnostic['child_exits'][1]['returncode'], -signal.SIGKILL)
                    else:
                        self.assertEqual(result['diagnostics'], {})
                finally:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait(timeout=5)
                    process.stdout.close(); process.stderr.close()


if __name__ == '__main__':
    unittest.main()
