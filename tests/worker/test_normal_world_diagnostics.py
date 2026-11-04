"""Trusted Python process/adapter probes; no candidate binary or VM execution."""
import json
import itertools
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


class FailureCapture(unittest.TestCase):
    def test_first_observation_is_latched_before_peer_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'meminfo').write_text('MemTotal: 4096 kB\nMemAvailable: 99 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n')
            (root/'vmstat').write_text('oom_kill 3\n')
            children = [Mock(pid=123, poll=Mock(return_value=None)), Mock(pid=124, poll=Mock(return_value=-9))]
            capture = normal.FailureCapture(time.monotonic(), proc=root)
            for name, child in zip(('world', 'zone'), children): capture.watch(name, child)
            capture.latch(children, 'child-exit', [None, -9])
            before = json.loads(json.dumps(capture.pre))
            children[0].poll.return_value = 0
            capture.latch(children, 'cancelled', [0, -9])
            self.assertEqual(capture.pre, before)
            self.assertEqual(capture.pre['first_observed_exited'], 'zone')
            self.assertEqual(capture.pre['processes'][0]['returncode'], None)
            self.assertLessEqual(len(normal.encoded(capture.pre)), 512)
            resources = capture.finish()
            normal.validate_capture(dict(pre_cleanup_observation=capture.pre, failure_resources=resources))
            self.assertEqual(resources['guest']['baseline']['oom_kill'], 3)
            self.assertEqual(resources['guest']['delta'], 0)
            self.assertLessEqual(len(normal.encoded(resources)), 1536)

    def proc_fixture(self, root, pid=123, ticks=100, rss=12, hwm=20):
        child = root/str(pid); child.mkdir(exist_ok=True)
        (child/'stat').write_text(str(pid)+' (hostile secret ) name) S '+'0 '*18+str(ticks)+'\n')
        (child/'status').write_text('Name: guest-secret\nVmRSS: '+str(rss)+' kB\nVmHWM: '+str(hwm)+' kB\n')
        (root/'meminfo').write_text('MemTotal: 4096 kB\nMemAvailable: 99 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n')
        (root/'vmstat').write_text('oom_kill 3\n')
        return Mock(pid=pid, poll=Mock(return_value=None))

    def test_numeric_sampling_identity_races_gaps_and_counter_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = self.proc_fixture(root)
            with patch.object(normal.time, 'monotonic', return_value=1):
                capture = normal.FailureCapture(1, proc=root); capture.watch('world', child); capture.sample()
            with patch.object(normal.time, 'monotonic', return_value=1.25):
                self.proc_fixture(root, rss=15, hwm=25); capture.sample()
            item = capture.children[0]
            self.assertEqual((item['samples'],item['rss_kib'],item['hwm_kib'],item['max_gap_ms']), (2,15,25,250))
            with patch.object(normal, 'start_ticks', side_effect=[100, 101]): capture.sample(force=True)
            self.assertEqual(item['state'], 'identity-changed')
            self.assertEqual(item['samples'], 2)
            self.proc_fixture(root,ticks=101,rss=999,hwm=999); capture.sample(force=True)
            self.assertEqual(item['rss_kib'],15)
            (root/'123/status').write_bytes(b'x'*8193)
            self.proc_fixture(root,ticks=100)
            (root/'123/status').write_bytes(b'x'*8193); capture.sample(force=True)
            self.assertEqual(item['state'],'invalid')
            (root/'123/stat').unlink(); capture.latch([child], 'deadline')
            (root/'vmstat').write_text('oom_kill 1\n')
            resources = capture.finish()
            self.assertTrue(resources['guest']['reset']); self.assertIsNone(resources['guest']['delta'])
            self.assertNotIn('guest-secret',json.dumps(resources))
            normal.validate_capture(dict(pre_cleanup_observation=capture.pre, failure_resources=resources))

    def test_failed_samples_measure_coverage_gap_and_missing_counter_does_not_hide_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);child=self.proc_fixture(root)
            with patch.object(normal.time,'monotonic',return_value=1):
                capture=normal.FailureCapture(1,proc=root);capture.watch('world',child);capture.sample()
            for elapsed in (2,3):
                with patch.object(normal.time,'monotonic',return_value=elapsed), patch.object(normal,'proc_bytes',side_effect=PermissionError()):
                    capture.sample()
            with patch.object(normal.time,'monotonic',return_value=4):capture.sample()
            self.assertEqual(capture.children[0]['samples'],2)
            self.assertEqual(capture.children[0]['max_gap_ms'],3000)
            (root/'vmstat').unlink();capture.latch([child],'assertion')
            (root/'vmstat').write_text('oom_kill 1\n')
            resources=capture.finish()
            self.assertTrue(resources['guest']['reset']);self.assertIsNone(resources['guest']['delta'])
            normal.validate_capture(dict(pre_cleanup_observation=capture.pre,failure_resources=resources))

    def kernel(self, blocks, pids=(123,), clock=None):
        collector = normal.KernelOOM.__new__(normal.KernelOOM)
        collector.fd = 99; collector.state = 'ok'; collector.opened_us = 1000000
        with patch.object(normal.os,'read',side_effect=blocks), patch.object(normal.os,'close') as close:
            if clock:
                with patch.object(normal.time,'monotonic',side_effect=itertools.chain(clock,itertools.repeat(clock[-1]))): result = collector.finish(pids)
            else: result = collector.finish(pids)
        close.assert_called_once_with(99)
        return result

    def test_kernel_numeric_targets_bounds_overrun_and_hostile_text(self):
        record = b'6,12,456,-;Out of memory: Killed process 123 (guest-secret /private/config ) hostile) total-vm:99kB, anon-rss:88kB, file-rss:7kB, shmem-rss:0kB, UID:65534\n'
        result = self.kernel([record,record.replace(b'process 123',b'process 456'),record,record,BlockingIOError()])
        self.assertEqual(len(result['records']),2); self.assertEqual(result['additional'],1)
        self.assertTrue(result['truncated']); self.assertEqual(result['state'],'would-block')
        self.assertEqual(result['records'][0]['anon_rss_kib'],88)
        self.assertEqual(result['scope'],'observer-through-cleanup')
        self.assertEqual(result['basis'],'pid-in-cursor-window')
        self.assertEqual(result['opened_us'],1000000)
        self.assertIsNone(result['opening_sequence'])
        self.assertEqual(result['boundary'],'cursor-end')
        self.assertGreater(result['closed_us'],result['opened_us'])
        self.assertNotIn('secret',json.dumps(result)); self.assertNotIn('config',json.dumps(result))
        for altered in (record.replace(b'6,12',b'x,12'), record.replace(b'88kB',b'NaNkB'),
                        record.replace(b'12,456',b'999999999999999999999,456')):
            self.assertEqual(self.kernel([altered,BlockingIOError()])['records'],[])
        self.assertEqual(self.kernel([BrokenPipeError(32,'guest-secret')])['state'],'overrun')
        self.assertEqual(self.kernel([PermissionError('guest-secret')])['state'],'denied')
        self.assertEqual(self.kernel([b'x'*8192]*8)['state'],'budget')
        self.assertEqual(self.kernel([b'bad']*256)['state'],'budget')
        self.assertEqual(self.kernel([],clock=[1,1.1])['state'],'budget')

    def test_kernel_descriptor_is_nonblocking_close_on_exec_and_closed_on_seek_failure(self):
        with patch.object(normal.os,'geteuid',return_value=0), patch.object(normal.Path,'is_file',return_value=True), \
                patch.object(normal.os,'open',return_value=99) as opened, \
                patch.object(normal.os,'lseek',side_effect=OSError('guest-secret')), patch.object(normal.os,'close') as closed:
            collector = normal.KernelOOM()
        self.assertIsNone(collector.fd); self.assertEqual(collector.state,'read-error')
        self.assertTrue(opened.call_args.args[1] & os.O_CLOEXEC)
        self.assertTrue(opened.call_args.args[1] & os.O_NONBLOCK)
        closed.assert_called_once_with(99)
        with patch.object(normal.os,'geteuid',return_value=1000), patch.object(normal.os,'open') as opened:
            self.assertEqual(normal.KernelOOM().finish([])['state'],'not-opened'); opened.assert_not_called()

    def test_capture_schema_and_combined_budget_reject_secret_strings_and_bool_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = normal.FailureCapture(time.monotonic(),proc=Path(tmp))
            capture.latch([], 'assertion')
            good = dict(pre_cleanup_observation=capture.pre, failure_resources=capture.finish())
            normal.validate_capture(good)
            for change in ('number','extra','state','target','bool'):
                bad = json.loads(json.dumps(good))
                if change == 'number': bad['pre_cleanup_observation']['elapsed_ms'] = 'guest-secret'
                if change == 'extra': bad['failure_resources']['argv'] = 'guest-secret'
                if change == 'state': bad['failure_resources']['kernel']['state'] = 'guest-secret'
                if change == 'target': bad['failure_resources']['kernel']['records'] = [dict(pid=1,sequence=1,time_us=1,total_vm_kib=1,anon_rss_kib=1,file_rss_kib=1,shmem_rss_kib=1)]
                if change == 'bool': bad['failure_resources']['version'] = True
                with self.subTest(change=change), self.assertRaises(ValueError): normal.validate_capture(bad)


class AdapterDiagnostics(unittest.TestCase):
    def replay(self, cleanup, large=False, database_error=False, cancel_root=False, source=False, sanitizer=False, changed_config=False, kernel_error=None, successful=False, merge_error=None, malformed_capture=False):
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
            if sanitizer:
                capture = normal.FailureCapture(time.monotonic(),proc=root/'absent-proc')
                for name,pid in (('world',123),('zone',124)): capture.watch(name,Mock(pid=pid))
                capture.latch([], 'child-exit', [None,-9])
                frame.update(pre_cleanup_observation=capture.pre,failure_resources=capture.finish(),
                    native_exit_codes=[dict(name='world', returncode=0), dict(name='zone', returncode=-9)])
            if not cleanup:
                frame['cleanup_diagnostics'] = dict(forced_kill=True,
                    survivors_before_kill=[dict(pid=123, name='python-child', state='S')],
                    survivors_after_kill=[], child_exits=[-15, -9])
            if large:
                frame['cleanup_diagnostics']['survivors_before_kill'] *= 8
                frame['inserver_tests'].update(selected=32, started=32, completed=32, failed=32)
                frame['inserver_tests']['tests'] = [dict(name='case-'+str(n), passed=False,
                    diagnostic='deliberate assertion guest-secret ' + 'x'*220) for n in range(32)]
            if malformed_capture:
                frame['failure_resources']['kernel']['state'] = 'guest-secret /private/path'
            if successful:
                frame = baseline()
                for key in ('fixture_manifest_sha256', 'binaries', 'database_cleanup'): del frame[key]
            cleanup_calls = []
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
                    cleanup_calls.append(True)
                    if database_error: raise RuntimeError('database cleanup guest-secret failed')
                    return True
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                if str(path) == '/opt/runtime-fixture.json':
                    return '{"manifest_sha256":"'+'a'*64+'"}'
                return original_read(path, *args, **kwargs)
            validate_capture = normal.validate_capture
            with patch.object(normal, 'fit_resources', wraps=normal.fit_resources) as fit, \
                    patch.object(normal, 'validate_capture', wraps=validate_capture) as validate, \
                    patch.object(normal, 'KernelOOM') as kernel, \
                    patch.object(actor_runtime, 'Runtime', ReplayRuntime), \
                    patch.object(actor_runtime, 'ROOT', root/'runtime'), \
                    patch.object(actor_runtime, 'MEDIA', root/'media'), \
                    patch.object(normal.os, 'geteuid', return_value=0), \
                    patch.object(normal.os, 'chown'), \
                    patch.object(normal.Path, 'is_file', return_value=True), \
                    patch.object(normal.Path, 'read_text', read):
                kernel.return_value.finish.return_value = normal.kernel_facts('denied')
                if merge_error == 'fit': fit.side_effect = ValueError('fit guest-secret /private/path')
                if merge_error == 'validate':
                    def validate_merge(value):
                        if value.get('failure_resources', {}).get('kernel', {}).get('state') == 'denied':
                            raise ValueError('validate guest-secret /private/path')
                        return validate_capture(value)
                    validate.side_effect = validate_merge
                if kernel_error == 'init': kernel.side_effect = RuntimeError('kernel guest-secret /private/path')
                elif kernel_error: getattr(kernel.return_value, kernel_error).side_effect = RuntimeError('kernel guest-secret /private/path')
                try:
                    outcome = normal.run(build, dict(world_control=None if successful else 'assertion'))
                    self.assertEqual(cleanup_calls, [True])
                    return outcome, build.CandidateFailure
                except Exception as error:
                    self.assertEqual(cleanup_calls, [True])
                    if cancel_root:
                        pid = int((root/'observer.pid').read_text())
                        self.assertFalse(Path('/proc', str(pid)).exists())
                    return error, build.CandidateFailure
            self.fail('Assertion replay passed')

    def test_root_kernel_failures_preserve_candidate_result_and_always_clean_database(self):
        for phase, reason in (('init', 'kernel-init-unavailable'),
                              ('finish', 'kernel-merge-unavailable'),
                              ('close', 'kernel-close-unavailable')):
            with self.subTest(phase=phase):
                error, candidate_failure = self.replay(True, sanitizer=True, kernel_error=phase)
                self.assertIsInstance(error, candidate_failure)
                result = error.result
                self.assertEqual(result['exit_code'], 1)
                self.assertTrue(result['cleanup_complete'])
                self.assertTrue(result['database_cleanup'])
                self.assertEqual(result['capture_error'], reason)
                self.assertEqual(result['native_exit_codes'], [dict(name='world', returncode=0), dict(name='zone', returncode=-9)])
                self.assertFalse(result['inserver_tests']['passed'])
                self.assertEqual(result['pre_cleanup_observation']['processes'][1]['returncode'], -9)
                self.assertEqual(result['failure_resources']['processes'][1]['pid'], 124)
                self.assertEqual(result['failure_resources']['kernel']['state'],
                                 'denied' if phase == 'close' else 'not-opened')
                self.assertNotIn('adapter_error', result)
                self.assertNotIn('guest-secret', json.dumps(result))
                self.assertNotIn('/private/path', json.dumps(result))
                normal.validate_capture(result)

    def test_root_merge_is_transactional_on_fit_or_validation_exception(self):
        for phase in ('fit', 'validate'):
            with self.subTest(phase=phase):
                error, candidate_failure = self.replay(True, sanitizer=True, merge_error=phase)
                self.assertIsInstance(error, candidate_failure)
                self.assertEqual(error.result['exit_code'], 1)
                self.assertTrue(error.result['database_cleanup'])
                self.assertTrue(error.result['cleanup_complete'])
                self.assertEqual(error.result['capture_error'], 'kernel-merge-unavailable')
                self.assertEqual(error.result['failure_resources']['kernel']['state'], 'not-opened')
                self.assertEqual(error.result['pre_cleanup_observation']['processes'][1]['returncode'], -9)
                self.assertNotIn('guest-secret', json.dumps(error.result))
                self.assertNotIn('/private/path', json.dumps(error.result))
                normal.validate_capture(error.result)

    def test_root_invalid_resource_capture_retains_valid_latch_without_raw_metadata(self):
        error, candidate_failure = self.replay(True, sanitizer=True, malformed_capture=True)
        self.assertIsInstance(error, candidate_failure)
        self.assertEqual(error.result['capture_error'], 'root-capture-unavailable')
        self.assertEqual(error.result['pre_cleanup_observation']['processes'][1]['returncode'], -9)
        self.assertNotIn('failure_resources', error.result)
        self.assertTrue(error.result['database_cleanup'])
        self.assertNotIn('guest-secret', json.dumps(error.result))
        self.assertNotIn('/private/path', json.dumps(error.result))
        normal.validate_capture(error.result)

    def test_root_kernel_failures_do_not_reclassify_success_or_add_failure_capture(self):
        for phase in ('init', 'finish', 'close'):
            with self.subTest(phase=phase):
                result, _ = self.replay(True, sanitizer=True, kernel_error=phase, successful=True)
                self.assertIsInstance(result, dict)
                self.assertEqual(result['exit_code'], 0)
                self.assertTrue(result['database_cleanup'])
                self.assertTrue(result['cleanup_complete'])
                for key in ('capture_error', 'pre_cleanup_observation', 'failure_resources'):
                    self.assertNotIn(key, result)

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
    def test_observer_real_children_keep_first_poll_separate_from_shutdown(self):
        controller = r"""
import json,os,signal,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import normal_world as normal
mode=sys.argv[2]
real_popen=normal.subprocess.Popen
launched=[]
def launch(*args,**kwargs):
    process=real_popen(*args,**kwargs);launched.append(process)
    # Both real children are already exited before the guard's first scan.
    if mode=='dual' and len(launched)==2:
        for child in launched:child.wait(timeout=5)
    return process
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    for name in ('world','zone'):
        action = 'while True: signal.pause()'
        if mode=='kill' and name=='zone': action='time.sleep(.03); os.kill(os.getpid(),9)'
        if mode=='dual': action='time.sleep(.03); raise SystemExit(1)'
        if mode=='cancel' and name=='zone': action='time.sleep(.03); os.kill(os.getppid(),15)\nwhile True: signal.pause()'
        handler = 'raise SystemExit(0)'
        if mode=='escalate' and name=='zone': handler='return'
        if mode=='late' and name=='world': handler='print("ERROR: LeakSanitizer: fixture late failure",flush=True); raise SystemExit(1)'
        text='#!'+sys.executable+'\nimport os,signal,time\ndef stop(*_):\n    '+handler+'\nsignal.signal(signal.SIGTERM,stop)\n'+action+'\n'
        path=root/name;path.write_text(text);path.chmod(0o700)
    with patch.object(normal.subprocess,'Popen',side_effect=launch), patch.object(normal.Path,'is_file',return_value=True), patch.object(normal,'read_observer_secrets',return_value=['secret','key']), patch.object(normal,'world_connected',return_value=False), patch.object(normal,'OBSERVE_SECONDS',.2):
        normal.observe(root,root,None)
"""
        for mode in ('kill','dual','cancel','deadline','escalate','late'):
            with self.subTest(mode=mode):
                process = subprocess.Popen([sys.executable,'-B','-c',controller,str(ROOT/'validation/worker'),mode],
                    env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try:
                    stdout,stderr=process.communicate(timeout=18)
                    self.assertEqual(process.returncode,0,stderr.decode())
                    result=json.loads(next(line.removeprefix(b'NORMAL_WORLD_RESULT ') for line in stdout.splitlines() if line.startswith(b'NORMAL_WORLD_RESULT ')))
                    pre=result['pre_cleanup_observation']; normal.validate_capture(result)
                    self.assertEqual(result['cleanup_complete'],mode!='escalate')
                    self.assertNotEqual(result['exit_code'],0)
                    if mode=='kill':
                        self.assertEqual(pre['first_observed_exited'],'zone')
                        self.assertEqual([p['returncode'] for p in pre['processes']],[None,-9])
                        self.assertEqual([p['returncode'] for p in result['native_exit_codes']],[0,-9])
                    if mode=='dual': self.assertTrue(pre['simultaneous_observed'])
                    if mode in ('cancel','deadline','escalate','late'):
                        self.assertIsNone(pre['first_observed_exited'])
                        self.assertEqual(pre['condition'],'cancelled' if mode=='cancel' else 'deadline')
                    if mode=='escalate':
                        self.assertTrue(result['cleanup_diagnostics']['forced_kill'])
                        self.assertEqual(result['native_exit_codes'][1]['returncode'],-9)
                    if mode=='late':
                        self.assertEqual(result['native_exit_codes'][0]['returncode'],1)
                        self.assertIn('world-console.log',result['failure_evidence']['first_sanitizer_diagnostic'])
                finally:
                    try: os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait(timeout=5);process.stdout.close();process.stderr.close()

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
