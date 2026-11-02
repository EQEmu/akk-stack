"""Real local sockets/processes and source packaging; no candidate code or VM execution."""
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import build_guest
import prepare
import runtime
import test_runtime


class Transfer(unittest.TestCase):
    def test_guest_final_result_preserves_large_structured_native_exception(self):
        import normal_world
        normal = dict(exit_code=1, cleanup_complete=True,
                      failure_evidence=dict(console={'zone': 'useful detail '+('x'*9000)}))
        capture = normal_world.FailureCapture(time.monotonic(),proc=Path('/nonexistent-ks48-proc'))
        capture.latch([], 'assertion')
        normal.update(pre_cleanup_observation=capture.pre,failure_resources=capture.finish())
        failure = build_guest.CandidateFailure('assertion ' + '\ufffd'*3500)
        failure.result = normal
        old = {key: getattr(build_guest, key) for key in ('WORK', 'MEDIA', 'DEADLINE', 'CHECKS', 'STAGE')}
        self.addCleanup(lambda: [setattr(build_guest, key, value) for key, value in old.items()])
        self.addCleanup(build_guest.COMPLETED.clear)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mkdir = Path.mkdir
            def guest_mkdir(path, *args, **kwargs):
                if str(path) == '/media/eqemu-input': return
                return mkdir(path, *args, **kwargs)
            def read(path, *args, **kwargs):
                if str(path) == '/opt/eqemu-worker-nonce': return 'a'*32
                if str(path) == '/opt/eqemu-worker-checks.json': return json.dumps(runtime.BUILD_CHECKS)
                raise AssertionError('Unexpected read: '+str(path))
            output = io.StringIO()
            with patch.object(build_guest, 'WORK', root/'work'), patch.object(build_guest, 'MEDIA', root/'media'), \
                    patch.object(build_guest, 'LOGS', root/'work/logs'), \
                    patch.object(build_guest.os, 'geteuid', return_value=0), \
                    patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'read_text', read), \
                    patch.object(Path, 'mkdir', guest_mkdir), patch.object(build_guest, 'command'), \
                    patch.object(build_guest, 'provision', return_value={}), \
                    patch.object(build_guest, 'build', return_value={}), \
                    patch.object(normal_world, 'run', side_effect=failure), contextlib.redirect_stdout(output):
                build_guest.main()
            frame = next(line for line in output.getvalue().splitlines() if line.startswith('EQEMU_WORKER_RESULT '))
            result = json.loads(frame.removeprefix('EQEMU_WORKER_RESULT '))
            self.assertEqual(result['exit_code'], 1)
            self.assertEqual(result['normal_world'], normal)
            self.assertLessEqual(len(frame.encode())+1, 32768)
            self.assertGreater(len(json.dumps(result['normal_world'])), 3000)

    def test_early_infrastructure_diagnostic_survives_large_read(self):
        # Coalesce real pipe reads to exercise platforms with a larger pipe buffer.
        data = b'failed to select a version for the requirement cxx\n' + b'x' * 20000
        original_read = os.read
        def coalesced(fd, count):
            block = original_read(fd, count)
            if count == 65536 and block:
                os.set_blocking(fd, True)
                try:
                    while len(block) < len(data):
                        extra = original_read(fd, count - len(block))
                        if not extra: break
                        block += extra
                finally:
                    os.set_blocking(fd, False)
            return block
        self.addCleanup(setattr, build_guest, 'DEADLINE', build_guest.DEADLINE)
        build_guest.DEADLINE = time.monotonic() + 10
        with patch.object(build_guest.os, 'read', side_effect=coalesced), self.assertRaises(RuntimeError) as caught:
            build_guest.command('trusted-large-read-fixture',
                                [sys.executable, '-c', 'import os; os.write(1,' + repr(data) + '); raise SystemExit(101)'],
                                candidate=True)
        self.assertIs(type(caught.exception), RuntimeError)

    def test_streaming_hash_and_disconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ('pass', 'changed', 'disconnect'):
                with self.subTest(mode=mode):
                    sender, receiver = socket.socketpair()
                    try:
                        data = b'opaque ISO bytes' * 1000
                        wanted = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        def send():
                            sender.sendall(data if mode != 'changed' else b'x' * len(data))
                            sender.shutdown(socket.SHUT_WR)
                        if mode == 'disconnect':
                            sender.shutdown(socket.SHUT_WR)
                        else:
                            thread = threading.Thread(target=send); thread.start()
                        path = Path(tmp) / mode
                        if mode == 'pass':
                            runtime.receive_payload(receiver, path, wanted, time.monotonic() + 2)
                            self.assertEqual(path.read_bytes(), data)
                        else:
                            with self.assertRaises((ValueError, RuntimeError)):
                                runtime.receive_payload(receiver, path, wanted, time.monotonic() + 2)
                        if mode != 'disconnect': thread.join(2)
                    finally:
                        sender.close(); receiver.close()

    def test_guest_phase_exit_and_resource_failure_classification(self):
        old_deadline = build_guest.DEADLINE
        self.addCleanup(setattr, build_guest, 'DEADLINE', old_deadline)
        build_guest.DEADLINE = time.monotonic() + 10
        for candidate, script, error in (
                (True, 'exit 1', build_guest.CandidateFailure),
                (False, 'exit 1', RuntimeError),
                (True, 'echo "no matching package named dependency"; exit 101', RuntimeError),
                (True, 'echo "Killed signal terminated program cc1plus"; exit 1', RuntimeError),
                (True, 'echo "failed to select a version for the requirement cxx"; exit 101', RuntimeError),
                (True, 'echo "Could NOT find MissingLibrary"; exit 1', RuntimeError),
                (True, 'echo "Could not find a package configuration file provided by MissingLibrary"; exit 1', RuntimeError)):
            with self.subTest(script=script, candidate=candidate):
                with self.assertRaises(error) as caught:
                    build_guest.command('trusted-fixture', ['/bin/sh', '-c', script], candidate=candidate)
                self.assertIs(type(caught.exception), error)


class BuildRuntime(unittest.TestCase):
    def setUp(self):
        test_runtime.Runtime.setUp(self)
        disk = patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3))
        disk.start(); self.addCleanup(disk.stop)
    def build_request(self):
        return dict(version=1, operation='build', candidate='a'*40, tree='b'*40, bytes=3,
                    sha256=hashlib.sha256(b'ISO').hexdigest())

    def test_build_uses_larger_guest_readonly_input_and_same_owned_cleanup(self):
        request = self.build_request(); self.client.sendall(b'ISO')
        guest = dict(version=1, nonce='n', scope='worker-build', exit_code=1, stage='rust-tests', error='assertion failed',
                     selected_checks=list(runtime.BUILD_CHECKS), completed_checks=list(runtime.BUILD_CHECKS[:3]))
        def simulate(*args):
            args[-2](12345); args[-1].update(guest); return 1
        with patch.object(runtime, 'resource_state', return_value={'memory.max': str(6*1024**3)}), \
                patch.object(runtime, 'supervise', side_effect=simulate) as supervisor:
            result = runtime.run_vm(self.value, self.server, build=request)
        self.assertEqual(result['exit_code'], 1, result)
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['candidate'], request['candidate'])
        self.assertEqual(result['guest']['stage'], 'rust-tests')
        self.assertEqual(result['completed_checks'], list(runtime.BUILD_CHECKS[:3]))
        self.assertRegex(result['implementation_sha256'], '^[a-f0-9]{64}$')
        argv = supervisor.call_args.args[0]
        self.assertEqual(argv[argv.index('-m') + 1], '4096')
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertIn('payload.iso,media=cdrom,readonly=on,format=raw', ' '.join(argv))
        self.assertFalse((self.state / 'active.json').exists())
        self.assertFalse(any(path.is_dir() for path in self.state.iterdir()))

    def test_changed_payload_and_old_host_budget_start_no_vm_and_return_two(self):
        for memory in (2, 6):
            with self.subTest(memory=memory), \
                    patch.object(runtime, 'resource_state', return_value={'memory.max': str(memory*1024**3)}), \
                    patch.object(runtime, 'supervise') as supervisor:
                if memory == 6: self.client.sendall(b'bad')
                result = runtime.run_vm(self.value, self.server, build=self.build_request())
                self.assertEqual(result['exit_code'], 2)
                self.assertFalse(result['vm_started'])
                self.assertTrue(result['cleanup_complete'])
                supervisor.assert_not_called()

    def test_coalesced_request_header_preserves_binary_payload(self):
        request = self.build_request()
        self.client.sendall(json.dumps(request).encode() + b'\nISO')
        def consume(value, connection, **kwargs):
            self.assertEqual(kwargs['build'], request)
            self.assertEqual(connection.recv(3), b'ISO')
            return {'exit_code': 2}
        with patch.object(runtime, 'run_vm', side_effect=consume):
            self.assertEqual(runtime.request(self.server, self.value), {'exit_code': 2})

    def test_foreground_cancellation_after_streamed_readiness_cleans_owned_vm(self):
        import client
        qemu = self.tools/'qemu'
        marker = b'EQEMU_RUNTIME {"kind":"stage","name":"normal-world-ready","state":"started"}\n'
        # Exercise split serial reads and do not exit until the worker cancels us.
        qemu.write_text('#!' + sys.executable + '\nimport os,time\n'
                        'os.write(1,' + repr(marker[:35]) + ')\ntime.sleep(.05)\n'
                        'os.write(1,' + repr(marker[35:]) + ')\ntime.sleep(30)\n')
        payload = self.root/'payload'; payload.write_bytes(b'ISO')
        path = self.root/'progress.sock'
        reports = []; errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path)); listener.listen(1); listener.settimeout(3)
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        raw = bytearray()
                        while not raw.endswith(b'\n'):
                            raw.extend(connection.recv(1))
                        reports.append(runtime.run_vm(self.value, connection, build=json.loads(raw)))
                except BaseException as error:
                    errors.append(error)
            def interrupt(message, **kwargs):
                self.assertEqual(message, 'EQEMU_STAGE normal-world-ready')
                self.assertIs(kwargs['file'], sys.stderr)
                self.assertTrue(kwargs['flush'])
                raise KeyboardInterrupt
            with patch.object(runtime, 'resource_state', return_value={'memory.max': str(6*1024**3)}), \
                    patch.object(runtime, 'BUILD_SECONDS', 3), \
                    patch('builtins.print', side_effect=interrupt):
                thread = threading.Thread(target=serve); thread.start()
                try:
                    with self.assertRaises(KeyboardInterrupt):
                        client.exchange(path, self.build_request(), payload)
                finally:
                    thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(len(reports), 1)
        result = reports[0]
        self.assertEqual(result['exit_code'], 2)
        self.assertIn('disconnected', result['error'])
        self.assertTrue(result['vm_started'])
        self.assertTrue(result['cleanup_complete'])
        self.assertFalse((self.state/'active.json').exists())
        self.assertFalse(any(p.is_dir() for p in self.state.iterdir()))
        with self.assertRaises(ProcessLookupError):
            os.kill(result['qemu_pid'], 0)

    def test_cloud_init_failure_ends_idle_guest_promptly(self):
        script = self.root / 'failed-cloud-init.py'
        # Replay the captured failure split across reads, then keep the fake VM idle.
        message = b'cloud-init[972]: cc_scripts_user.py[WARNING]: Failed to run module scripts_user'
        script.write_text('import os,time\n'
                          'os.write(1,' + repr(message[:50]) + ')\n'
                          'time.sleep(.05)\n'
                          'os.write(1,' + repr(message[50:] + b'\nlogin: ') + ')\n'
                          'time.sleep(30)\n')
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'Guest cloud-init command failed'):
            runtime.supervise([sys.executable, str(script)], self.root, self.root / 'console.log',
                              self.server, started + 2, 'a'*32, build_result={})

    def test_cloud_init_failure_is_infrastructure_with_owned_cleanup(self):
        message = 'cc_scripts_user.py[WARNING]: Failed to run module scripts_user'
        qemu = self.tools / 'qemu'
        qemu.write_text('#!' + sys.executable + '\nimport time\nprint(' + repr(message)
                        + ', flush=True)\ntime.sleep(30)\n')
        self.client.sendall(b'ISO')
        with patch.object(runtime, 'resource_state', return_value={'memory.max': str(6*1024**3)}):
            result = runtime.run_vm(self.value, self.server, build=self.build_request())
        self.assertEqual(result['exit_code'], 2)
        self.assertIn('Guest cloud-init command failed', result['error'])
        self.assertTrue(result['vm_started'])
        self.assertTrue(result['cleanup_complete'])
        self.assertFalse((self.state / 'active.json').exists())
        self.assertFalse(any(path.is_dir() for path in self.state.iterdir()))

    def test_large_native_failure_survives_serial_and_owned_vm_cleanup(self):
        import normal_world
        import test_client
        import test_normal_world_diagnostics
        with patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3, used=0)):
            error, candidate_failure = test_normal_world_diagnostics.AdapterDiagnostics().replay(True, source=True, sanitizer=True)
        self.assertIsInstance(error, candidate_failure)
        self.assertNotIn('guest-secret', json.dumps(error.result))
        source = error.result['failure_evidence']['source_diagnostics']
        self.assertEqual(source['context'], 'result=failed ************')
        self.assertEqual(source['stack'], '#0 native_function ************\n')
        self.assertTrue(source['advisory'])
        first = error.result['failure_evidence']['first_sanitizer_diagnostic']['zone-console.log']
        self.assertIn('runtime error:', first['text'])
        self.assertIn('*', first['text'])
        self.assertNotIn('guest', first['text'])
        self.assertTrue(first['advisory'])
        self.assertFalse(error.result['failure_evidence']['stack_capture']['captured'])
        self.assertEqual(error.result['pre_cleanup_observation']['first_observed_exited'],'zone')
        self.assertEqual(error.result['failure_resources']['kernel']['state'],'denied')
        detail = dict(version=1, nonce='a'*32, scope='worker-build', exit_code=1,
            stage='normal-world', error='udp-timeout', selected_checks=list(runtime.BUILD_CHECKS),
            completed_checks=list(runtime.BUILD_CHECKS[:-1]), normal_world=error.result)
        script = self.root/'large-failure.py'
        script.write_text('print('+repr('EQEMU_WORKER_RESULT '+json.dumps(detail))+')\n')
        retained = {}
        code = runtime.supervise([sys.executable, str(script)], self.root, self.root/'console.log',
            self.server, time.monotonic()+2, 'a'*32, build_result=retained)
        self.assertEqual(code, 1)
        self.assertEqual(retained, detail)
        self.client.sendall(b'ISO')
        def replay(*args):
            args[-2](12345); args[-1].update(detail); return 1
        with patch.object(runtime, 'resource_state', return_value={'memory.max': str(6*1024**3)}), \
                patch.object(runtime, 'supervise', side_effect=replay):
            report = runtime.run_vm(self.value, self.server, build=self.build_request())
        self.assertEqual(report['exit_code'], 1)
        self.assertTrue(report['cleanup_complete'])
        self.assertEqual(report['guest']['normal_world'], detail['normal_world'])
        self.assertEqual(json.loads((self.state/'last-result.json').read_text())['guest'], detail)
        received = test_client.Client().exchange((json.dumps(report)+'\n').encode(), self.build_request())
        self.assertEqual(received, report)
        artifact = normal_world.export_evidence(received, 'a'*40, self.root/'evidence')
        self.assertGreater(artifact.stat().st_size, 3000)
        self.assertLessEqual(artifact.stat().st_size, normal_world.EVIDENCE_LIMIT)
        self.assertNotIn('guest-secret', artifact.read_text())
        self.assertEqual(json.loads(artifact.read_text())['normal_world'], detail['normal_world'])
        public = json.loads((artifact.parent/'public-summary.json').read_text())
        self.assertEqual(public['status'], 'failed')
        self.assertNotIn('native_function', json.dumps(public))
        # A source diagnostic cannot replace the client's independent pass gate.
        with self.assertRaises(ValueError):
            test_client.Client().exchange((json.dumps(dict(report, exit_code=0))+'\n').encode(),
                                          self.build_request())

    def test_build_completion_preserves_infrastructure_details(self):
        result = dict(version=1, nonce='a'*32, scope='worker-build', exit_code=2,
                      stage='offline-package-install', error='Missing offline input',
                      selected_checks=list(runtime.BUILD_CHECKS), completed_checks=[])
        script = self.root / 'emit.py'
        script.write_text('print(' + repr('EQEMU_WORKER_RESULT ' + json.dumps(result)) + ')\n')
        detail = {}
        code = runtime.supervise([sys.executable, str(script)], self.root, self.root / 'console.log',
                                 self.server, time.monotonic() + 2, 'a'*32, build_result=detail)
        self.assertEqual(code, 2)
        self.assertEqual(detail['error'], result['error'])


class Packaging(unittest.TestCase):
    def test_prepare_actual_git_commit_without_executing_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); repo = root / 'repo'; repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q'); git('config', 'user.email', 'fixture@example.test'); git('config', 'user.name', 'Fixture')
            (repo / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
            (repo / 'build.rs').write_text('panic!("MUST NEVER EXECUTE ON HOST");\n')
            git('add', '.'); git('commit', '-qm', 'opaque fixture')
            commit = git('rev-parse', 'HEAD'); tree = git('rev-parse', 'HEAD^{tree}')
            native = root / 'native.iso'; native.write_bytes(b'fixture native')
            rust = root / 'rust.tar'; rust.write_bytes(b'fixture rust')
            profile = {'sources': {'eqemu': {'gitlinks': {}}, 'websocketpp': {'commit': commit, 'tree': tree}}, 'dependency_blobs': {}}
            runtime_iso = root / 'runtime.iso'; runtime_iso.write_bytes(b'fixture runtime')
            fixture = {'iso': prepare.record(runtime_iso)}
            with patch.object(prepare.json, 'loads', side_effect=lambda raw: fixture if 'manifest_sha256' in raw else profile), \
                    patch.object(prepare, 'NATIVE_SHA', prepare.record(native)['sha256']), \
                    patch.object(prepare, 'RUST_SHA', prepare.record(rust)['sha256']):
                output = root / 'payload.iso'
                request = prepare.prepare(repo, 'HEAD', repo, native, rust, output, runtime_iso)
                self.assertEqual(request['candidate'], commit)
                self.assertEqual(request['sha256'], prepare.record(output)['sha256'])
                (repo / 'Cargo.toml').write_text('dirty')
                with self.assertRaisesRegex(ValueError, 'Dirty source'):
                    prepare.prepare(repo, 'HEAD', repo, native, rust, root / 'dirty.iso', runtime_iso)


if __name__ == '__main__':
    unittest.main()
