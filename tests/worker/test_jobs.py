"""Actual host process/adapter seams using trusted harmless fixtures, no VM/Cargo."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import jobs


class Jobs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adapter = self.root / 'adapter'
        self.adapter.write_text('#!/usr/bin/python3\nimport pathlib,sys\n'
            + 'root=pathlib.Path(' + repr(str(self.root)) + ')\n'
            + 'with (root/"messages").open("a") as f: f.write(sys.stdin.read()+"\\n")\n'
            + 'raise SystemExit(1 if (root/"fail-callback").exists() else 0)\n')
        self.adapter.chmod(0o700)
        self.paths = []
        self.addCleanup(self.stop)

    def stop(self):
        for path in self.paths:
            state = jobs.read(path / 'state.json')
            try:
                if not (path / 'result.json').exists(): jobs.cancel(path)
                self.wait(path)
            except Exception:
                if state.get('validator'):
                    try: jobs.signal_owned(state['validator'], signal.SIGKILL)
                    except (OSError, ValueError): pass
                if state.get('runner'):
                    try: jobs.signal_owned(state['runner'], signal.SIGKILL)
                    except (OSError, ValueError): pass

    def start(self, script=None, command=None):
        if script is not None:
            fixture = self.root / ('fixture-' + str(len(self.paths)) + '.py')
            fixture.write_text(script)
            command = ['/usr/bin/python3', str(fixture)]
        value = jobs.start(self.root / 'jobs', dict(command=command, candidate='a'*40,
            profile='trusted-process-fixture', adapter=str(self.adapter), thread='explicit-thread',
            t3_base_dir=str(self.root)))
        path = jobs.job_path(self.root / 'jobs', value['job_id']); self.paths.append(path)
        return path

    def wait(self, path):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = jobs.status(path)
            if value['result'] and value['notification']['status'] in ('sent', 'failed'): return value
            time.sleep(.03)
        self.fail('Job did not finish: ' + repr(jobs.status(path)) + (path / 'runner.log').read_text())

    def test_success_late_failure_and_launch_failure(self):
        for code in (0, 1, 7):
            path = self.start('import json,sys\nprint(json.dumps(dict(passed=True,cleanup_complete=True)))\n'
                              + 'print("raw stderr",file=sys.stderr)\nraise SystemExit(' + str(code) + ')\n')
            value = self.wait(path)
            self.assertEqual(value['result']['returncode'], code)
            self.assertTrue(value['result']['cleanup_complete'])
            self.assertEqual(jobs.read(path / 'validator-result.json')['passed'], True)
            self.assertIn('raw stderr', (path / 'validator.stderr.log').read_text())
        value = self.wait(self.start(command=['/nonexistent-trusted-validator']))
        self.assertEqual(value['result']['status'], 'launch_failed')
        self.assertIsNone(value['result']['returncode'])
        self.assertIsNone(value['result']['cleanup_complete'])

    def test_callback_failure_retry_never_relaunches_validator_and_sent_is_noop(self):
        (self.root / 'fail-callback').touch()
        path = self.start('from pathlib import Path\n'
            + 'with Path(' + repr(str(self.root / 'launches')) + ').open("a") as f: f.write("launch\\n")\n'
            + 'print("{}")\nraise SystemExit(1)\n')
        first = self.wait(path)
        self.assertEqual(first['notification']['status'], 'failed')
        (self.root / 'fail-callback').unlink()
        self.assertEqual(jobs.notify(path)['status'], 'sent')
        self.assertEqual(jobs.notify(path)['attempts'], 2)
        self.assertEqual(jobs.status(path)['result'], first['result'])
        self.assertEqual((self.root / 'launches').read_text(), 'launch\n')
        messages = (self.root / 'messages').read_text().splitlines()
        self.assertEqual(len(messages), 2)
        self.assertTrue(all(path.name in message for message in messages))
        duplicate = subprocess.run(['/usr/bin/python3', '-I', str(ROOT / 'validation/worker/jobs.py'),
            '--run', str(path.parent), path.name], capture_output=True)
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertEqual((self.root / 'launches').read_text(), 'launch\n')

    def test_cancel_preserves_final_receipt_or_cleanup_unknown(self):
        for final in (False, True):
            path = self.start('import signal,time,json\n'
                + 'def stop(*args):\n'
                + (' print(json.dumps(dict(cleanup_complete=True)))\n' if final else ' pass\n')
                + ' raise SystemExit(2)\nsignal.signal(signal.SIGINT,stop)\n'
                + 'print("started",flush=True)\ntime.sleep(30)\n')
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (path / 'validator.stdout.log').exists() and 'started' in (path / 'validator.stdout.log').read_text(): break
                time.sleep(.02)
            jobs.cancel(path)
            result = self.wait(path)['result']
            self.assertEqual(result['status'], 'cancelled')
            self.assertEqual(result['returncode'], 2)
            self.assertEqual(result['cleanup_complete'], True if final else None)

    def test_rejects_recycled_process_foreign_job_symlink_and_dead_runner(self):
        path = self.start('import time\ntime.sleep(30)\n')
        with jobs.locked(path / 'state.lock'):
            state = jobs.read(path / 'state.json')
            wrong = dict(state['runner'], start='wrong')
            jobs.write(path / 'state.json', dict(state, runner=wrong))
        with self.assertRaisesRegex(ValueError, 'ownership mismatch'): jobs.cancel(path)
        self.assertFalse((path / 'cancel.json').exists())
        jobs.write(path / 'state.json', state)
        jobs.cancel(path); self.wait(path)
        for value in ('../escape', 'not-a-job'):
            with self.assertRaises(ValueError): jobs.job_path(path.parent, value)
        alias = path.parent / ('b'*32); alias.symlink_to(path, target_is_directory=True)
        with self.assertRaises(ValueError): jobs.job_path(path.parent, alias.name)

    def test_bounded_logs_preserve_exit_and_report_tail(self):
        code, detail = jobs.capture(['/usr/bin/python3', '-c',
            'import sys; print("x"*10000); print("{\\"cleanup_complete\\":true}"); sys.exit(9)'],
            self.root / 'finite', limit=100)
        self.assertEqual(code, 9)
        self.assertTrue(detail['truncated'])
        self.assertEqual((self.root / 'finite.stdout.log').stat().st_size, 100)
        self.assertIn(b'cleanup_complete', detail['tail'])

    def test_adapter_execs_supported_cli_with_explicit_base_and_stdin(self):
        cli = self.root / 'cli'
        cli.write_text('#!/usr/bin/python3\nimport json,sys,os\n'
            + 'print(json.dumps(dict(args=sys.argv[1:],message=sys.stdin.read(),marker=os.environ["MARKER"])))\n')
        cli.chmod(0o700)
        config = self.root / 'cli.json'
        config.write_text(json.dumps(dict(command=[str(cli)], env={'MARKER': 'trusted'})))
        result = subprocess.run([str(ROOT / 'scripts/t3-validation-notify'), '--base-dir', str(self.root),
            '--thread', 'explicit-thread'], input='bounded summary', text=True, capture_output=True,
            env=dict(os.environ, T3_VALIDATION_CLI_CONFIG=str(config)), check=True)
        value = json.loads(result.stdout)
        self.assertEqual(value['args'], ['thread', 'send', '--base-dir', str(self.root), '--json', 'explicit-thread', '-'])
        self.assertEqual(value['message'], 'bounded summary')
        self.assertEqual(value['marker'], 'trusted')

    def test_exited_parent_descendant_pipe_is_bounded_and_owned_child_stopped(self):
        child = self.root / 'pipe-child'
        script = ('import subprocess,sys\n'
            + 'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])\n'
            + 'open(' + repr(str(child)) + ',"w").write(str(p.pid))\n')
        started = time.monotonic()
        code, detail = jobs.capture(['/usr/bin/python3', '-c', script], self.root / 'pipes', seconds=.2)
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 4)
        self.assertFalse(detail['pipe_drain_incomplete'])
        pid = int(child.read_text())
        try: self.assertFalse(jobs.alive(jobs.process_identity(pid)))
        except (FileNotFoundError, ProcessLookupError): pass
        # The same seam must still publish a durable job result and callback.
        path = self.start(script)
        value = self.wait(path)
        self.assertEqual(value['result']['returncode'], 0)
        self.assertFalse(value['result']['logs']['pipe_drain_incomplete'])

    def test_runner_death_cancel_uses_owned_validator_and_never_infers_cleanup(self):
        ready = self.root / 'ready'; stopped = self.root / 'stopped'
        path = self.start('import signal,time,pathlib\n'
            + 'def stop(*args):\n pathlib.Path(' + repr(str(stopped)) + ').touch()\n raise SystemExit(2)\n'
            + 'signal.signal(signal.SIGINT,stop)\npathlib.Path(' + repr(str(ready)) + ').touch()\ntime.sleep(30)\n')
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline: time.sleep(.02)
        self.assertTrue(ready.exists())
        state = jobs.read(path / 'state.json')
        jobs.signal_owned(state['runner'], signal.SIGKILL)
        while jobs.alive(state['runner']) and time.monotonic() < deadline: time.sleep(.02)
        self.assertEqual(jobs.status(path)['state']['status'], 'interrupted')
        jobs.cancel(path)
        value = self.wait(path)
        self.assertEqual(value['result']['status'], 'cancelled')
        self.assertIsNone(value['result']['returncode'])
        self.assertIsNone(value['result']['cleanup_complete'])
        while not stopped.exists() and time.monotonic() < deadline: time.sleep(.02)
        self.assertTrue(stopped.exists())
        self.assertEqual(jobs.notify(path)['attempts'], 1)

    def test_runner_bootstrap_is_frozen_and_launch_failure_notifies(self):
        # Change the source file immediately after copying it, before exec loads
        # the runner; only the job's recorded private copy may execute.
        source = self.root / 'source-jobs.py'; source.write_bytes(Path(jobs.__file__).read_bytes())
        original = subprocess.Popen
        def launch(*args, **kwargs):
            source.unlink()
            return original(*args, **kwargs)
        with patch.object(jobs, '__file__', str(source)), patch.object(jobs.subprocess, 'Popen', side_effect=launch):
            path = self.start('print("{}")\n')
        self.assertEqual(self.wait(path)['result']['returncode'], 0)
        launches = 0
        def fail_once(*args, **kwargs):
            nonlocal launches
            launches += 1
            if launches == 1: raise OSError('deliberate runner launch failure')
            return original(*args, **kwargs)
        with patch.object(jobs.subprocess, 'Popen', side_effect=fail_once):
            path = self.start(command=['/never-launched-validator'])
        value = self.wait(path)
        self.assertEqual(value['result']['status'], 'launch_failed')
        self.assertEqual(value['notification']['status'], 'sent')


if __name__ == '__main__': unittest.main()
