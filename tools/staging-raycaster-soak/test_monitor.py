"""Harmless host tests. No Docker, native server, DB or network execution."""
import copy
from contextlib import ExitStack
from types import SimpleNamespace
import importlib.util
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('monitor', HERE/'monitor.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def manifest():
    c = json.loads((HERE/'manifest.example.json').read_text())
    c['health_sha256'] = 'a'*64
    c['limits'].update(disk_free_bytes=100, host_available_bytes=100,
                       log_growth_bytes=1000, process_rss_bytes=1000)
    for v in c['limits']['containers'].values():
        v.update(memory_bytes=1000, cpu_cores=1)
    return c


def snapshot():
    return {'monotonic': 0, 'processes': [{'identity': [1, 2, 3]}],
            'containers': {n: dict(id='id', image='image', pid=1, started='start',
                                  restarts=0, init_process={'identity': [1, 2, 3]}, memory_max='1000', cpu_max='100000 100000',
                                  memory_events={'oom': 0}, cpu={'usage_usec': 0})
                           for n in m.CONTAINERS}, 'logs': [{'offset': 0}]}


class TestMonitor(unittest.TestCase):
    def test_manifest_rejects_missing_unbounded_nonfinite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'m.json'
            c = manifest()
            p.write_text(json.dumps(c))
            self.assertEqual(m.config(p), c)
            for key, value in [('duration_hours', 49), ('duration_hours', float('nan')),
                               ('duration_hours', float('inf')), ('source', ''),
                               ('zone_sha256', ''), ('backend', ''), ('logs', [])]:
                bad = copy.deepcopy(c)
                bad[key] = value
                p.write_text(json.dumps(bad))
                with self.assertRaises(m.Nonpass):
                    m.config(p)
            c['limits']['disk_free_bytes'] = None
            p.write_text(json.dumps(c))
            with self.assertRaises(m.Nonpass):
                m.config(p)

    def test_commands_timeout_cap_exit_and_no_exception_output(self):
        self.assertEqual(m.command([sys.executable, '-c', 'print(123)']), b'123\n')
        for code, kwargs in [('import time; time.sleep(2)', {'timeout': .05}),
                             ('print("private"*10000)', {'cap': 100}),
                             ('raise SystemExit(4)', {})]:
            with self.assertRaises(m.Nonpass) as caught:
                m.command([sys.executable, '-c', code], **kwargs)
            self.assertNotIn('private', str(caught.exception))

    def test_logs_baseline_new_bytes_split_tokens_rotation_backlog(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'native.log'
            p.write_bytes(b'old panic private player content\n')
            b = m.log_sample(p, None)
            self.assertEqual(b['new_bytes'], 0)
            with p.open('ab') as f:
                f.write(b'ordinary line\nna')
            b = m.log_sample(p, b)
            with p.open('ab') as f:
                f.write(b'n\n')
            with self.assertRaisesRegex(m.Nonpass, 'nonfinite'):
                m.log_sample(p, b)
            p.write_bytes(b'')
            with self.assertRaisesRegex(m.Nonpass, 'truncated'):
                m.log_sample(p, b)
            b = m.log_sample(p, None)
            p.write_bytes(b'x'*(m.CAP+1))
            with self.assertRaisesRegex(m.Nonpass, 'backlog'):
                m.log_sample(p, b)

    def test_identity_pressure_cpu_and_growth_abort(self):
        obs = m.Observer(manifest())
        obs.baseline = snapshot()
        obs.previous = copy.deepcopy(obs.baseline)
        good = snapshot()
        good['monotonic'] = 300
        obs.check(good)
        mutations = [lambda s: s['processes'][0]['identity'].append(4),
                     lambda s: s['containers'][m.CONTAINERS[0]].update(restarts=1),
                     lambda s: s['containers'][m.CONTAINERS[0]].update(pid=2),
                     lambda s: s['containers'][m.CONTAINERS[0]]['memory_events'].update(oom=1),
                     lambda s: s['containers'][m.CONTAINERS[0]]['cpu'].update(usage_usec=301000000),
                     lambda s: s['logs'][0].update(offset=1001)]
        for mutate in mutations:
            s = copy.deepcopy(good)
            mutate(s)
            with self.assertRaises(m.Nonpass):
                obs.check(s)

    def test_run_deadline_partial_and_immutable_files(self):
        for failure in (None, 0, 1):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as d:
                now = [0.0]
                class Fake:
                    count = 0
                    def sample(self, result):
                        result['safe_metric'] = 1
                        if self.count == failure:
                            raise RuntimeError('private credential')
                        self.count += 1
                def sleep(seconds):
                    now[0] += seconds
                out = m.Artifacts(Path(d)/'run')
                with patch.object(signal, 'setitimer'), patch.object(signal, 'alarm'):
                    rc = m.run(manifest(), out, Fake(), lambda: now[0], sleep)
                summary = json.loads((out.root/'summary.json').read_text())
                self.assertEqual(rc, int(failure is not None))
                self.assertEqual(summary['samples'], 289 if failure is None else failure)
                self.assertEqual(summary['elapsed_seconds'], 86400 if failure is None else failure*300)
                self.assertNotIn('private credential', ''.join(p.read_text() for p in out.root.iterdir()))
                if failure == 0:
                    self.assertFalse((out.root/'baseline.json').exists())
                else:
                    self.assertTrue(json.loads((out.root/'baseline.json').read_text())['complete'])
                with self.assertRaises(FileExistsError):
                    m.Artifacts(out.root)
                with self.assertRaises(FileExistsError):
                    out.write('summary.json', {})

    def test_full_sample_mocked_readonly_sources_and_faults(self):
        for fault in (None, 'oom', 'unhealthy', 'memory', 'rss', 'hash', 'health_exit'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d, ExitStack() as stack:
                c = manifest()
                log = Path(d)/'native.log'
                log.write_text('old private console content')
                c['logs'] = [str(log)]
                c['expected_zones'] = 1
                c['world_sha256'] = c['zone_sha256'] = 'a'*64
                commands = []
                def command(argv, **kwargs):
                    commands.append(argv)
                    if argv[0] != 'docker':
                        if fault == 'health_exit':
                            raise m.Nonpass('command_exit')
                        return b'private health output'
                    if argv[1] == 'top':
                        return b'PID COMMAND\n101 world\n102 zone\n'
                    state = dict(Running=True, OOMKilled=fault == 'oom', Restarting=False,
                                 Pid=100, StartedAt='start',
                                 HealthStatus='unhealthy' if fault == 'unhealthy' else 'healthy')
                    return ' '.join(json.dumps(v) for v in ['id', 'image', state, 0, '/log']).encode()
                def read(path, cap=m.CAP):
                    p = str(path)
                    if p.endswith('/cgroup'):
                        return b'0::/test-owned'
                    if p.endswith('memory.current'):
                        return b'1001' if fault == 'memory' else b'100'
                    if p.endswith('memory.max'):
                        return b'1000'
                    if p.endswith('cpu.max'):
                        return b'100000 100000'
                    if p.endswith('meminfo'):
                        return b'MemAvailable: 1000 kB\n'
                    raise AssertionError(p)
                def process(pid, hashes):
                    return dict(identity=[pid, 1], kind='world' if pid == 101 else 'zone',
                                sha256='b'*64 if fault == 'hash' else 'a'*64,
                                rss_bytes=1001 if fault == 'rss' else 100, cpu_ticks=1)
                for name, replacement in [('command', command), ('read', read),
                                          ('process', process), ('digest', lambda p: 'a'*64),
                                          ('counters', lambda p: {'usage_usec': 0} if str(p).endswith('cpu.stat') else {'oom': 0})]:
                    stack.enter_context(patch.object(m, name, replacement))
                stack.enter_context(patch.object(m.os, 'statvfs', return_value=SimpleNamespace(f_bavail=1000, f_frsize=4096)))
                obs, result = m.Observer(c), {}
                if fault:
                    with self.assertRaises(m.Nonpass):
                        obs.sample(result)
                else:
                    obs.sample(result)
                    self.assertNotIn('private', m.encode(result).decode())
                    self.assertEqual(result['health']['exit'], 0)
                    self.assertEqual(len(result['processes']), 2)
                    self.assertTrue(all(a[1] in ('inspect', 'top') for a in commands if a[0] == 'docker'))
                    inspect = next(a for a in commands if a[0] == 'docker' and a[1] == 'inspect')
                    self.assertNotIn('{{json .State}}', inspect)
                    self.assertNotIn('Env', ''.join(inspect))

    def test_stop_signal_retains_abort_summary(self):
        with tempfile.TemporaryDirectory() as d:
            class Interrupted:
                def sample(self, result):
                    m.interrupted(signal.SIGTERM, None)
            out = m.Artifacts(Path(d)/'run')
            with patch.object(signal, 'setitimer'), patch.object(signal, 'alarm'):
                self.assertEqual(m.run(manifest(), out, Interrupted()), 1)
            summary = json.loads((out.root/'summary.json').read_text())
            self.assertTrue(summary['abort_receipt'])
            self.assertEqual(summary['reason'], 'observer_signal_15')
            self.assertFalse(summary['services_changed'])

    def test_budget_keeps_terminal_reserve(self):
        with tempfile.TemporaryDirectory() as d:
            out = m.Artifacts(Path(d)/'run')
            out.used = m.BUDGET - 65536
            with self.assertRaisesRegex(m.Nonpass, 'budget'):
                out.write('samples.jsonl', {'x': 1}, append=True)
            out.write('summary.json', {'status': 'NONPASS'})

    def test_fifo_is_rejected_without_blocking(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'fifo'
            os.mkfifo(p)
            with self.assertRaisesRegex(m.Nonpass, 'not_regular'):
                m.log_sample(p, None)


if __name__ == '__main__':
    unittest.main()
