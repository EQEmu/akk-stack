"""Harmless host tests. No Docker, native server, DB or network execution."""
import copy
import os
import gzip
import shutil
import subprocess
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
                                  memory_events={'oom': 0}, cpu={'usage_usec': 0}, cpu_read_window=[0, 0])
                           for n in m.CONTAINERS}, 'logs': [{'offset': 0}], 'log_footprint': {'baseline_bytes':0,'current_bytes':0,'high_water_bytes':0,'increase_bytes':0}}


class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.previous_umask=os.umask(0o077)

    def tearDown(self):
        os.umask(self.previous_umask)

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
            p.write_bytes(b'old private player content\n')
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
            with self.assertRaisesRegex(m.Nonpass, 'truncation'):
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
        for v in good['containers'].values():
            v['cpu_read_window'] = [300, 300]
        obs.check(good)
        mutations = [lambda s: s['processes'][0]['identity'].append(4),
                     lambda s: s['containers'][m.CONTAINERS[0]].update(restarts=1),
                     lambda s: s['containers'][m.CONTAINERS[0]].update(pid=2),
                     lambda s: s['containers'][m.CONTAINERS[0]]['memory_events'].update(oom=1),
                     lambda s: s['containers'][m.CONTAINERS[0]]['cpu'].update(usage_usec=301000000),
                     lambda s: s['log_footprint'].update(increase_bytes=1001)]
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
        for fault in (None, 'oom', 'unhealthy', 'memory', 'rss', 'hash', 'health_exit', 'health_hash', 'not_ready', 'wrong_zones'):
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
                    if argv[:2] == ['docker', 'exec']:
                        self.assertEqual(argv[2], m.CONTAINERS[0])
                        if argv[3] == 'sha256sum':
                            return (('b' if fault == 'health_hash' else 'a')*64 + '  /home/eqemu/server/bin/staging-health.py').encode()
                        self.assertEqual(argv[3:], ['python3', '-I', '/home/eqemu/server/bin/staging-health.py'])
                        if fault == 'health_exit':
                            raise m.Nonpass('command_exit')
                        return json.dumps({'ready': fault != 'not_ready', 'zones': 7 if fault == 'wrong_zones' else c['expected_zones'], 'static_zones': ['qeynos2','poknowledge']}).encode()
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
                for name, replacement in [('verify_policy', lambda:m.POLICY_SHA), ('command', command), ('read', read),
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
                    self.assertTrue(result['health']['ready'])
                    shutil.copyfile(log,Path(str(log)+'.1'));log.write_bytes(b'after rotation\n')
                    next_result={};obs.sample(next_result)
                    self.assertTrue(obs.log_gap);self.assertTrue(next_result['health']['ready'])
                    self.assertEqual(next_result['log_footprint']['baseline_bytes'],len('old private console content'))
                    self.assertEqual(next_result['log_footprint']['current_bytes'],len('old private console contentafter rotation\n'))
                    self.assertEqual(next_result['log_coverage'],'GAP_POSSIBLE')
                    self.assertEqual(len(result['processes']), 2)
                    self.assertTrue(all(a[1] in ('inspect', 'top', 'exec') for a in commands if a[0] == 'docker'))
                    inspect = next(a for a in commands if a[0] == 'docker' and a[1] == 'inspect')
                    self.assertNotIn('{{json .State}}', inspect)
                    self.assertNotIn('Env', ''.join(inspect))

    def test_cpu_counter_window_rejects_sample_start_underestimate(self):
        obs = m.Observer(manifest())
        obs.baseline = snapshot()
        obs.previous = copy.deepcopy(obs.baseline)
        current = snapshot()
        current['monotonic'] = 300
        for name in m.CONTAINERS:
            obs.previous['containers'][name]['cpu_read_window'] = [40, 40]
            current['containers'][name]['cpu_read_window'] = [300, 300]
            current['containers'][name]['cpu']['usage_usec'] = 280000000
        with self.assertRaisesRegex(m.Nonpass, 'container_cpu_limit'):
            obs.check(current)

    def test_terminal_fault_never_leaves_pass(self):
        for fault in ('file_sync', 'chmod', 'directory_sync', 'link'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as d:
                out = m.Artifacts(Path(d)/'run')
                calls = [0]
                original = m.os.fsync
                def sync(fd):
                    calls[0] += 1
                    if fault == 'file_sync' and calls[0] == 1 or fault == 'directory_sync' and calls[0] == 3:
                        raise OSError('injected')
                    original(fd)
                with ExitStack() as stack:
                    stack.enter_context(patch.object(m.os, 'fsync', sync))
                    if fault == 'chmod':stack.enter_context(patch.object(m.os, 'fchmod', side_effect=OSError('injected')))
                    if fault == 'link':stack.enter_context(patch.object(m.os, 'link', side_effect=OSError('injected')))
                    with self.assertRaises(OSError):
                        out.write('summary.json', {'status':'PASS_WITH_LOG_COVERAGE_GAP'})
                self.assertFalse((out.root/'summary.json').exists())
                self.assertFalse((out.root/'.summary.pending').exists())

    def test_delayed_sample_cannot_complete_soak(self):
        with tempfile.TemporaryDirectory() as d:
            now = [0]
            def sleep(seconds):
                now[0] += seconds + 91
            out = m.Artifacts(Path(d)/'run')
            with patch.object(signal, 'alarm'):
                rc = m.run(manifest(), out, object(), lambda: now[0], sleep)
            summary = json.loads((out.root/'summary.json').read_text())
            self.assertEqual(rc, 1)
            self.assertEqual(summary['samples'], 0)
            self.assertEqual(summary['reason'], 'sample_gap')

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


class TestRotationContract(unittest.TestCase):
    def setUp(self):
        self.previous_umask=os.umask(0o077)

    def tearDown(self):
        os.umask(self.previous_umask)

    def rotate(self,p):
        for n in range(7,2,-1):
            src=Path(str(p)+'.'+str(n-1)+'.gz');dest=Path(str(p)+'.'+str(n)+'.gz')
            if src.exists():src.replace(dest)
        old=Path(str(p)+'.1')
        if old.exists():
            Path(str(p)+'.2.gz').write_bytes(gzip.compress(old.read_bytes()));old.unlink()
        shutil.copyfile(p,old)
        p.write_bytes(b'')

    def test_actual_copytruncate_old_red_new_gap_and_visible_footprint(self):
        old_source=subprocess.check_output(['git','show','3a14b6cecb04c9baed4f047cabd271d75ce2f151:tools/staging-raycaster-soak/monitor.py'],cwd=HERE,text=True)
        namespace={'__name__':'old_fixture'};exec(compile(old_source,'retained_old_monitor','exec'),namespace)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'native.log';p.write_bytes(b'baseline\n')
            old=namespace['log_sample'](p,None);current=m.log_sample(p,None)
            self.rotate(p);p.write_bytes(b'new\n')
            with self.assertRaisesRegex(namespace['Nonpass'],'truncated'):namespace['log_sample'](p,old)
            current=m.log_sample(p,current)
            self.assertTrue(current['coverage_gap']);self.assertEqual(current['rotation']['content_coverage'],'GAP_POSSIBLE')
            self.assertEqual(current['visible_footprint_bytes'],len(b'baseline\nnew\n'))
            with p.open('ab') as f:f.write(b'later\n')
            current=m.log_sample(p,current);self.assertTrue(current['coverage_gap']);self.assertIsNone(current['rotation'])
            self.rotate(p);current=m.log_sample(p,current)
            self.assertTrue(current['coverage_gap']);self.assertIn('.2.gz',current['archives'])

    def test_expected_transition_does_not_hide_observed_bad_or_split_tokens(self):
        for where in ('archive','current','split'):
            with self.subTest(where=where),tempfile.TemporaryDirectory() as d:
                p=Path(d)/'native.log';p.write_bytes(b'base\n');old=m.log_sample(p,None)
                if where=='archive':
                    with p.open('ab') as f:f.write(b'panic\n')
                self.rotate(p)
                p.write_bytes(b'pa' if where=='split' else b'panic\n' if where=='current' else b'')
                if where=='split':
                    old=m.log_sample(p,old)
                    with p.open('ab') as f:f.write(b'nic\n')
                with self.assertRaisesRegex(m.Nonpass,'nonfinite'):m.log_sample(p,old)

    def test_missing_unexpected_malformed_unsafe_and_budget_refuse(self):
        for fault in ('missing_archive','replacement','wrong_prefix','unknown_suffix','symlink','writable','malformed_gzip','gzip_bomb','rewritten_prefix'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as d:
                p=Path(d)/'native.log';p.write_bytes(b'base\n');old=m.log_sample(p,None)
                if fault=='missing_archive':p.write_bytes(b'')
                elif fault=='replacement':p.rename(Path(d)/'elsewhere');p.write_bytes(b'base\n')
                elif fault=='rewritten_prefix':p.write_bytes(b'BASE\nmore')
                elif fault=='unknown_suffix':Path(str(p)+'.8.gz').write_bytes(b'x')
                elif fault=='symlink':Path(str(p)+'.1').symlink_to(p)
                elif fault=='writable':p.chmod(0o666)
                else:
                    self.rotate(p)
                    if fault=='wrong_prefix':Path(str(p)+'.1').write_bytes(b'WRONG\n')
                    elif fault=='malformed_gzip':Path(str(p)+'.2.gz').write_bytes(b'not gzip')
                    else:Path(str(p)+'.2.gz').write_bytes(gzip.compress(b'x'*(m.CAP+1)))
                with self.assertRaises((m.Nonpass,OSError,EOFError)):m.log_sample(p,old)
        with tempfile.TemporaryDirectory() as d:
            a=Path(d)/'a';z=Path(d)/'z';a.write_bytes(b'xx');z.write_bytes(b'xx');budget=[3]
            m.log_sample(a,None,budget)
            with self.assertRaisesRegex(m.Nonpass,'backlog'):m.log_sample(z,None,budget)

    def test_unstable_read_fails_closed(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log';p.write_bytes(b'data');real=os.fstat;calls=[0]
            def changed(fd):
                st=real(fd);calls[0]+=1
                if calls[0]==2:
                    return SimpleNamespace(st_dev=st.st_dev,st_ino=st.st_ino,st_size=st.st_size+1,st_mtime_ns=st.st_mtime_ns,st_ctime_ns=st.st_ctime_ns)
                return st
            with patch.object(m.os,'fstat',side_effect=changed),self.assertRaisesRegex(m.Nonpass,'unstable'):m.log_sample(p,None)

    def test_gap_does_not_join_separate_content_epochs(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log';p.write_bytes(b'base\n');old=m.log_sample(p,None)
            with p.open('ab') as f:f.write(b'pa')
            old=m.log_sample(p,old);self.rotate(p);p.write_bytes(b'nic\n')
            new=m.log_sample(p,old);self.assertTrue(new['coverage_gap'])
            self.assertEqual(new['_tail'],b'nic\n')

    def test_policy_change_and_unsafe_manifest_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'policy';p.write_bytes(b'changed')
            with patch.object(m,'POLICY_PATH',str(p)),self.assertRaises(m.Nonpass):m.verify_policy()
            c=manifest();c['log_observation']['growth_metric']='generated-bytes'
            p.write_text(json.dumps(c))
            with self.assertRaisesRegex(m.Nonpass,'log_contract'):m.config(p)
            c=manifest();c['logs']=['/wrong/native.log'];p.write_text(json.dumps(c))
            with self.assertRaisesRegex(m.Nonpass,'fixed_log'):m.config(p)

    def test_archive_changed_after_its_read_refuses_whole_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log';p.write_bytes(b'base\n');archive=Path(str(p)+'.1');archive.write_bytes(b'old\n')
            real=os.fstat;calls=[0]
            def mutate(fd):
                st=real(fd)
                if os.readlink('/proc/self/fd/'+str(fd))==str(p):
                    calls[0]+=1
                    if calls[0]==2:
                        with archive.open('ab') as f:f.write(b'changed')
                return st
            with patch.object(m.os,'fstat',side_effect=mutate),self.assertRaisesRegex(m.Nonpass,'unstable_archive'):m.log_sample(p,None)

    def test_policy_hash_checked_even_with_safe_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'policy';p.write_bytes(b'synthetic harmless policy\n');st=p.stat();digest=m.hashlib.sha256(p.read_bytes()).hexdigest()
            safe=SimpleNamespace(st_mode=st.st_mode,st_uid=0,st_dev=st.st_dev,st_ino=st.st_ino,st_size=st.st_size,st_mtime_ns=st.st_mtime_ns)
            with patch.object(m,'POLICY_PATH',str(p)),patch.object(m.os,'fstat',return_value=safe):
                with patch.object(m,'POLICY_SHA',digest):self.assertEqual(m.verify_policy(),digest)
                with self.assertRaisesRegex(m.Nonpass,'policy_changed'):m.verify_policy()

    def test_every_observed_plain_or_expanded_content_range_is_scanned(self):
        for location in ('active','archive','gzip','anchor_split'):
            with self.subTest(location=location),tempfile.TemporaryDirectory() as d:
                p=Path(d)/'log';p.write_bytes(b'panic\n' if location=='active' else b'pa' if location=='anchor_split' else b'safe\n')
                if location in ('archive','gzip'):
                    Path(str(p)+'.1').write_bytes(b'panic\n' if location=='archive' else b'safe\n')
                if location=='gzip':Path(str(p)+'.2.gz').write_bytes(gzip.compress(b'panic\n'))
                if location=='anchor_split':
                    old=m.log_sample(p,None)
                    with p.open('ab') as f:f.write(b'nic\n')
                else:old=None
                with self.assertRaisesRegex(m.Nonpass,'nonfinite'):m.log_sample(p,old)

    def test_unexpected_archive_appearing_during_read_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log';p.write_bytes(b'safe\n');real=os.fstat;calls=[0]
            def add_archive(fd):
                st=real(fd)
                if os.readlink('/proc/self/fd/'+str(fd))==str(p):
                    calls[0]+=1
                    if calls[0]==2:Path(str(p)+'.8.gz').write_bytes(b'not permitted')
                return st
            with patch.object(m.os,'fstat',side_effect=add_archive),self.assertRaisesRegex(m.Nonpass,'unexpected_archive'):m.log_sample(p,None)

    def test_completed_gap_is_scoped_not_plain_pass_and_no_end_eligibility(self):
        with tempfile.TemporaryDirectory() as d:
            now=[0.]
            class Fake:
                log_gap=True
                def sample(self,result):result['log_coverage']='GAP_POSSIBLE'
            def sleep(seconds):now[0]+=seconds
            out=m.Artifacts(Path(d)/'run')
            with patch.object(signal,'setitimer'),patch.object(signal,'alarm'):
                self.assertEqual(m.run(manifest(),out,Fake(),lambda:now[0],sleep),0)
            summary=json.loads((out.root/'summary.json').read_text())
            self.assertEqual(summary['status'],'PASS_WITH_LOG_COVERAGE_GAP')
            self.assertEqual(summary['resource_health_status'],'PASS')
            self.assertEqual(summary['logcoverage'],'GAP_POSSIBLE');self.assertEqual(summary['log_continuity'],'UNPROVEN')
            self.assertFalse(summary['end_probe_eligible']);self.assertFalse(summary['abort_receipt'])


if __name__ == '__main__':
    unittest.main()
