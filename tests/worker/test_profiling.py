"""Real trusted finite processes, independent sampler and bounded private transport."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import guest
import profile_artifacts as artifacts
import profile_inputs
import profiling
import runtime
import staging

HELPERS=('profiling.py','profile_artifacts.py','profile_inputs.py','profile_contract.py')


class Closure(unittest.TestCase):
    def test_exact_helpers_packaged_and_identity_bound(self):
        data=json.loads(guest.build_user_data('a'*32).removeprefix('#cloud-config\n'))
        files={item['path']:item['content'] for item in data['write_files']}
        for name in HELPERS:
            self.assertEqual(files['/opt/'+name],(ROOT/'validation/worker'/name).read_text())
            self.assertIn('validation/worker/'+name,runtime.IMPLEMENTATION_FILES)
            self.assertIn('validation/worker/'+name,staging.FILES)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in runtime.IMPLEMENTATION_FILES:
                dest=root/name; dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(b'original')
            original=runtime.implementation_identity(dict(code_dir=str(root)))
            for name in HELPERS:
                dest=root/'validation/worker'/name
                dest.write_bytes(b'changed')
                self.assertNotEqual(original,runtime.implementation_identity(dict(code_dir=str(root))))
                dest.unlink()
                with self.assertRaises(FileNotFoundError): runtime.implementation_identity(dict(code_dir=str(root)))
                dest.write_bytes(b'original')
            # The source allowlist is finite; unknown files do not join identity/packaging.
            self.assertNotIn('validation/worker/unknown.py',staging.FILES)
            (root/'validation/worker/unknown.py').write_bytes(b'not admitted')
            self.assertEqual(original,runtime.implementation_identity(dict(code_dir=str(root))))

    def test_packaging_refuses_changed_omitted_helpers_and_unknown_files(self):
        import test_setup
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o755)
            host=test_setup.FakeHost(root)
            code=root/'code'; code.mkdir(mode=0o755)
            expected={name:b'finite reviewed bytes' for name in staging.FILES}
            for name,data in expected.items():
                path=code/name; path.parent.mkdir(parents=True,exist_ok=True); path.parent.chmod(0o755)
                path.write_bytes(data); path.chmod(0o755 if name.startswith('scripts/') else 0o644)
            staging.existing_code(host,code,os.getuid(),expected)
            for name in HELPERS:
                path=code/'validation/worker'/name
                path.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'differs'): staging.existing_code(host,code,os.getuid(),expected)
                path.unlink()
                with self.assertRaisesRegex(ValueError,'missing or unknown'): staging.existing_code(host,code,os.getuid(),expected)
                path.write_bytes(expected['validation/worker/'+name]); path.chmod(0o644)
            (code/'validation/worker/unknown.py').write_bytes(b'not admitted')
            with self.assertRaisesRegex(ValueError,'unknown'): staging.existing_code(host,code,os.getuid(),expected)


class Artifacts(unittest.TestCase):
    def test_bounds_offsets_privacy_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); sink=artifacts.Sink(root/'raw')
            raw=artifacts.frame('timeline.jsonl',0,b'{"rss_bytes":123}\n')
            sink.accept(json.loads(raw.removeprefix(artifacts.PREFIX)))
            self.assertEqual((root/'raw/timeline.jsonl').stat().st_mode & 0o777,0o600)
            for value in (dict(name='../secret',offset=0,data='YQ=='),
                          dict(name='timeline.jsonl',offset=0,data='YQ=='),
                          dict(name='stages.jsonl',offset=0,data='!')):
                with self.assertRaises((ValueError,TypeError)): sink.accept(value)
            with patch.object(artifacts,'FILE_LIMIT',2):
                with self.assertRaises(ValueError): sink.accept(dict(name='stages.jsonl',offset=0,data='YWJj'))
            sink.accept(dict(name='timeline.jsonl',offset=len(b'{\"rss_bytes\":123}\n'),data='Yg=='))
            output=io.BytesIO(); artifacts.send(root/'raw',output)
            other=artifacts.Sink(root/'copy')
            for line in output.getvalue().splitlines(): other.accept(json.loads(line.removeprefix(artifacts.PREFIX)))
            self.assertEqual(sink.inventory(),other.inventory())
            (root/'raw/unexpected').touch()
            with self.assertRaises(ValueError): sink.inventory()

    def test_export_error_keeps_partial_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); sink=artifacts.Sink(root/'raw')
            sink.accept(dict(name='timeline.jsonl',offset=0,data='YQ=='))
            class Broken:
                def write(self,data): raise BrokenPipeError('fixture')
            with self.assertRaises(BrokenPipeError): artifacts.send(root/'raw',Broken())
            self.assertEqual((root/'raw/timeline.jsonl').read_bytes(),b'a')
            (root/'secret').write_bytes(b'private')
            (root/'raw/stages.jsonl').symlink_to(root/'secret')
            with self.assertRaises(OSError): sink.accept(dict(name='stages.jsonl',offset=0,data='YQ=='))
            self.assertEqual((root/'secret').read_bytes(),b'private')

    def test_writer_truncation_does_not_stop_later_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            writer=profiling.Writer(tmp)
            with patch.object(profiling,'FILE_LIMIT',5):
                self.assertTrue(writer.append('timeline.jsonl',b'1234'))
                self.assertFalse(writer.append('timeline.jsonl',b'56'))
                self.assertTrue(writer.append('stages.jsonl',b'a'))
            self.assertEqual(writer.truncated,{'timeline.jsonl'})


class Processes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='trusted-profiling-tests-')
        cls.root=Path(cls.temp.name); cls.binary=cls.root/'fixture'
        subprocess.run(['/usr/bin/gcc','-O2','-g','-fno-omit-frame-pointer','-fno-builtin-malloc',
                        str(Path(__file__).with_name('profiling_fixture.c')),'-o',str(cls.binary)],check=True)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def session(self,root,seconds=8):
        session=profiling.Session('timeline',root/'profile',{'zone':self.binary},os.getuid(),time.monotonic()+seconds,
            dict(scope='trusted-host-fixture',source_sha256=profiling.file_identity(Path(__file__).with_name('profiling_fixture.c'))['sha256'],
                flags=['-O2','-g','-fno-omit-frame-pointer']))
        with open(os.devnull,'wb') as sink:
            original=subprocess.Popen
            def launch(args,**kwargs):
                if args[2]=='export': kwargs['stdout']=sink
                return original(args,**kwargs)
            with patch.object(profiling.subprocess,'Popen',side_effect=launch): session.start()
        self.addCleanup(lambda: [p.kill() for p in (session.sampler,session.exporter) if p and p.poll() is None])
        return session

    def test_live_rss_cpu_and_sampler_survives_abrupt_child_death(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=self.session(Path(tmp))
            process=subprocess.Popen([str(self.binary)])
            try:
                time.sleep(1.3)
                before=(session.directory/'timeline.jsonl').stat().st_size
                process.kill(); process.wait(timeout=3)
                time.sleep(.5)
                self.assertIsNone(session.sampler.poll())
                self.assertGreater((session.directory/'timeline.jsonl').stat().st_size,before)
                result=session.finish()
                rows=[json.loads(row) for row in (session.directory/'timeline.jsonl').read_text().splitlines()]
                samples=[p for row in rows for p in row['processes']]
                self.assertTrue(result['complete'],result)
                self.assertGreater(max(p['rss_bytes'] or 0 for p in samples),15*1024**2)
                self.assertGreater(max(p['cpu_user_ticks'] for p in samples),0)
                self.assertTrue(any(row['unavailable'] for row in rows))
                self.assertFalse(result['sampler']['true_peak_known'])
                self.assertTrue(all(row['monotonic_ns']>0 for row in rows))
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=3)

    def test_deadline_and_cancel_are_finite_and_preserve_flushed_partial(self):
        for deadline in (True,False):
            with self.subTest(deadline=deadline),tempfile.TemporaryDirectory() as tmp:
                session=self.session(Path(tmp),seconds=.6 if deadline else 8)
                time.sleep(.8 if deadline else .3)
                if not deadline: session.sampler.send_signal(signal.SIGTERM)
                session.sampler.wait(timeout=3)
                summary=json.loads((session.directory/'summary.json').read_text())
                self.assertEqual(summary['stop_reason'],'deadline' if deadline else 'requested')
                self.assertGreater(summary['samples'],0)
                session.finish()
                self.assertIsNotNone(session.exporter.poll())

    def test_pid_identity_and_unavailable_access(self):
        current=profiling.proc_sample(os.getpid())
        with self.assertRaisesRegex(ValueError,'identity'):
            profiling.proc_sample(os.getpid(),current['start_ticks']+1)
        with self.assertRaises(OSError): profiling.proc_sample(2147483647)
        with patch.object(Path,'read_text',side_effect=PermissionError('fixture')):
            with self.assertRaises(PermissionError): profiling.proc_sample(os.getpid())

    def test_observer_block_does_not_block_sampler_and_transport_backpressure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            # Use an undrained exporter pipe, while the sampler continues local writes.
            session=profiling.Session('timeline',root/'profile',{'zone':self.binary},os.getuid(),time.monotonic()+8,{})
            original=subprocess.Popen
            def launch(args,**kwargs):
                if args[2]=='export': kwargs['stdout']=subprocess.PIPE
                return original(args,**kwargs)
            with patch.object(profiling.subprocess,'Popen',side_effect=launch): session.start()
            try:
                # Model a blocked observer; sampling must continue in its own process.
                time.sleep(.9)
                before=(session.directory/'timeline.jsonl').stat().st_size
                time.sleep(.5)
                self.assertGreater((session.directory/'timeline.jsonl').stat().st_size,before)
                session.sampler.terminate(); session.sampler.wait(timeout=3)
                session.exporter.kill(); session.exporter.communicate(timeout=3)
            finally:
                for child in (session.sampler,session.exporter):
                    if child.poll() is None: child.kill(); child.wait(timeout=3)



    def test_scheduler_pause_is_labeled_as_a_sampling_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            session=self.session(Path(tmp))
            process=subprocess.Popen([str(self.binary)])
            try:
                time.sleep(.3)
                session.sampler.send_signal(signal.SIGSTOP)
                time.sleep(.65)
                session.sampler.send_signal(signal.SIGCONT)
                time.sleep(.4)
                result=session.finish()
                self.assertGreaterEqual(result['sampler']['gap_count'],1)
                self.assertGreater(result['sampler']['maximum_gap_seconds'],.6)
            finally:
                if process.poll() is None: process.kill();process.wait(timeout=3)


class ProfileInputs(unittest.TestCase):
    def bundle(self,path,extra=False):
        import tarfile
        data=b'trusted opaque deb bytes'
        value=dict(version=1,packages=[dict(path='debs/tool.deb',package='heaptrack',version='1.5.0-1',
            bytes=len(data),sha256=hashlib.sha256(data).hexdigest())],tools={})
        with tarfile.open(path,'w') as stream:
            for name,raw in [('manifest.json',json.dumps(value).encode()),('debs/tool.deb',data)]+([('../escape',b'x')] if extra else []):
                info=tarfile.TarInfo(name);info.size=len(raw);stream.addfile(info,io.BytesIO(raw))
        return value

    def test_pinned_bundle_verifies_opaque_bytes_and_refuses_unknown_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'tools.tar'
            value=self.bundle(path)
            self.assertEqual(profile_inputs.manifest(path),value)
            self.bundle(path,extra=True)
            with self.assertRaisesRegex(ValueError,'Unexpected'): profile_inputs.manifest(path)

    def test_missing_requested_profiler_fails_without_starting_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(profiling.TOOLS,{'heaptrack':('/nonexistent/qndr-library',)}), \
                    patch.object(profiling.subprocess,'Popen') as launch:
                with self.assertRaises(FileNotFoundError):
                    profiling.Session('heaptrack',Path(tmp)/'profile',{},os.getuid(),time.monotonic()+1,{})
                launch.assert_not_called()


class WorkerTransport(unittest.TestCase):
    def setUp(self):
        import test_runtime
        test_runtime.Runtime.setUp(self)

    def test_deadline_retains_chunks_and_does_not_claim_complete(self):
        scratch=self.root/'scratch';scratch.mkdir()
        (scratch/'profile-requested').write_text(json.dumps(dict(profiling='timeline',candidate='a'*40,tree='b'*40)))
        script=self.root/'profile-producer.py'
        chunk=artifacts.frame('timeline.jsonl',0,b'{"partial":true}\n').decode()
        script.write_text('import time\nprint('+repr(chunk)+',end="",flush=True)\ntime.sleep(30)\n')
        detail={}
        with self.assertRaisesRegex(RuntimeError,'deadline'):
            runtime.supervise([sys.executable,str(script)],scratch,self.root/'serial.log',self.server,
                time.monotonic()+.5,'a'*32,build_result=detail)
        self.assertFalse(detail['profile_transport']['complete'])
        self.assertEqual((self.root/'profiles/timeline.jsonl').read_text(),'{"partial":true}\n')
        self.assertTrue(detail['profile_transport']['artifacts'])

    def test_native_failure_cleanup_and_collection_are_separate(self):
        from test_normal_world import baseline
        scratch=self.root/'scratch';scratch.mkdir()
        (scratch/'profile-requested').write_text(json.dumps(dict(profiling='timeline',candidate='a'*40,tree='b'*40)))
        normal=baseline();normal['exit_code']=1
        normal['profiling']=dict(mode='timeline',complete=False)
        result=dict(version=1,nonce='a'*32,scope='worker-build',exit_code=1,stage='normal-world',
            selected_checks=list(runtime.BUILD_CHECKS),completed_checks=list(runtime.BUILD_CHECKS[:-1]),normal_world=normal)
        text=artifacts.frame('timeline.jsonl',0,b'partial\n').decode()+'EQEMU_WORKER_RESULT '+json.dumps(result)+'\n'
        script=self.root/'profile-producer.py';script.write_text('print('+repr(text)+',end="",flush=True)\n')
        detail={}
        code=runtime.supervise([sys.executable,str(script)],scratch,self.root/'serial.log',self.server,
            time.monotonic()+3,'a'*32,build_result=detail)
        self.assertEqual(code,2)
        self.assertEqual(detail['normal_world']['exit_code'],1)
        self.assertTrue(detail['normal_world']['cleanup_complete'])
        self.assertFalse(detail['profile_transport']['complete'])

    def test_retained_collection_replaces_only_previous_profile(self):
        for name in ('old','new'):
            job=self.root/name;job.mkdir();sink=artifacts.Sink(job/'profiles')
            sink.accept(dict(name='timeline.jsonl',offset=0,data=base64.b64encode(name.encode()).decode()))
            report={};runtime.retain_profiles(job,self.state,name,report)
            self.assertEqual((self.state/'last-profile/timeline.jsonl').read_text(),name)
            self.assertEqual(report['profile_artifacts']['run_id'],name)
            self.assertFalse((job/'profiles').exists())

    def test_client_exports_separate_raw_files_and_retains_on_interrupted_report(self):
        import client
        import threading
        path=self.root/'profile.sock'
        request=dict(version=1,operation='build',profiling='timeline',candidate='a'*40,tree='b'*40,sha256='c'*64)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            listener.bind(str(path));listener.listen(1)
            def serve():
                conn,_=listener.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(artifacts.frame('timeline.jsonl',0,b'partial\n'))
            import threading
            thread=threading.Thread(target=serve);thread.start()
            try:
                with self.assertRaisesRegex(RuntimeError,'closed'):
                    client.exchange(path,request,profile_output=self.root/'client-raw')
            finally: thread.join(3)
        self.assertEqual((self.root/'client-raw/timeline.jsonl').read_text(),'partial\n')


class PerfRegressions(unittest.TestCase):
    def test_preflight_owns_a_writable_native_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def run(args,**kwargs):
                directory=root/'preflight'
                self.assertEqual(directory.stat().st_uid,os.getuid())
                self.assertEqual(directory.stat().st_mode&0o777,0o700)
                self.assertEqual(args[args.index('-o')+1],str(directory/'perf.data'))
                self.assertEqual(kwargs['prefix'],('/native-prefix',))
                return 17
            with patch.object(profiling,'tool',side_effect=run):
                self.assertEqual(profiling.perf_preflight(root/'preflight',os.getuid(),('/native-prefix',)),17)

    def test_perf_launch_never_raises_inherited_hard_limit(self):
        code='import resource,sys; sys.path.insert(0,'+repr(str(ROOT/'validation/worker'))+'); import profiling; resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576)); profiling.perf_limits(); print(resource.getrlimit(resource.RLIMIT_FSIZE))'
        output=subprocess.check_output([sys.executable,'-B','-c',code],text=True)
        self.assertEqual(output.strip(),'(1048576, 1048576)')




class RecoveryRegression(unittest.TestCase):
    def setUp(self):
        import test_runtime
        test_runtime.Runtime.setUp(self)

    def test_retained_profiles_remain_identifiable_after_uncertain_cleanup_recovery(self):
        run_id='d'*32
        job=self.state/run_id;job.mkdir(mode=0o700);(job/'scratch').mkdir(mode=0o700)
        sink=artifacts.Sink(job/'profiles')
        sink.accept(dict(name='timeline.jsonl',offset=0,data=base64.b64encode(b'partial\n').decode()))
        prior=dict(version=1,run_id=run_id,exit_code=2,cleanup_complete=False,profile_client_export_complete=False)
        runtime.retain_profiles(job,self.state,run_id,prior)
        runtime.refresh_profile_receipt(self.state,run_id,prior)
        runtime.atomic_json(self.state/'last-result.json',prior)
        runtime.atomic_json(self.state/'active.json',dict(run_id=run_id,invocation_id='a'*32,control='build',qemu_pid=123))
        with patch.object(runtime,'service_processes',return_value=[os.getpid()]):
            self.assertEqual(runtime.cleanup(self.value),0)
        recovery=json.loads((self.state/'last-result.json').read_text())
        self.assertEqual(recovery['exit_code'],2)
        self.assertFalse(recovery['cleanup_complete'])
        self.assertTrue(recovery['scratch_removed'])
        self.assertEqual(recovery['profile_artifacts']['run_id'],run_id)
        self.assertEqual(recovery['profile_artifacts']['files'],artifacts.inventory(self.state/'last-profile'))
        self.assertTrue(recovery['profile_artifacts']['partial'])
        output=io.BytesIO();artifacts.send(self.state/'last-profile',output)
        self.assertNotIn(b'collection.json',output.getvalue())
        self.assertIn(b'timeline.jsonl',output.getvalue())
        request=dict(version=1,operation='profile-artifacts',run_id=run_id)
        self.client.sendall(json.dumps(request).encode()+b'\n')
        exported=runtime.request(self.server,self.value)
        self.assertEqual(exported['scope'],'profile-export-only')
        self.assertFalse(exported['executed'])
        self.assertIsNone(exported['workload_exit_code'])
        self.assertEqual(exported['execution_exit_code'],2)
        self.assertIn(b'timeline.jsonl',self.client.recv(4096))




class ReviewR4ExportRegressions(unittest.TestCase):
    def test_exporter_sweeps_again_if_finalization_appears_during_a_sweep(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)
            (directory/'world.perf.data').write_bytes(b'final perf header and records')
            original=Path.is_file;fired=[False]
            def exists(path):
                if path==directory/'timeline.jsonl' and not fired[0]:
                    fired[0]=True
                    (directory/'summary.json').write_bytes(b'{"final":true}\n')
                    (directory/'export.done').touch()
                return original(path)
            output=io.BytesIO()
            from types import SimpleNamespace
            with patch.object(Path,'is_file',side_effect=exists,autospec=True),patch.object(profiling.sys,'stdout',SimpleNamespace(buffer=output)):
                profiling.exporter(dict(directory=str(directory),deadline=time.monotonic()+3))
            names={json.loads(line.removeprefix(artifacts.PREFIX))['name'] for line in output.getvalue().splitlines()}
            self.assertIn('summary.json',names)
            self.assertIn('world.perf.data',names)

    def test_ordinary_job_receipt_cannot_hide_retained_profile(self):
        import test_runtime
        test_runtime.Runtime.setUp(self)
        run_id='e'*32;job=self.state/run_id;job.mkdir()
        sink=artifacts.Sink(job/'profiles');sink.accept(dict(name='timeline.jsonl',offset=0,data='YQ=='))
        prior=dict(exit_code=2,cleanup_complete=False,guest=dict(exit_code=1,
            normal_world=dict(exit_code=1,cleanup_complete=True,database_cleanup=True,
                profiling=dict(mode='perf',complete=False,error='collector failed',collector_exit_codes=[1,0],analysis_exit_codes={'world-analysis':0})),
            profile_transport=dict(complete=False,partial=True)))
        runtime.retain_profiles(job,self.state,run_id,prior)
        runtime.atomic_json(self.state/'last-result.json',dict(version=1,run_id='f'*32,exit_code=0,scope='worker-smoke'))
        self.client.sendall(json.dumps(dict(version=1,operation='profile-artifacts',run_id=run_id)).encode()+b'\n')
        result=runtime.request(self.server,self.value)
        self.assertEqual(result['workload_exit_code'],1)
        self.assertEqual(result['execution_exit_code'],2)
        receipt=result['result_receipt']
        self.assertTrue(receipt['native_cleanup_complete'])
        self.assertTrue(receipt['database_cleanup_complete'])
        self.assertFalse(receipt['vm_cleanup_complete'])
        self.assertEqual(receipt['profiler']['collector_exit_codes'],[1,0])
        self.assertFalse(receipt['transport']['complete'])
        self.assertTrue(receipt['profiler']['error_present'])
        self.assertNotIn('collector failed',json.dumps(receipt))
        self.assertEqual(result['profile_artifacts']['run_id'],run_id)
        self.assertIn(b'timeline.jsonl',self.client.recv(4096))


class ReviewR7InitializationRegression(unittest.TestCase):
    def test_callback_failure_early_exit_and_uncertain_cleanup_close_launched_pipe(self):
        from unittest.mock import Mock
        for failure in ('callback','early-exit','stop'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                process=Mock(pid=4321);process.poll.return_value=1 if failure=='early-exit' else None
                started=Mock(side_effect=ValueError('callback failure') if failure=='callback' else None)
                with patch.object(runtime.subprocess,'Popen',return_value=process), \
                        patch.object(runtime,'disconnected',return_value=True), \
                        patch.object(runtime.os,'set_blocking'), \
                        patch.object(runtime.selectors,'DefaultSelector'), \
                        patch.object(runtime,'stop_process',side_effect=runtime.CleanupError('unconfirmed') if failure=='stop' else None) as stop:
                    with self.assertRaises((ValueError,RuntimeError)):
                        runtime.supervise(['/never-execute'],root,root/'serial',Mock(),time.monotonic()+1,'a'*32,started,{})
                started.assert_called_once_with(4321)
                stop.assert_called_once_with(process)
                process.stdout.close.assert_called_once()

    def test_profile_initialization_failure_records_ownership_and_reaps_launched_child(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scratch=root/'scratch';scratch.mkdir()
            (scratch/'profile-requested').write_text('{invalid-json')
            process=Mock(pid=4321);process.poll.return_value=None
            started=Mock()
            with patch.object(runtime.subprocess,'Popen',return_value=process), \
                    patch.object(runtime,'stop_process') as stop:
                with self.assertRaises(json.JSONDecodeError):
                    runtime.supervise(['/never-execute'],scratch,root/'serial',Mock(),time.monotonic()+1,'a'*32,started,{})
            started.assert_called_once_with(4321)
            stop.assert_called_once_with(process)
            process.stdout.close.assert_called_once()

    def test_sink_initialization_failure_preserves_vm_started_and_confirmed_cleanup(self):
        import test_build
        test_build.BuildRuntime.setUp(self)
        request=dict(test_build.BuildRuntime.build_request(self),profiling='timeline')
        self.client.sendall(b'ISO')
        stopped=[]
        original=runtime.stop_process
        def stop(process):
            original(process);stopped.append((process.pid,process.returncode))
        with patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}), \
                patch.object(artifacts,'Sink',side_effect=OSError('trusted sink initialization failure')), \
                patch.object(runtime,'stop_process',side_effect=stop):
            result=runtime.run_vm(self.value,self.server,build=request)
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['vm_started'])
        self.assertTrue(result['cleanup_complete'])
        owned=[entry for entry in stopped if entry[0]==result['qemu_pid']]
        self.assertEqual(len(owned),1)
        with self.assertRaises(ProcessLookupError): os.kill(owned[0][0],0)
        self.assertFalse((self.state/'active.json').exists())

    def test_ownership_record_failure_still_reaps_and_reports_launched(self):
        import test_build
        test_build.BuildRuntime.setUp(self)
        request=dict(test_build.BuildRuntime.build_request(self),profiling='timeline')
        self.client.sendall(b'ISO')
        original=runtime.atomic_json
        def record(path,value):
            if path.name=='active.json' and value.get('qemu_pid') is not None:
                raise OSError('ownership record failure')
            return original(path,value)
        with patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}), \
                patch.object(runtime,'atomic_json',side_effect=record):
            result=runtime.run_vm(self.value,self.server,build=request)
        self.assertTrue(result['vm_started'])
        self.assertEqual(result['exit_code'],2)
        self.assertTrue(result['cleanup_complete'])
        with self.assertRaises(ProcessLookupError): os.kill(result['qemu_pid'],0)

    def test_postlaunch_initialization_with_unconfirmed_reap_preserves_active_scratch(self):
        import test_build
        test_build.BuildRuntime.setUp(self)
        request=dict(test_build.BuildRuntime.build_request(self),profiling='timeline')
        self.client.sendall(b'ISO')
        original=runtime.stop_process
        def uncertain(process):
            original(process)
            if Path(process.args[0])==Path(runtime.QEMU):
                raise runtime.CleanupError('trusted unconfirmed reap fixture')
        with patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}), \
                patch.object(artifacts,'Sink',side_effect=OSError('sink init failure')), \
                patch.object(runtime,'stop_process',side_effect=uncertain):
            result=runtime.run_vm(self.value,self.server,build=request)
        self.assertTrue(result['vm_started'])
        self.assertEqual(result['exit_code'],2)
        self.assertFalse(result['cleanup_complete'])
        self.assertTrue((self.state/'active.json').is_file())
        self.assertTrue((self.state/result['run_id']/'scratch').is_dir())


class ReviewR6ClientExportRegression(unittest.TestCase):
    def setUp(self):
        import test_build
        test_build.BuildRuntime.setUp(self)

    def run_disconnect(self,receipt_failure=False):
        import test_build
        from test_normal_world import baseline
        request=dict(test_build.BuildRuntime.build_request(self),profiling='timeline')
        self.client.sendall(b'ISO')
        normal=dict(baseline(),profiling=dict(mode='timeline',complete=True))
        def simulate(*args):
            args[-2](12345)
            sink=artifacts.Sink(args[1].parent/'profiles')
            sink.accept(dict(name='timeline.jsonl',offset=0,data='YQ=='))
            args[-1].update(exit_code=0,normal_world=normal,profile_transport=dict(complete=True),completed_checks=list(runtime.BUILD_CHECKS))
            return 0
        with patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}), \
                patch.object(runtime,'supervise',side_effect=simulate), \
                patch.object(artifacts,'send',side_effect=BrokenPipeError('secret text must not enter receipt')), \
                (patch.object(runtime,'refresh_profile_receipt',side_effect=OSError('receipt write failed')) if receipt_failure else contextlib.nullcontext()):
            result=runtime.run_vm(self.value,self.server,build=request)
        return result

    def test_disconnect_receipt_survives_last_result_replacement(self):
        result=self.run_disconnect()
        self.assertEqual(result['exit_code'],2)
        receipt=result['profile_artifacts']['result_receipt']
        self.assertEqual(receipt['overall_exit_code'],2)
        self.assertEqual(receipt['workload_exit_code'],0)
        self.assertEqual(receipt['guest_exit_code'],0)
        self.assertTrue(receipt['transport']['complete'])
        self.assertFalse(receipt['client_export']['complete'])
        self.assertTrue(receipt['client_export']['error_present'])
        self.assertNotIn('secret',json.dumps(receipt))
        self.assertTrue(receipt['native_cleanup_complete'])
        self.assertTrue(receipt['database_cleanup_complete'])
        self.assertTrue(receipt['vm_cleanup_complete'])
        runtime.atomic_json(self.state/'last-result.json',dict(exit_code=0,scope='unrelated-smoke'))
        self.client.sendall(json.dumps(dict(version=1,operation='profile-artifacts',run_id=result['run_id'])).encode()+b'\n')
        exported=runtime.request(self.server,self.value)
        self.assertEqual(exported['exit_code'],0)
        self.assertEqual(exported['result_receipt'],receipt)
        self.assertEqual(exported['workload_exit_code'],0)
        self.assertEqual(exported['execution_exit_code'],2)
        self.assertIn(b'timeline.jsonl',self.client.recv(4096))

    def test_disconnect_and_receipt_write_failure_recovery_repairs_or_preserves_uncertainty(self):
        result=self.run_disconnect(receipt_failure=True)
        run_id=result['run_id']
        self.assertFalse(result['profile_retention_complete'])
        self.assertTrue((self.state/'active.json').exists())
        pending=runtime.retained_profile(self.state,run_id)
        self.assertEqual(pending['receipt_finalization'],'pending')
        self.assertTrue(pending['partial'])
        self.assertEqual(pending['execution_exit_code'],2)
        self.assertIsNone(pending['result_receipt']['client_export']['complete'])
        with patch.object(runtime,'service_processes',return_value=[os.getpid()]), \
                patch.object(runtime,'complete_profile_receipt',side_effect=OSError('still unwritable')):
            self.assertEqual(runtime.cleanup(self.value),2)
        self.assertTrue((self.state/'active.json').exists())
        self.assertEqual(runtime.retained_profile(self.state,run_id)['receipt_finalization'],'pending')
        with patch.object(runtime,'service_processes',return_value=[os.getpid()]):
            self.assertEqual(runtime.cleanup(self.value),0)
        self.assertFalse((self.state/'active.json').exists())
        repaired=runtime.retained_profile(self.state,run_id)
        self.assertEqual(repaired['receipt_finalization'],'complete')
        receipt=repaired['result_receipt']
        self.assertEqual(receipt['overall_exit_code'],2)
        self.assertEqual(receipt['workload_exit_code'],0)
        self.assertFalse(receipt['client_export']['complete'])
        self.assertTrue(receipt['client_export']['error_present'])
        runtime.atomic_json(self.state/'last-result.json',dict(exit_code=0,scope='unrelated-smoke'))
        self.client.sendall(json.dumps(dict(version=1,operation='profile-artifacts',run_id=run_id)).encode()+b'\n')
        exported=runtime.request(self.server,self.value)
        self.assertEqual(exported['result_receipt'],receipt)
        self.assertIn(b'timeline.jsonl',self.client.recv(4096))

    def test_interruption_before_retention_move_finishes_nonpass_receipt_or_keeps_active(self):
        run_id='d'*32
        job=self.state/run_id;job.mkdir();(job/'scratch').mkdir()
        sink=artifacts.Sink(job/'profiles');sink.accept(dict(name='timeline.jsonl',offset=0,data='YQ=='))
        runtime.atomic_json(self.state/'active.json',dict(run_id=run_id,invocation_id='a'*32,control='build',qemu_pid=123))
        with patch.object(runtime,'service_processes',return_value=[os.getpid()]), \
                patch.object(runtime,'refresh_profile_receipt',side_effect=OSError('write unavailable')):
            self.assertEqual(runtime.cleanup(self.value),2)
        self.assertTrue((self.state/'active.json').exists())
        pending=runtime.retained_profile(self.state,run_id)
        self.assertEqual(pending['receipt_finalization'],'pending')
        self.assertEqual(pending['execution_exit_code'],2)
        with patch.object(runtime,'service_processes',return_value=[os.getpid()]):
            self.assertEqual(runtime.cleanup(self.value),0)
        self.assertFalse((self.state/'active.json').exists())
        complete=runtime.retained_profile(self.state,run_id)
        self.assertEqual(complete['receipt_finalization'],'complete')
        self.assertEqual(complete['execution_exit_code'],2)
        self.assertIsNone(complete['result_receipt']['workload_exit_code'])
        self.assertFalse(complete['result_receipt']['client_export']['complete'])
        self.assertTrue(complete['result_receipt']['client_export']['error_present'])


class ReviewR10FifoFinalizationRegression(unittest.TestCase):
    def test_oversized_private_row_discards_its_suffix_through_next_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);os.mkfifo(directory/'zone.fifo')
            config=directory/'config.json'
            config.write_text(json.dumps(dict(mode='heaptrack',directory=tmp,binaries={'zone':'/bin/true'},uid=os.getuid(),deadline=time.monotonic()+5)))
            process=subprocess.Popen([sys.executable,'-B',str(ROOT/'validation/worker/profiling.py'),'sample',str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+2
                while not (directory/'sampler.ready').exists():
                    if process.poll() is not None or time.monotonic()>deadline: self.fail('sampler did not become ready')
                    time.sleep(.01)
                fd=os.open(directory/'zone.fifo',os.O_WRONLY)
                try:
                    prefix=b'X '+b'a'*20000
                    while prefix: prefix=prefix[os.write(fd,prefix):]
                    time.sleep(.3)
                    os.write(fd,b'+ private-argv-suffix\n- final-free\n')
                finally: os.close(fd)
                process.terminate();out,err=process.communicate(timeout=4)
                self.assertEqual(process.returncode,0,err)
                raw=(directory/'zone.heaptrack.raw').read_bytes()
                self.assertNotIn(b'private-argv',raw)
                self.assertIn(b'- final-free\n',raw)
                self.assertIn('zone.heaptrack.raw',json.loads((directory/'summary.json').read_text())['truncated'])
            finally:
                if process.poll() is None: process.kill()
                process.communicate(timeout=3)

    def test_stop_immediately_after_final_write_drains_complete_rows_and_labels_partial_tail(self):
        for tail,budget in ((b'- final-free\n',1),(b'- incomplete-free',1),(b'- final-free\n',0)):
            with self.subTest(tail=tail,budget=budget), tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp);os.mkfifo(directory/'zone.fifo')
                config=dict(mode='heaptrack',directory=tmp,binaries={'zone':'/bin/true'},uid=os.getuid(),deadline=time.monotonic()+3)
                prior={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
                def final_write():
                    fd=os.open(directory/'zone.fifo',os.O_WRONLY|os.O_NONBLOCK)
                    try: os.write(fd,b'X private-argv\n'+tail)
                    finally: os.close(fd)
                    signal.raise_signal(signal.SIGTERM)
                    return {}
                try:
                    with patch.object(profiling,'pressure',side_effect=final_write), \
                            patch.object(profiling,'FINAL_DRAIN_SECONDS',budget): profiling.sampler(config)
                finally:
                    for sig,handler in prior.items(): signal.signal(sig,handler)
                summary=json.loads((directory/'summary.json').read_text())
                raw=(directory/'zone.heaptrack.raw').read_bytes() if (directory/'zone.heaptrack.raw').exists() else b''
                self.assertNotIn(b'private-argv',raw)
                complete=tail.endswith(b'\n') and budget>0
                self.assertEqual(summary['allocation_drain']['complete'],complete)
                self.assertEqual(summary['sampler_complete'],complete)
                if complete:
                    self.assertEqual(raw,tail)
                    self.assertEqual(summary['truncated'],[])
                else:
                    self.assertIn('allocation-finalization',summary['truncated'])


class ReviewR8CollectorShutdownRegression(unittest.TestCase):
    def test_real_same_group_collector_exits_on_target_death_before_group_cleanup(self):
        import normal_world
        script='''import json,os,sys,time,subprocess
sys.path.insert(0,sys.argv[1]);import normal_world as normal
native=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
collector_code='''+repr('import os,sys,time\npid=int(sys.argv[1]);end=time.monotonic()+5\nwhile time.monotonic()<end:\n try: os.kill(pid,0)\n except ProcessLookupError: sys.exit(0)\n time.sleep(.02)\nsys.exit(1)')+'''
collector=subprocess.Popen([sys.executable,'-c',collector_code,str(native.pid)])
try:
 error=normal.finalize_collectors([native],[collector])
finally:
 clean=normal.stop([native,collector])
print(json.dumps(dict(error=error,clean=clean,collector=collector.returncode)))
'''
        process=subprocess.Popen([sys.executable,'-B','-c',script,str(ROOT/'validation/worker')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            out,err=process.communicate(timeout=15)
            self.assertEqual(process.returncode,0,err)
            self.assertEqual(json.loads(out),dict(error=None,clean=True,collector=0))
        finally:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=3)


class ReviewR12SimultaneousExitRegression(unittest.TestCase):
    def test_native_failure_precedes_collector_exit_after_readiness(self):
        import itertools
        import normal_world as normal
        from unittest.mock import Mock
        for mode,native_died,collector_exit in ((None,True,0),('perf',True,0),('perf',True,1),('perf',False,1)):
            with self.subTest(mode=mode,native_died=native_died,collector_exit=collector_exit), tempfile.TemporaryDirectory() as tmp:
                server=Path(tmp);after_readiness=False
                natives=[Mock(pid=101),Mock(pid=102)]
                collectors=[Mock(pid=201,returncode=collector_exit),Mock(pid=202,returncode=collector_exit)]
                for child in natives:
                    child.poll.side_effect=lambda: 1 if after_readiness and native_died else None
                for child in collectors:
                    child.poll.side_effect=lambda: collector_exit if after_readiness else None
                launched=[]
                def launch(args,**kwargs):
                    child=collectors[len([p for p in launched if p in collectors])] if args[0]=='/usr/bin/perf' else natives[len([p for p in launched if p in natives])]
                    launched.append(child);return child
                def ready(**kwargs):
                    nonlocal after_readiness
                    after_readiness=True;return True
                config=server/'profile.json';config.write_text(json.dumps(dict(mode='perf',directory=str(server))))
                output=io.StringIO()
                with patch.object(normal.os,'geteuid',return_value=65534),patch.object(normal.resource,'setrlimit'), \
                        patch.object(normal.Path,'is_file',return_value=True),patch.object(normal.subprocess,'Popen',side_effect=launch), \
                        patch.object(normal,'world_connected',return_value=True),patch.object(normal,'probe',side_effect=ready), \
                        patch.object(normal,'cpu_ticks',return_value=0),patch.object(normal,'failure_snapshot',return_value={}), \
                        patch.object(normal,'finalize_collectors',return_value=None),patch.object(normal,'stop',return_value=True) as stop, \
                        patch.object(normal.time,'monotonic',side_effect=itertools.count(0,.1)),contextlib.redirect_stdout(output):
                    normal.observe(Path('/never-execute-candidate'),server,None,config if mode else None)
                result=json.loads(next(line.removeprefix('NORMAL_WORLD_RESULT ') for line in output.getvalue().splitlines() if line.startswith('NORMAL_WORLD_RESULT ')))
                self.assertEqual(result['exit_code'],1 if native_died else 2)
                self.assertTrue(result['cleanup_complete']);stop.assert_called_once()
                self.assertIn('Normal server exited' if native_died else 'perf collector exited',result['error'])
                if mode:self.assertEqual(result['profile_processes']['perf_exit_codes'],[collector_exit]*2)


class ReviewR5CollectorRegression(unittest.TestCase):
    def test_failed_collector_cannot_pass_with_readable_analyzed_data(self):
        from unittest.mock import Mock
        for codes in ([1,0],[-9,0],None,[],[None,0],[True,0],[0,0]):
            with self.subTest(codes=codes), tempfile.TemporaryDirectory() as tmp:
                directory=Path(tmp)
                (directory/'summary.json').write_text(json.dumps(dict(sampler_complete=True,processes=[{}],truncated=[])))
                for name in ('world','zone'): (directory/(name+'.perf.data')).write_bytes(b'readable partial trace')
                session=object.__new__(profiling.Session)
                session.directory=directory;session.mode='perf';session.tools={};session.preflight={}
                session.config={'binaries':{'world':{},'zone':{}}}
                session.sampler=Mock(returncode=0);session.exporter=Mock(returncode=0);session.stage=Mock()
                with patch.object(profiling,'tool',return_value=0) as analyze:
                    result=session.finish(collector_exit_codes=codes,collector_finalization_error='TimeoutExpired' if codes==[0,0] else None)
                self.assertFalse(result['complete'])
                self.assertIn('collector',result['error'])
                self.assertEqual(analyze.call_count,2)
                self.assertTrue((directory/'world.perf.data').exists())

    def test_collector_and_analyzer_zero_nonzero_matrix(self):
        from unittest.mock import Mock
        for collector in (0,1):
            for analyzer in (0,1):
                with self.subTest(collector=collector,analyzer=analyzer), tempfile.TemporaryDirectory() as tmp:
                    directory=Path(tmp)
                    (directory/'summary.json').write_text(json.dumps(dict(sampler_complete=True,processes=[{}],truncated=[])))
                    for name in ('world','zone'): (directory/(name+'.perf.data')).write_bytes(b'readable trace')
                    session=object.__new__(profiling.Session)
                    session.directory=directory;session.mode='perf';session.tools={};session.preflight={}
                    session.config={'binaries':{'world':{},'zone':{}}}
                    session.sampler=Mock(returncode=0);session.exporter=Mock(returncode=0);session.stage=Mock()
                    with patch.object(profiling,'tool',return_value=analyzer):
                        result=session.finish(collector_exit_codes=[collector,collector])
                    self.assertEqual(result['complete'],collector==analyzer==0)
                    self.assertEqual(result['collector_exit_codes'],[collector,collector])
                    self.assertEqual(result['analysis_exit_codes'],{'world-analysis':analyzer,'zone-analysis':analyzer})

    def test_receipt_projects_only_finite_codes_and_flags_without_error_text(self):
        secret='do-not-retain-private-error'
        receipt=runtime.profile_receipt(dict(exit_code=2,cleanup_error=secret,guest=dict(
            error=secret,profile_transport=dict(complete=False,export_error=secret),normal_world=dict(
                exit_code=1,error=secret,profiling=dict(mode='perf',error=secret,
                    collector_exit_codes=[1,secret],analysis_exit_codes={'world-analysis':0,secret:secret},
                    preflight=dict(exit_code=1,error=secret))))))
        self.assertNotIn(secret,json.dumps(receipt))
        self.assertEqual(receipt['workload_exit_code'],1)
        self.assertEqual(receipt['profiler']['collector_exit_codes'],[1,None])
        self.assertTrue(receipt['profiler']['error_present'])
        self.assertTrue(receipt['transport']['error_present'])


if __name__=='__main__': unittest.main()
