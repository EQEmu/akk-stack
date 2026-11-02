"""Real trusted finite processes, independent sampler and bounded private transport."""
import base64
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


if __name__=='__main__': unittest.main()


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
