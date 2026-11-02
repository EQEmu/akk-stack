"""Additive publication tested on a synthetic filesystem. No real root/service calls."""
import copy
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import profile_contract as contract
import profile_release as release
import runtime
import test_runtime


class FakeHost(release.Host):
    def __init__(self,root):
        super().__init__(root);self.owners={};self.calls=[];self.active=False;self.fail_after=None;self.writes=0;self.socket_loaded=False
    def info(self,path):
        info=list(path.lstat()); info[4],info[5]=self.owners.get(str(path),(0,0))
        return os.stat_result(info)
    def chown(self,path,uid,gid):
        self.owners[str(path)]=(uid,gid);self.writes+=1
        if self.fail_after==self.writes: raise RuntimeError('injected publication interruption')
    def run(self,args):
        self.calls.append(args)
        if args[1]=='list-units':
            if '--type=socket' in args:
                return release.SOCKET+' loaded active listening\n' if self.socket_loaded else ''
            return 'eqemu-validator@1.service loaded active running\n' if self.active else ''
        if args[1]=='start' and args[2]==release.SOCKET: self.socket_loaded=True
        if args[1]=='stop' and args[2]==release.SOCKET:
            if not self.socket_loaded and not self.path('/etc/systemd/system/'+release.SOCKET).exists():
                raise subprocess.CalledProcessError(5,args)
            self.socket_loaded=False
        return ''
    def processes(self): pass
    def account(self,name):
        from types import SimpleNamespace
        return SimpleNamespace(pw_uid=os.getuid() if name=='worker' else os.getuid()+2,pw_gid=os.getgid())


class Publication(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o755)
        self.host=FakeHost(self.root)
        for path in ('/etc/eqemu-validator','/etc/systemd/system','/etc/apparmor.d','/srv','/var/lib/eqemu-validator'):
            self.host.path(path).mkdir(parents=True,exist_ok=True)
        self.ordinary=dict(version=1,user='worker',worker_uid=os.getuid(),worker_gid=os.getgid(),submitter=pwd.getpwuid(os.getuid()).pw_name,
            state_dir='/var/lib/eqemu-validator',code_dir='/srv/ordinary',socket='/run/eqemu-validator.sock',base_image='/public/base.qcow2')
        for name in ('config.json','asan-v1.json','asan-v2.json','asan-v3.json'):
            config=dict(self.ordinary)
            stem='eqemu-validator' if name=='config.json' else 'eqemu-validator-'+name.removesuffix('.json')
            if name!='config.json': config['code_dir']='/srv/'+stem
            dest=self.host.path('/etc/eqemu-validator/'+name);dest.write_text(json.dumps(config));dest.chmod(0o644)
            code=self.host.path(config['code_dir'])
            for file,mode in (('scripts/check-validation-worker',0o755),('validation/worker/runtime.py',0o644)):
                path=code/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'retained asset');path.chmod(mode)
                self.host.owners[str(path)]=(1000,1000) if name=='config.json' else (0,0)
            for suffix in ('@.service','.socket'):
                self.host.path('/etc/systemd/system/'+stem+suffix).write_bytes(b'retained unit')
            self.host.path('/etc/apparmor.d/'+stem).write_bytes(b'retained profile')
        lock=self.host.path(release.SHARED_LOCK);lock.touch(mode=0o600)
        self.host.owners[str(lock)]=(self.ordinary['worker_uid'],self.ordinary['worker_gid'])
        self.host.path('/var/lib/eqemu-validator').chmod(0o700)
        self.host.owners[str(lock.parent)]=(self.ordinary['worker_uid'],self.ordinary['worker_gid'])
        for path in self.root.rglob('*'):
            if path.is_dir() and path!=lock.parent: path.chmod(0o755)
        self.package=self.root/'package'
        self.receipt=release.prepare(self.package,ROOT,self.ordinary,'a'*40,'b'*40,host=self.host)
        self.before=release.retained(self.host)

    def operation(self,name): return release.operate(self.host,self.package,self.receipt['package_sha256'],name)

    def test_new_package_is_self_consistent_and_scope_exact(self):
        value,files,config=release.load_package(self.package,self.receipt['package_sha256'])
        self.assertEqual(set(contract.SOURCE_FILES),set(release.SOURCE_FILES))
        contract.validate(config,contract.CONFIG,self.ordinary)
        policy=files['apparmor'].decode()
        self.assertIn('/etc/eqemu-validator/profiling.json r,',policy)
        self.assertIn('/etc/eqemu-validator/config.json r,',policy)
        self.assertIn('/var/lib/eqemu-validator-inputs',policy) if 'inputs' in self.ordinary['base_image'] else None
        self.assertIn('profile eqemu-validator-profiling ',policy)
        self.assertNotIn('peer=eqemu-validator,',policy)
        self.assertIn('/var/lib/eqemu-validator/worker.lock rwk,',policy)
        self.assertIn('CapabilityBoundingSet=\n',files['service'].decode())
        self.assertIn('NoNewPrivileges=yes',files['service'].decode())
        self.assertIn('MemoryMax=6G',files['service'].decode())
        self.assertIn('profiling.json',files['service'].decode())
        self.assertFalse(self.receipt['installed'])
        self.assertEqual(json.loads(files['retained.json'])['files'],self.before)

    def test_apply_verify_repeat_and_rollback_preserve_every_retained_asset(self):
        self.operation('apply');self.operation('apply');self.operation('verify')
        self.assertEqual(release.retained(self.host),self.before)
        ordinary_helper=self.before['srv/ordinary/scripts/check-validation-worker']
        self.assertEqual((ordinary_helper['uid'],ordinary_helper['gid'],ordinary_helper['mode']),(1000,1000,0o755))
        for call in self.host.calls:
            self.assertFalse(call[1:2] in (['start'],['enable']))
        self.operation('rollback');self.operation('rollback')
        self.assertEqual(release.retained(self.host),self.before)
        self.assertFalse(self.host.path(release.CONFIG).exists())
        self.assertFalse(self.host.path(release.RELEASE_ROOT+'/'+'a'*40).exists())

    def test_reviewed_public_snapshot_never_probes_private_state_or_lock(self):
        original=self.host.path
        def public_only(name):
            if str(name).startswith('/var/'):
                self.fail('Preparation must not observe private active markers or lock')
            return original(name)
        with patch.object(self.host,'path',side_effect=public_only):
            receipt=release.prepare(self.root/'public-only',ROOT,self.ordinary,'a'*40,'b'*40,host=self.host)
        self.assertEqual(receipt['package_sha256'],self.receipt['package_sha256'])

    def test_before_first_apply_retained_bytes_and_metadata_drift_refuse_without_publication(self):
        changes=[('/srv/ordinary/validation/worker/runtime.py',kind) for kind in ('bytes','mode','uid','gid')]
        changes += [('/srv/eqemu-validator-asan-v1/scripts/check-validation-worker',kind) for kind in ('bytes','mode')]
        for config,stem in (('config.json','eqemu-validator'),('asan-v1.json','eqemu-validator-asan-v1'),
                            ('asan-v2.json','eqemu-validator-asan-v2'),('asan-v3.json','eqemu-validator-asan-v3')):
            changes += [('/etc/eqemu-validator/'+config,'bytes'),('/etc/systemd/system/'+stem+'@.service','bytes'),
                        ('/etc/systemd/system/'+stem+'.socket','bytes'),('/etc/apparmor.d/'+stem,'bytes')]
        for name,kind in changes:
            with self.subTest(asset=name,change=kind):
                case=Publication();case.setUp()
                try:
                    path=case.host.path(name)
                    if kind=='bytes': path.write_bytes(path.read_bytes()+b'\n')
                    elif kind=='mode': path.chmod(0o600)
                    else:
                        info=case.host.info(path)
                        case.host.owners[str(path)]=(info.st_uid+(kind=='uid'),info.st_gid+(kind=='gid'))
                    original=release.retained
                    def locked_snapshot(host):
                        with self.assertRaises(BlockingIOError):
                            with release.shared_lock(host,case.ordinary): pass
                        return original(host)
                    with patch.object(release,'retained',side_effect=locked_snapshot):
                        with self.assertRaisesRegex(ValueError,'Reviewed retained assets changed'): case.operation('apply')
                    for owned in (release.JOURNAL,release.CONFIG,release.STATE,release.RELEASE_ROOT+'/'+'a'*40,
                                  '/etc/systemd/system/'+release.SERVICE,'/etc/systemd/system/'+release.SOCKET,release.POLICY):
                        self.assertFalse(case.host.path(owned).exists())
                    self.assertFalse(release.temporary(case.host.path(release.JOURNAL)).exists())
                    self.assertFalse(any(call[1] in ('start','stop','daemon-reload','-r','-R') for call in case.host.calls))
                finally: case.doCleanups()

    def test_reviewed_baseline_is_package_bound_and_enforced_on_later_operations(self):
        self.operation('apply')
        target=self.host.path('/srv/ordinary/validation/worker/runtime.py');original=target.read_bytes()
        target.write_bytes(original+b'drift')
        for operation in ('apply','verify','activate','rollback'):
            with self.subTest(operation=operation),self.assertRaisesRegex(ValueError,'Reviewed retained assets changed'):
                self.operation(operation)
            self.assertTrue(self.host.path(release.CONFIG).exists())
        other=release.prepare(self.root/'different-baseline',ROOT,self.ordinary,'a'*40,'b'*40,host=self.host)
        self.assertNotEqual(other['package_sha256'],self.receipt['package_sha256'])
        target.write_bytes(original);self.operation('rollback');self.operation('rollback')
        snapshot=self.package/'retained.json';saved=snapshot.read_bytes();snapshot.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'identity mismatch'): self.operation('apply')
        snapshot.write_bytes(saved);snapshot.unlink()
        with self.assertRaisesRegex(ValueError,'omitted'): self.operation('apply')

    def test_bootstrap_literal_pins_ignore_mutable_checksum_file_and_detect_copy_drift(self):
        # This is the same stdin verification as the quoted handoff here-document.
        expected=(self.receipt['operator_sha256']+'  '+str(self.package/'operator.py')+'\n'
                  +self.receipt['package_sha256']+'  '+str(self.package/'package.json')+'\n')
        mutable=self.root/'submitter-writable.sha256';mutable.write_text('not trusted\n')
        def verify():
            return subprocess.run(['/usr/bin/sha256sum','--check','-'],input=expected,text=True,capture_output=True).returncode
        self.assertEqual(verify(),0)
        for name in ('operator.py','package.json'):
            path=self.package/name;original=path.read_bytes();path.write_bytes(original+b'changed')
            mutable.write_text(release.sha(path.read_bytes())+'  '+str(path)+'\n')
            self.assertNotEqual(verify(),0)
            path.write_bytes(original)
        self.assertEqual(verify(),0)

    def test_partial_publication_can_finish_or_roll_back_repeatedly(self):
        self.host.fail_after=5
        with self.assertRaisesRegex(RuntimeError,'interruption'): self.operation('apply')
        self.host.fail_after=None
        self.operation('rollback');self.operation('rollback')
        self.assertEqual(release.retained(self.host),self.before)
        self.operation('apply');self.operation('verify')

    def test_rollback_before_socket_publication_skips_confirmed_absence_and_repeats(self):
        self.host.fail_after=5
        with self.assertRaises(RuntimeError): self.operation('apply')
        self.host.fail_after=None
        self.assertFalse(self.host.path('/etc/systemd/system/'+release.SOCKET).exists())
        self.operation('rollback');self.operation('rollback')
        self.assertFalse(any(call[1:3]==['stop',release.SOCKET] for call in self.host.calls))
        self.assertFalse(self.host.path(release.JOURNAL).exists())

    def test_rollback_stops_owned_loaded_socket_and_refuses_uncertain_query_or_stop_error(self):
        self.operation('apply');self.operation('activate')
        original=self.host.run
        def uncertain(args):
            if '--type=socket' in args: return release.SOCKET+' loaded activating start\n'
            return original(args)
        with patch.object(self.host,'run',side_effect=uncertain):
            with self.assertRaisesRegex(ValueError,'Uncertain'): self.operation('rollback')
        def stop_error(args):
            if args[1:3]==['stop',release.SOCKET]: raise subprocess.CalledProcessError(1,args)
            return original(args)
        with patch.object(self.host,'run',side_effect=stop_error):
            with self.assertRaises(subprocess.CalledProcessError): self.operation('rollback')
        self.assertTrue(self.host.path(release.CONFIG).exists())
        self.operation('rollback')
        self.assertTrue(any(call[1:3]==['stop',release.SOCKET] for call in self.host.calls))

    def test_collision_drift_unknown_source_and_tampering_refuse(self):
        collision=self.host.path(release.CONFIG);collision.write_bytes(b'not owned')
        with self.assertRaises(ValueError): self.operation('apply')
        self.assertEqual(collision.read_bytes(),b'not owned');collision.unlink()
        self.operation('apply')
        code=self.host.path(release.RELEASE_ROOT+'/'+'a'*40)
        unknown=code/'unknown.py';unknown.write_bytes(b'preserve')
        with self.assertRaisesRegex(ValueError,'Unknown'): self.operation('rollback')
        unknown.unlink()
        target=code/'validation/worker/profiling.py';original=target.read_bytes();target.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'changed'): self.operation('rollback')
        self.assertTrue(self.host.path(release.CONFIG).exists())
        target.write_bytes(original)
        (self.package/'unknown').touch()
        with self.assertRaisesRegex(ValueError,'Unknown'): self.operation('verify')

    def test_lock_contention_bad_lock_mode_and_active_selection_refuse_before_mutation(self):
        # Real flock uses the same inode across the old/new selection.
        with release.shared_lock(self.host,self.ordinary):
            with self.assertRaises(BlockingIOError): self.operation('apply')
        self.host.active=True
        with self.assertRaisesRegex(ValueError,'active'): self.operation('apply')
        self.host.active=False
        lock=self.host.path(release.SHARED_LOCK);lock.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'0600'): self.operation('apply')
        lock.chmod(0o600)
        self.assertFalse(self.host.path(release.JOURNAL).exists())

    def test_profiling_active_marker_refuses_all_operations_before_side_effects(self):
        self.operation('apply')
        marker=self.host.path(release.STATE)/'active.json'
        for symlink in (False,True):
            if symlink: marker.symlink_to('/missing/uncertain-state')
            else: marker.write_text('{}')
            for operation in ('apply','verify','activate','rollback'):
                self.host.calls.clear()
                with self.assertRaisesRegex(ValueError,'unconfirmed'): self.operation(operation)
                self.assertFalse(any(call[1] in ('stop','start','-R','-r') for call in self.host.calls))
                self.assertTrue(self.host.path(release.CONFIG).exists())
            marker.unlink()
        self.operation('rollback')

    def test_own_active_or_uncertain_unit_refuses_rollback_under_shared_lock(self):
        self.operation('apply')
        original=self.host.run
        def run(args):
            if args[1]=='list-units':
                self.assertIn('eqemu-validator*',args)
                with self.assertRaises(BlockingIOError):
                    with release.shared_lock(self.host,self.ordinary): pass
                return row
            return original(args)
        for row in ('eqemu-validator-profiling@1.service loaded active running\n',
                    'eqemu-validator-profiling@1.service loaded activating start\n',
                    'eqemu-validator-profiling@1.service uncertain\n'):
            self.host.calls.clear()
            with patch.object(self.host,'run',side_effect=run):
                with self.assertRaisesRegex(ValueError,'uncertain'): self.operation('rollback')
            self.assertFalse(any(call[1] in ('stop','-R') for call in self.host.calls))
            self.assertTrue(self.host.path(release.CONFIG).exists())

    def test_malformed_new_selection_and_new_manifest_mutation_or_omission_refuse(self):
        _,files,value=release.load_package(self.package,self.receipt['package_sha256'])
        for key,bad in (('shared_lock','/tmp/alternate'),('confinement','eqemu-validator-extra'),
                        ('selection','anything'),('source_commit','short'),('code_dir','/srv/ordinary'),
                        ('state_dir','/var/lib/eqemu-validator'),('socket','/run/eqemu-validator.sock')):
            changed=dict(value,**{key:bad})
            with self.subTest(key=key),self.assertRaises(ValueError): contract.validate(changed,contract.CONFIG,self.ordinary)
        self.operation('apply')
        root=self.host.path(value['code_dir'])
        def mapped(path): return self.host.path(path) if str(path).startswith('/srv/') else path
        with patch.object(contract,'Path',side_effect=lambda p: root if str(p)==value['code_dir'] else Path(p)):
            contract.verify_release(value,lambda p:p)
            path=root/'validation/worker/profile_contract.py';old=path.read_bytes();path.write_bytes(b'bad')
            with self.assertRaises(ValueError): contract.verify_release(value,lambda p:p)
            path.unlink()
            with self.assertRaises(FileNotFoundError): contract.verify_release(value,lambda p:p)
            path.write_bytes(old)

    def test_interrupted_temporary_file_is_reversible_without_partial_final_file(self):
        original=release.publish
        once=[False]
        def interrupt(host,path,data,mode):
            if not once[0]:
                once[0]=True
                pending=release.temporary(path);pending.write_bytes(data[:7]);pending.chmod(0o600);host.chown(pending,0,0)
                self.assertFalse(path.exists())
                raise RuntimeError('interrupted finite temporary write')
            return original(host,path,data,mode)
        with patch.object(release,'publish',side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError,'temporary'): self.operation('apply')
        self.operation('rollback');self.operation('rollback')
        self.assertEqual(release.retained(self.host),self.before)
        self.operation('apply');self.operation('verify')


class RuntimeSelection(unittest.TestCase):
    def test_profile_readiness_has_exact_label_and_ordinary_readiness_is_unchanged(self):
        # Reuse the real host-readiness probes with only their read-only OS seam mocked.
        base=test_runtime.Readiness()
        base.test_enforcing_profile_accepts_only_known_unconfined_stack_forms()
        value={'base_image':'/public/base','submitter':'submitter','selection':'profiling-v1'}
        limits=dict(memory_max='unused',**{'memory.max':'64','pids.max':'64','memory.swap.max':'0','cpu.max':'200000 100000','no_new_privileges':'1','effective_capabilities':'0'})
        from unittest.mock import Mock
        file=Mock();file.stat.return_value.st_size=1
        with patch.object(runtime,'invocation',return_value='a'*32),patch.object(runtime,'resource_state',return_value=limits), \
                patch.object(runtime,'root_file',return_value=file),patch.object(runtime.os.path,'isfile',return_value=True), \
                patch.object(runtime.os,'access',side_effect=lambda path,mode:path!='/home/submitter'), \
                patch.object(runtime.os,'open',return_value=42),patch.object(runtime.os,'close'), \
                patch.object(runtime.pwd,'getpwnam',return_value=Mock(pw_dir='/home/submitter')):
            for label,wanted in (('eqemu-validator-profiling (enforce)',True),('eqemu-validator (enforce)',False),
                                  ('eqemu-validator-profiling-extra (enforce)',False),('eqemu-validator-profiling (complain)',False)):
                with patch.object(runtime.Path,'read_text',return_value=label):
                    self.assertEqual(runtime.ready(value)['checks']['apparmor'],wanted)

    def test_old_and_new_acquire_contend_on_exact_same_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=Path(tmp);old=dict(state_dir=tmp,worker_uid=os.getuid(),worker_gid=os.getgid())
            fd=runtime.acquire(old)
            try:
                with patch.object(contract,'SHARED_LOCK',str(state/'worker.lock')):
                    new=dict(old,selection='profiling-v1',shared_lock=str(state/'worker.lock'))
                    with self.assertRaises(RuntimeError): runtime.acquire(new)
            finally: os.close(fd)
            with patch.object(contract,'SHARED_LOCK',str(state/'worker.lock')):
                new=dict(old,selection='profiling-v1',shared_lock=str(state/'worker.lock'))
                fd=runtime.acquire(new)
                try:
                    with self.assertRaises(RuntimeError): runtime.acquire(old)
                finally: os.close(fd)


class PublicationRegressions(unittest.TestCase):
    setUp=Publication.setUp
    operation=Publication.operation
    # Inherit the same synthetic publication contract for these targeted paths.
    def test_systemd_grants_only_exact_existing_shared_lock_write_path(self):
        _,files,_=release.load_package(self.package,self.receipt['package_sha256'])
        lines=files['service'].decode().splitlines()
        self.assertIn('ProtectSystem=strict',lines)
        self.assertIn('ReadWritePaths='+release.STATE+' '+release.SHARED_LOCK,lines)
        self.assertNotIn('ReadWritePaths=/var/lib/eqemu-validator',lines)

    def test_zero_size_virtual_profile_table_allows_policy_rollback(self):
        self.operation('apply')
        path=self.host.path('/sys/kernel/security/apparmor/profiles')
        path.parent.mkdir(parents=True);path.touch()
        self.assertEqual(path.stat().st_size,0)
        original=Path.open
        class Virtual:
            def __enter__(self): return self
            def __exit__(self,*_): pass
            def read(self,limit): return b'eqemu-validator-profiling (enforce)\n'
        # No filesystem-size comparison is valid for securityfs. A bounded
        # stream is sufficient even when a virtual file reports st_size=0.
        with patch.object(Path,'open',side_effect=lambda p,*a,**kw:Virtual() if p==path else original(p,*a,**kw),autospec=True):
            self.operation('rollback')
        self.assertTrue(any(call[0]=='/usr/sbin/apparmor_parser' and call[1]=='-R' for call in self.host.calls))


class ReviewR2Regressions(unittest.TestCase):
    setUp=Publication.setUp
    operation=Publication.operation

    def test_interrupted_journal_never_publishes_truncated_json(self):
        original=release.publish
        def interrupt(host,path,data,mode):
            if path==host.path(release.JOURNAL):
                pending=release.temporary(path);pending.write_bytes(data[:10]);pending.chmod(0o600);host.chown(pending,0,0)
                raise RuntimeError('interrupted journal creation')
            return original(host,path,data,mode)
        with patch.object(release,'publish',side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError,'journal'): self.operation('apply')
        self.assertFalse(self.host.path(release.JOURNAL).exists())
        self.operation('rollback');self.operation('rollback')
        self.operation('apply');self.operation('verify')
        self.assertEqual(release.retained(self.host),self.before)

    def test_special_unknown_entry_refuses_verify_and_rollback_before_deletion(self):
        self.operation('apply')
        code=self.host.path(release.RELEASE_ROOT+'/'+'a'*40)
        fifo=code/'unknown.fifo';os.mkfifo(fifo)
        for action in ('verify','rollback'):
            with self.subTest(action=action),self.assertRaisesRegex(ValueError,'Unknown'): self.operation(action)
            self.assertTrue(self.host.path(release.CONFIG).exists())
            self.assertTrue((code/'validation/worker/runtime.py').exists())
        fifo.unlink()
        import socket
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(code/'unknown.sock'))
            with self.assertRaisesRegex(ValueError,'Unknown'): self.operation('rollback')
        (code/'unknown.sock').unlink()
        self.operation('rollback')

    def test_unprotected_root_package_is_rejected(self):
        self.package.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'owner/mode'): self.operation('apply')
        self.assertFalse(self.host.path(release.JOURNAL).exists())


class ReviewR3Regression(unittest.TestCase):
    setUp=Publication.setUp
    operation=Publication.operation

    def test_verify_and_activate_refuse_drifted_expected_temporary_files(self):
        self.operation('apply')
        path=self.host.path(release.RELEASE_ROOT+'/'+'a'*40+'/validation/worker/runtime.py.profiling-tmp')
        path.write_bytes(b'unrelated bytes')
        for mode in (0o666,0o644):
            path.chmod(mode)
            for action in ('verify','activate'):
                with self.subTest(mode=mode,action=action),self.assertRaises(ValueError): self.operation(action)
        self.assertFalse(any(call[1:2]==['start'] for call in self.host.calls))
        path.unlink();self.operation('verify')


class ReviewR4RollbackRegression(unittest.TestCase):
    setUp=Publication.setUp
    operation=Publication.operation

    def test_policy_drift_refuses_before_socket_stop_or_policy_unload(self):
        self.operation('apply')
        table=self.host.path('/sys/kernel/security/apparmor/profiles')
        table.parent.mkdir(parents=True);table.write_text('eqemu-validator-profiling (enforce)\n')
        self.host.path(release.POLICY).write_text('profile eqemu-validator {}\n')
        self.host.calls.clear()
        with self.assertRaisesRegex(ValueError,'changed'): self.operation('rollback')
        self.assertFalse(any(call[1:2] in (['stop'],['-R']) for call in self.host.calls))
        self.assertTrue(self.host.path(release.CONFIG).exists())
