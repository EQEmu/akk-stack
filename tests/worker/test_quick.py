"""Trusted Python/data/process fixtures only; never runs candidate compilers or a VM."""
import base64
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import build_guest
import client
import guest
import quick_guest
import quick_prepare
import quick_snapshot as snapshot
import runtime
import test_runtime
from test_format import source_fixture,git


class QuickSnapshots(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.repo,self.base=source_fixture(self.root)
    def capture(self):return snapshot.capture(self.repo,self.base,'d'*64)

    def test_complete_dirty_snapshot_new_native_headers_deletion_and_exclusions(self):
        (self.repo/'zone').mkdir();(self.repo/'zone/a.cpp').write_text('opaque native bytes')
        (self.repo/'zone/new.h').write_text('opaque header')
        (self.repo/'rust/actors/deleted.rs').unlink()
        (self.repo/'.env').write_text('SECRET_NEVER_SUBMITTED')
        for directory in ('target','vendor','generated'):
            (self.repo/directory).mkdir();(self.repo/directory/'secret.rs').write_text('excluded')
        value=self.capture();names={e['path'] for e in value['files']}
        self.assertIn('zone/a.cpp',names);self.assertIn('zone/new.h',names)
        self.assertEqual(value['deleted'],['rust/actors/deleted.rs'])
        self.assertFalse({'.env','vendor/secret.rs','generated/secret.rs','target/secret.rs'}&names)
        archive=self.root/'source.tar';snapshot.archive(self.repo,value,archive)
        with tarfile.open(archive) as stream:self.assertEqual(set(stream.getnames()),names)
        self.assertNotIn('SECRET_NEVER_SUBMITTED',json.dumps(snapshot.identity(value)))
        self.assertEqual(snapshot.native_scope(value)['changed_translation_units'],['zone/a.cpp'])
        self.assertTrue(snapshot.native_scope(value)['limitations'])

    def test_symlink_oversize_malformed_and_stale_archive_refuse(self):
        value=self.capture();outside=self.root/'outside';outside.write_text('outside')
        link=self.repo/'evil.cpp';link.symlink_to(outside)
        with self.assertRaises(OSError):self.capture()
        link.unlink()
        with patch.object(snapshot,'FILE_LIMIT',1),self.assertRaises(ValueError):self.capture()
        for update in ({'path':'../escape.cpp'},{'path':'/absolute.cpp'},{'mode':'120000'},{'bytes':snapshot.FILE_LIMIT+1}):
            bad=copy.deepcopy(value);bad['files'][0].update(update)
            with self.subTest(update=update),self.assertRaises(ValueError):snapshot.validate_snapshot(bad)
        (self.repo/'rust/actors/old.rs').write_text('newer edit')
        with self.assertRaisesRegex(ValueError,'Source changed'):snapshot.archive(self.repo,value,self.root/'stale.tar')

    def test_archive_limit_covers_valid_maximum_count_long_pax_paths_without_large_files(self):
        # Reproduce the review counterexample using metadata only, not a 287 MB archive.
        value=dict(version=1,scope='working-snapshot-quick-input',base='a'*40,head='b'*40,recipe_sha256='d'*64,
                   files=[dict(path=str(index).zfill(4)+'a'*231+'.cpp',mode='100644',bytes=26843,sha256='e'*64)
                          for index in range(9999)],changed=[],deleted=[],gitlinks={})
        value['files'].append(dict(path='rust/actors/Cargo.toml',mode='100644',bytes=23,sha256='f'*64))
        snapshot.validate_snapshot(value)
        self.assertEqual(sum(entry['bytes'] for entry in value['files']),268403180)
        size=0
        for entry in value['files']:
            info=tarfile.TarInfo(entry['path']);info.size=entry['bytes'];info.mode=0o644
            size+=len(info.tobuf(format=tarfile.PAX_FORMAT,encoding='utf-8'))
            size+=(entry['bytes']+tarfile.BLOCKSIZE-1)//tarfile.BLOCKSIZE*tarfile.BLOCKSIZE
        size+=2*tarfile.BLOCKSIZE
        size=(size+tarfile.RECORDSIZE-1)//tarfile.RECORDSIZE*tarfile.RECORDSIZE
        self.assertEqual(size,286699520)
        self.assertGreater(size,272*1024**2)
        self.assertLessEqual(size,snapshot.ARCHIVE_LIMIT)
        # A longest valid four-byte Unicode path also fits the per-member proof.
        path='𐀀'*snapshot.PATH_CHARACTERS
        self.assertTrue(snapshot.safe_path(path))
        info=tarfile.TarInfo(path);info.size=1
        actual_overhead=len(info.tobuf(format=tarfile.PAX_FORMAT,encoding='utf-8'))+tarfile.BLOCKSIZE-1
        self.assertLessEqual(actual_overhead,snapshot.ARCHIVE_MEMBER_OVERHEAD)

    def test_bridge_changes_deleted_translation_unit_and_many_objects_unavailable(self):
        value=self.capture()
        for name in ('rust/actors/bridge/src/lib.rs','rust/actors/bridge/build.rs','rust/actors/Cargo.toml','zone/deleted.cpp','common/header.hpp'):
            with self.subTest(name=name):
                changed=dict(value,changed=[name],deleted=[name] if name.endswith('.cpp') else [])
                self.assertTrue(snapshot.native_scope(changed)['limitations'])
        core=dict(value,changed=['rust/actors/core/src/lib.rs'])
        self.assertEqual(snapshot.native_scope(core)['limitations'],[])
        many=dict(value,changed=[f'zone/source{i}.cpp' for i in range(9)])
        self.assertTrue(snapshot.native_scope(many)['limitations'])

    def extracted(self,value):
        source=self.root/'source';source.mkdir()
        archive=self.root/'source.tar';snapshot.archive(self.repo,value,archive)
        with tarfile.open(archive) as stream:stream.extractall(source,filter='data')
        return source

    def test_independent_rust_failures_accumulate_but_dependency_failure_skips(self):
        value=self.capture();source=self.extracted(value);calls=[]
        def command(name,args,**kwargs):
            calls.append(name)
            if name in ('rust-format','rust-clippy'):raise build_guest.CandidateFailure(name+': opaque source failure')
            return ''
        result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,command)
        self.assertEqual(result['exit_code'],1)
        self.assertEqual(result['failed_checks'],['rust-format','rust-clippy'])
        self.assertIn('rust-tests',calls);snapshot.validate_detail(result)
        calls.clear()
        def missing(name,args,**kwargs):
            calls.append(name)
            if name=='rust-dependencies':
                self.assertIs(kwargs['candidate'],False)
                raise RuntimeError('no matching package named offline_dependency found')
            return ''
        result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,missing)
        self.assertEqual(result['exit_code'],2)
        self.assertNotIn('rust-clippy',calls);self.assertNotIn('rust-tests',calls)
        self.assertIn('rust-clippy',result['skipped_checks']);snapshot.validate_detail(result)

    def test_header_unavailable_does_not_prevent_rust_feedback(self):
        (self.repo/'new.hpp').write_text('opaque header')
        value=self.capture();source=self.extracted(value);calls=[]
        result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,
                                      lambda name,*args,**kwargs:calls.append(name))
        self.assertEqual(result['exit_code'],2);self.assertEqual(result['unavailable_checks'],['native-objects'])
        self.assertEqual(calls,['rust-format','rust-dependencies','rust-clippy','rust-tests'])
        snapshot.validate_detail(result)

    def test_added_and_edited_unknown_native_headers_never_become_not_applicable(self):
        for index,suffix in enumerate(('.hh','.ipp','.tpp','','.unknown')):
            for mode in ('added','edited'):
                with self.subTest(suffix=suffix,mode=mode):
                    name=f'zone/input-{index}-{mode}{suffix}';path=self.repo/name;path.parent.mkdir(exist_ok=True)
                    if mode=='edited':
                        path.write_text('opaque original include')
                        git(self.repo,'add',name);git(self.repo,'commit','-qm','trusted header fixture')
                        self.base=git(self.repo,'rev-parse','HEAD')
                    path.write_text('opaque invalid include')
                    value=self.capture();source=self.root/f'extracted-{index}-{mode}';source.mkdir()
                    archive=self.root/f'archive-{index}-{mode}.tar';snapshot.archive(self.repo,value,archive)
                    with tarfile.open(archive) as stream:stream.extractall(source,filter='data')
                    calls=[]
                    result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,
                                                  lambda check,*args,**kwargs:calls.append(check))
                    self.assertEqual(result['exit_code'],2)
                    self.assertIn('native-objects',result['unavailable_checks'])
                    self.assertIn('rust-tests',result['completed_checks'])
                    self.assertFalse({'native-configure','native-objects'}&set(calls))
                    git(self.repo,'add',name);git(self.repo,'commit','-qm','trusted complete fixture')
                    self.base=git(self.repo,'rev-parse','HEAD')

    def test_native_not_applicable_exclusions_are_narrow_and_documented(self):
        value=self.capture()
        for name in ('README.md','documentation/module.rst','LICENSE','rustfmt.toml','rust/actors/.rustfmt.toml','rust/actors/core/src/lib.rs'):
            with self.subTest(name=name):self.assertEqual(snapshot.native_scope(dict(value,changed=[name]))['limitations'],[])
        for name in ('rust/actors/core/build.rs','rust/unknown.hh','rust/actors/core/Cargo.toml','zone/README.txt','zone/LICENSE'):
            with self.subTest(name=name):self.assertTrue(snapshot.native_scope(dict(value,changed=[name]))['limitations'])

    def test_generated_object_target_preserves_real_ninja_prerequisite_execution(self):
        (self.repo/'zone').mkdir();(self.repo/'zone/movement.cpp').write_text('opaque compile input')
        value=self.capture();source=self.extracted(value);build=self.root/'build';build.mkdir()
        entry=dict(directory=str(build),file=str(source/'zone/movement.cpp'),
                   command='/trusted/compiler -include generated/pch.h -o zone/CMakeFiles/zone.dir/movement.cpp.o -c '+str(source/'zone/movement.cpp'))
        (build/'compile_commands.json').write_text(json.dumps([entry]));calls=[]
        def command(name,args,**kwargs):calls.append((name,args));return ''
        with patch.object(build_guest,'WORK',self.root),patch.object(build_guest,'configure_native',return_value=build) as configure:
            result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,command)
        self.assertEqual(result['exit_code'],0,result);configure.assert_called_once()
        self.assertEqual(result['native_scope']['selected_objects'],['zone/CMakeFiles/zone.dir/movement.cpp.o'])
        self.assertEqual(calls[-1],('native-objects',['cmake','--build',str(build),'--parallel','1','--target','zone/CMakeFiles/zone.dir/movement.cpp.o']))
        # The compiler command is data only. It is never executed directly.
        self.assertFalse(any(args[0]=='/trusted/compiler' for _,args in calls));snapshot.validate_detail(result)

    def test_new_tu_missing_graph_and_escaped_or_ambiguous_outputs_unavailable(self):
        source=self.root/'src';source.mkdir();output=self.root/'build';output.mkdir()
        entry=dict(directory=str(output),file=str(source/'new.cpp'),command='/trusted/compiler -o x.o -c new.cpp')
        self.assertEqual(quick_guest.object_targets([entry],source,output,['new.cpp']),['x.o'])
        for entries in ([],[dict(entry,command='/trusted/compiler -o ../escape.o -c new.cpp')],
                        [dict(entry,command='/trusted/compiler -o a.o -o b.o')],[dict(entry,output='--arbitrary.o')]):
            with self.subTest(entries=entries),self.assertRaises(ValueError):quick_guest.object_targets(entries,source,output,['new.cpp'])

    def test_native_reference_error_keeps_file_line_feedback_and_rust_results(self):
        (self.repo/'zone').mkdir();(self.repo/'zone/movement.cpp').write_text('opaque data')
        value=self.capture();source=self.extracted(value);build=self.root/'build';build.mkdir()
        (build/'compile_commands.json').write_text(json.dumps([dict(directory=str(build),file=str(source/'zone/movement.cpp'),
            command='/trusted/compiler -o zone/movement.cpp.o -c '+str(source/'zone/movement.cpp'))]))
        def command(name,*args,**kwargs):
            if name=='native-objects':raise build_guest.CandidateFailure('zone/movement.cpp:14: error: cannot bind mutable reference in FindBestZ')
        with patch.object(build_guest,'WORK',self.root),patch.object(build_guest,'configure_native',return_value=build):
            result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,command)
        self.assertEqual(result['exit_code'],1);self.assertEqual(result['failed_checks'],['native-objects'])
        self.assertIn('rust-tests',result['completed_checks'])
        self.assertIn('zone/movement.cpp:14:',result['checks'][-1]['diagnostic'])

    def test_bound_success_and_unavailable_cannot_claim_wrong_native_scope(self):
        value=self.capture();source=self.extracted(value)
        result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,lambda *args,**kwargs:None)
        tool=quick_prepare.tool_identity(ROOT);identity=snapshot.identity(value)
        result.update(version=1,scope='working-snapshot-quickcheck',operation='quick',advisory=True,
            **{key:identity[key] for key in ('base','head','input_snapshot_sha256','recipe_sha256')},
            output_snapshot_sha256=identity['input_snapshot_sha256'],vm_started=True,cleanup_complete=True,
            timings=dict(boot_seconds=.1,preparation_seconds=.2,total_seconds=.3),
            **{key:tool[key] for key in ('implementation_sha256','rust_input_sha256','native_input_sha256')})
        snapshot.validate_result(result,value,tool)
        forged=copy.deepcopy(result);forged['native_scope']['changed_translation_units']=['zone/unknown.cpp']
        with self.assertRaisesRegex(ValueError,'scope differs'):snapshot.validate_result(forged,value,tool)
        forged=copy.deepcopy(result);forged['output_snapshot_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'mismatched'):snapshot.validate_result(forged,value,tool)

    def test_unicode_diagnostics_and_long_path_projections_obey_encoded_byte_limits(self):
        value=self.capture()
        paths=['甲'*70+'/'+'乙'*70+'/'+str(index)+'丙'*60+'.cpp' for index in range(32)]
        self.assertTrue(all(snapshot.safe_path(path) for path in paths))
        value['changed']=sorted(paths)
        value['files']+= [dict(path=path,mode='100644',bytes=0,sha256=snapshot.sha(b'')) for path in paths]
        snapshot.validate_snapshot(value)
        result=quick_guest.unavailable('日'*10000,value)
        self.assertGreater(result['native_scope']['omitted_translation_units'],0)
        self.assertTrue(result['native_scope']['limitations'])
        for entry in result['checks']:entry['diagnostic']=snapshot.diagnostic('日'*10000)
        self.assertTrue(all(len(snapshot.canonical(entry['diagnostic']))<=3000 for entry in result['checks']))
        snapshot.validate_detail(result)
        self.assertLessEqual(len(snapshot.canonical(result)),snapshot.RESULT_LIMIT)
        result.update(version=1,scope='working-snapshot-quickcheck')
        public=runtime.persisted_report(result)
        self.assertEqual(public['native_scope']['changed_translation_unit_count'],32)
        self.assertNotIn('甲',json.dumps(public,ensure_ascii=False))
        self.assertNotIn('日',json.dumps(public,ensure_ascii=False))
        wrapper=dict(version=1,scope='worker-observation',operation='last-result',exit_code=0,result=public)
        self.assertLess(len(snapshot.canonical(wrapper)),client.REPORT_LIMIT)

    def test_source_modification_turns_checks_unavailable_and_skips_later_commands(self):
        value=self.capture();source=self.extracted(value);calls=[]
        def mutates(name,*args,**kwargs):calls.append(name);(source/'rust/actors/old.rs').write_text('changed by test')
        result=quick_guest.run_checks(source,source/'submodules/vcpkg','/trusted/cargo',value,mutates)
        self.assertEqual(result['exit_code'],2);self.assertEqual(calls,['rust-format'])
        self.assertEqual(result['checks'][0]['reason'],'source-changed-by-check')


class QuickRuntime(unittest.TestCase):
    def setUp(self):test_runtime.Runtime.setUp(self)
    def request_data(self):
        files={name:dict(bytes=3,sha256='d'*64) for name in ('snapshot.json','eqemu.tar','websocketpp.tar','native.iso','rust-inputs.tar')}
        files['native.iso']['sha256']='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'
        files['rust-inputs.tar']=dict(snapshot.RUST_PACKAGES['original'])
        return dict(version=1,operation='quick',base='a'*40,head='b'*40,input_snapshot_sha256='c'*64,recipe_sha256='d'*64,
                    files=files,bytes=3,sha256=snapshot.sha(b'ISO'))
    def test_reviewed_packages_cross_runtime_boundary_and_wrong_records_refuse(self):
        for item in snapshot.RUST_PACKAGES.values():
            request=self.request_data();request['files']['rust-inputs.tar']=dict(item)
            self.client.sendall(snapshot.canonical(request)+b'\n')
            with patch.object(runtime,'run_vm',return_value={'exit_code':2}) as run:
                runtime.request(self.server,self.value)
                self.assertEqual(run.call_args.kwargs['quick']['files']['rust-inputs.tar'],item)
        for item in (dict(bytes=171284480,sha256='f'*64),
                     dict(snapshot.RUST_PACKAGES['additive-v1'],bytes=171284479)):
            request=self.request_data();request['files']['rust-inputs.tar']=item
            self.client.sendall(snapshot.canonical(request)+b'\n')
            with patch.object(runtime,'run_vm') as run,self.assertRaisesRegex(ValueError,'Malformed quick request'):
                runtime.request(self.server,self.value)
            run.assert_not_called()

    def test_quick_protocol_keeps_payload_and_no_execution_retries(self):
        request=self.request_data();self.client.sendall(snapshot.canonical(request)+b'\nISO')
        def consume(value,connection,**kwargs):
            self.assertEqual(kwargs['quick'],request);self.assertEqual(connection.recv(3),b'ISO');return {'exit_code':2}
        with patch.object(runtime,'run_vm',side_effect=consume):self.assertEqual(runtime.request(self.server,self.value),{'exit_code':2})
        with patch.object(client,'exchange_once',side_effect=ConnectionResetError) as once:
            with self.assertRaises(ConnectionResetError):client.exchange('/unused',request)
            once.assert_called_once()

    def test_quick_protocol_accepts_valid_pax_boundary_and_rejects_derived_cap_excess(self):
        request=self.request_data();request['files']['eqemu.tar']['bytes']=286699520
        request['bytes']=sum(entry['bytes'] for entry in request['files'].values())+1024**2
        self.client.sendall(snapshot.canonical(request)+b'\n')
        with patch.object(runtime,'run_vm',return_value={'exit_code':2}) as run:
            self.assertEqual(runtime.request(self.server,self.value),{'exit_code':2})
            self.assertEqual(run.call_args.kwargs['quick'],request)
        request['files']['eqemu.tar']['bytes']=snapshot.ARCHIVE_LIMIT+1
        self.client.sendall(snapshot.canonical(request)+b'\n')
        with patch.object(runtime,'run_vm') as run,self.assertRaisesRegex(ValueError,'Malformed quick request'):
            runtime.request(self.server,self.value)
        run.assert_not_called()

    def test_quick_vm_uses_build_resources_and_owned_cleanup(self):
        request=self.request_data();self.client.sendall(b'ISO')
        detail=quick_guest.unavailable('private source diagnostic')
        def simulate(*args,**kwargs):
            args[-1](12345);kwargs['quick_result'].update(detail,boot_seconds=.1,preparation_seconds=.2);return 2
        with patch.object(runtime.shutil,'disk_usage',return_value=type('Disk',(),{'free':100*1024**3})()), \
                patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}), \
                patch.object(runtime,'supervise',side_effect=simulate) as supervisor:
            result=runtime.run_vm(self.value,self.server,quick=request)
        self.assertEqual(result['exit_code'],2);self.assertTrue(result['advisory']);self.assertTrue(result['cleanup_complete'])
        argv=supervisor.call_args.args[0];self.assertEqual(argv[argv.index('-m')+1],'4096');self.assertEqual(argv[argv.index('-nic')+1],'none')
        persisted=json.loads((self.state/'last-result.json').read_text())
        self.assertNotIn('private source diagnostic',json.dumps(persisted));self.assertFalse((self.state/'active.json').exists())

    def test_quick_cancel_reaps_real_harmless_child_and_scratch(self):
        Path(runtime.QEMU).write_text('#!'+sys.executable+'\nimport time\ntime.sleep(30)\n')
        self.client.sendall(b'ISO');reports=[]
        with patch.object(runtime.shutil,'disk_usage',return_value=type('Disk',(),{'free':100*1024**3})()), \
                patch.object(runtime,'resource_state',return_value={'memory.max':str(6*1024**3)}):
            thread=threading.Thread(target=lambda:reports.append(runtime.run_vm(self.value,self.server,quick=self.request_data())))
            thread.start();time.sleep(.2);self.client.close();thread.join(3)
        self.assertFalse(thread.is_alive());result=reports[0]
        self.assertEqual(result['exit_code'],2);self.assertTrue(result['cleanup_complete'])
        with self.assertRaises(ProcessLookupError):os.kill(result['qemu_pid'],0)
        self.assertFalse((self.state/'active.json').exists());self.assertFalse(any(p.is_dir() for p in self.state.iterdir()))

    def test_quick_framing_partition_limits_and_nonce(self):
        detail=quick_guest.unavailable('private diagnostic');detail.update(version=1,scope='working-snapshot-quickcheck',nonce='a'*32)
        script=self.root/'emit.py';script.write_text('print('+repr('EQEMU_QUICK_RESULT '+base64.b64encode(snapshot.canonical(detail)).decode())+')\n')
        result={}
        self.assertEqual(runtime.supervise([sys.executable,str(script)],self.root,self.root/'quick.log',self.server,
                                          time.monotonic()+3,'a'*32,quick_result=result),2)
        bad=copy.deepcopy(detail);bad['completed_checks']=['rust-tests']
        with self.assertRaises(ValueError):snapshot.validate_detail(bad)
        with patch.object(snapshot,'RESULT_LIMIT',10),self.assertRaises(ValueError):snapshot.validate_detail(detail)
        (self.root/'quick.log').unlink()
        with self.assertRaisesRegex(RuntimeError,'Malformed quick completion'):
            runtime.supervise([sys.executable,str(script)],self.root,self.root/'quick.log',self.server,time.monotonic()+3,'f'*32,quick_result={})


class QuickCLI(unittest.TestCase):
    def setUp(self):
        loader=importlib.machinery.SourceFileLoader('quick_cli',str(ROOT/'scripts/quick-worker-snapshot'))
        spec=importlib.util.spec_from_loader(loader.name,loader);self.cli=importlib.util.module_from_spec(spec);loader.exec_module(self.cli)
    def test_named_selection_changes_recipe_and_rejects_unreviewed_names(self):
        identities=[]
        for name,item in snapshot.RUST_PACKAGES.items():
            with patch.object(self.cli,'exchange') as exchange,contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(self.cli.main(['--identity','--rust-package',name]),0)
            identity=json.loads(out.getvalue());identities.append(identity)
            self.assertEqual(identity['rust_input_sha256'],item['sha256']);exchange.assert_not_called()
        self.assertNotEqual(identities[0]['recipe_sha256'],identities[1]['recipe_sha256'])
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            self.cli.main(['--identity','--rust-package','unreviewed'])
        for name in snapshot.RUST_PACKAGES:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);rust=root/'rust.tar';rust.write_bytes(b'incomplete')
                profile=json.loads((ROOT/'validation/profile.json').read_text())
                with patch.object(quick_prepare.subprocess,'run') as package,self.assertRaisesRegex(ValueError,'pinned quick Rust'):
                    quick_prepare.prepare(root,dict(gitlinks=profile['sources']['eqemu']['gitlinks']),root,root/'native',rust,root/'out',name)
                package.assert_not_called()

    def test_identity_and_stale_input_never_contact_worker(self):
        with patch.object(self.cli,'exchange') as exchange,patch.object(self.cli,'prepare') as prepare,contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(self.cli.main(['--identity']),0)
        self.assertEqual(json.loads(out.getvalue())['scope'],'working-snapshot-quick-tool');exchange.assert_not_called();prepare.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,base=source_fixture(root);output=root/'stale.json'
            with patch.object(self.cli,'exchange') as exchange,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self.cli.main(['--repo',str(repo),'--base',base,'--expected-input','bad','--output',str(output)]),2)
            exchange.assert_not_called();result=json.loads(output.read_text())
            self.assertEqual(result['input_snapshot_sha256'],result['output_snapshot_sha256']);self.assertFalse(result['vm_started'])
    def test_output_refusals_and_public_privacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,base=source_fixture(root);target=root/'target';target.mkdir();link=root/'link';link.symlink_to(target)
            for output in (repo/'forbidden.json',link/'forbidden.json'):
                with patch.object(self.cli,'exchange') as exchange,contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(self.cli.main(['--repo',str(repo),'--base',base,'--expected-input','x','--output',str(output)]),2)
                exchange.assert_not_called();self.assertFalse(output.exists())
            tool=quick_prepare.tool_identity(ROOT);value=snapshot.capture(repo,base,tool['recipe_sha256']);identity=snapshot.identity(value)
            config=root/'config.json';config.write_text(json.dumps({'socket':'/unused'}));output=root/'failure.json'
            with patch.object(self.cli,'exchange',side_effect=RuntimeError('PRIVATE_SOURCE_MARKER')),contextlib.redirect_stdout(io.StringIO()) as public:
                self.assertEqual(self.cli.main(['--repo',str(repo),'--base',base,'--expected-input',identity['input_snapshot_sha256'],
                                               '--config',str(config),'--output',str(output)]),2)
            self.assertNotIn('PRIVATE_SOURCE_MARKER',public.getvalue());self.assertIn('PRIVATE_SOURCE_MARKER',output.read_text())
            self.assertLessEqual(output.stat().st_size,snapshot.RESULT_LIMIT)


if __name__=='__main__':unittest.main()
