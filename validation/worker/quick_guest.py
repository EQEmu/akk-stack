#!/usr/bin/python3
"""Fixed advisory checks. This workload runs only in the disposable guest."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

import build_guest as build
import quick_snapshot as snapshot


def verify_source(source,value):
    expected={entry['path']:entry for entry in value['files']};found=set()
    for parent,dirs,files in os.walk(source,followlinks=False):
        for name in list(dirs):
            path=Path(parent)/name;relative=path.relative_to(source).as_posix()
            if relative in value['gitlinks']:dirs.remove(name)
            elif path.is_symlink():raise ValueError('Quick source directory became a symlink')
        for name in files:
            path=Path(parent)/name;relative=path.relative_to(source).as_posix()
            if relative not in expected:raise ValueError('Check introduced a source file')
            data,mode=snapshot.read_file(source,relative,snapshot.FILE_LIMIT);entry=expected[relative]
            if len(data)!=entry['bytes'] or snapshot.sha(data)!=entry['sha256'] or mode!=entry['mode']:
                raise ValueError('Check changed a source file')
            found.add(relative)
    if found!=set(expected):raise ValueError('Check removed a source file')


def object_targets(entries,source,output,changed):
    """Read actual CMake outputs; ask Ninja to build their declared prerequisites."""
    if not isinstance(entries,list) or len(entries)>20000:raise ValueError('Compiler database budget/shape refused')
    selected=set();seen=set();source=Path(source).resolve();output=Path(output).resolve()
    for entry in entries:
        if not isinstance(entry,dict) or not isinstance(entry.get('file'),str):raise ValueError('Malformed compiler database entry')
        directory=Path(entry.get('directory',''))
        if not directory.is_absolute() or not directory.resolve().is_relative_to(output):raise ValueError('Compiler directory escaped build')
        file=Path(entry['file']);file=file if file.is_absolute() else directory/file
        file=file.resolve()
        if not file.is_relative_to(source) or file.relative_to(source).as_posix() not in changed:continue
        seen.add(file.relative_to(source).as_posix())
        target=entry.get('output')
        if target is None:
            args=entry.get('arguments')
            if args is None:
                if not isinstance(entry.get('command'),str) or len(entry['command'])>65536:raise ValueError('Compiler command missing/oversized')
                args=shlex.split(entry['command'])
            if not isinstance(args,list) or not all(isinstance(arg,str) for arg in args) or args.count('-o')!=1:
                raise ValueError('Generated compiler output is ambiguous')
            index=args.index('-o')
            if index+1>=len(args):raise ValueError('Generated compiler output missing')
            target=args[index+1]
        if not isinstance(target,str):raise ValueError('Generated compiler output malformed')
        path=Path(target);path=(path if path.is_absolute() else directory/path).resolve()
        if not path.is_relative_to(output):raise ValueError('Generated compiler output escaped build')
        relative=path.relative_to(output).as_posix()
        if not snapshot.safe_path(relative) or relative.startswith('-') or not relative.endswith(('.o','.obj')):
            raise ValueError('Unsupported generated object target')
        selected.add(relative)
    if seen!=set(changed):raise ValueError('Changed/new translation unit absent from generated compiler database')
    if not selected or len(selected)>8:raise ValueError('Affected object scope exceeds the eight-object budget')
    return sorted(selected)


def run_checks(source,registry,cargo,value,command=build.command):
    records=[];native=snapshot.native_scope(value);source_valid=True
    def record(name,action=None,skip=None,unavailable=None):
        nonlocal source_valid
        started=time.monotonic();status='completed';reason='command-completed';diagnostic=''
        if skip:status='skipped';reason=skip
        elif unavailable:status='unavailable';reason=unavailable
        elif not source_valid:status='skipped';reason='source-changed-by-prior-check'
        else:
            try:action()
            except Exception as error:
                status='failed' if isinstance(error,build.CandidateFailure) else 'unavailable'
                reason='candidate-failure' if status=='failed' else 'infrastructure-or-scope-unavailable'
                diagnostic=snapshot.diagnostic(error)
            try:verify_source(source,value)
            except Exception as error:
                source_valid=False;status='unavailable';reason='source-changed-by-check';diagnostic=snapshot.diagnostic(error)
        records.append(dict(name=name,status=status,reason=reason,seconds=round(time.monotonic()-started,3),diagnostic=diagnostic))
        return status
    workspace=source/'rust/actors'
    record('rust-format',lambda:command('rust-format',[cargo,'fmt','--all','--check'],cwd=workspace,candidate=True,seconds=120))
    metadata=record('rust-dependencies',lambda:command('rust-dependencies',[cargo,'metadata','--format-version=1','--locked','--offline'],
                                                        cwd=workspace,candidate=False,seconds=120))
    for name,args in (
            ('rust-clippy',['clippy','--workspace','--all-targets','--locked','--offline','--','-D','warnings']),
            ('rust-tests',['test','--workspace','--locked','--offline','--lib','--tests'])):
        record(name,lambda name=name,args=args:command(name,[cargo,*args],cwd=workspace,candidate=True,seconds=600),
               skip='failed-rust-dependencies' if metadata!='completed' else None)
    if native['limitations']:
        record('native-configure',skip='unsupported-native-scope')
        record('native-objects',unavailable='native-header-bridge-build-or-deletion-scope-unavailable')
    elif not native['changed_translation_units']:
        record('native-configure',skip='no-native-translation-unit-changes')
        record('native-objects',skip='no-native-translation-unit-changes')
    else:
        configured=record('native-configure',lambda:build.configure_native(source,registry,seconds=1800))
        def compile_objects():
            database=build.WORK/'build/compile_commands.json'
            if database.stat().st_size>8*1024**2:raise ValueError('Compiler database size budget exceeded')
            entries=json.loads(database.read_text())
            native['selected_objects']=object_targets(entries,source,build.WORK/'build',native['changed_translation_units'])
            command('native-objects',['cmake','--build',str(build.WORK/'build'),'--parallel','1','--target',*native['selected_objects']],
                    candidate=True,seconds=900)
        record('native-objects',compile_objects,skip='failed-native-configure' if configured!='completed' else None)
    result=dict(selected_checks=list(snapshot.CHECKS),checks=records,native_scope=native)
    for status,key in [('completed','completed_checks'),('failed','failed_checks'),('unavailable','unavailable_checks'),('skipped','skipped_checks')]:
        result[key]=[entry['name'] for entry in records if entry['status']==status]
    result['exit_code']=2 if result['unavailable_checks'] else 1 if result['failed_checks'] else 0
    return result


def unavailable(error,value=None):
    return dict(exit_code=2,selected_checks=list(snapshot.CHECKS),completed_checks=[],failed_checks=[],
                unavailable_checks=list(snapshot.CHECKS),skipped_checks=[],native_scope=snapshot.native_scope(value) if value is not None else dict(changed_translation_units=[],selected_objects=[],limitations=[],omitted_translation_units=0,omitted_limitations=0),
                checks=[dict(name=name,status='unavailable',reason='quick-preparation-failed',seconds=0,
                             diagnostic=snapshot.diagnostic(error) if index==0 else '') for index,name in enumerate(snapshot.CHECKS)])


def main():
    if os.geteuid()!=0 or not Path('/opt/eqemu-worker-quick-guest').is_file():raise RuntimeError('Disposable quick guest only')
    started=time.monotonic();build.DEADLINE=started+3300
    nonce=Path('/opt/eqemu-worker-nonce').read_text().strip()
    request=json.loads(Path('/opt/eqemu-quick-request.json').read_text())
    result=dict(version=1,nonce=nonce,scope='working-snapshot-quickcheck')
    value=None
    try:
        build.WORK.mkdir();build.MEDIA.mkdir();Path('/media/eqemu-input').mkdir(parents=True)
        build.command('mount-job',['mount','-o','ro,nosuid,nodev','/dev/sr1','/media/eqemu-input'])
        manifest=Path('/media/eqemu-input/snapshot.json')
        if manifest.stat().st_size>snapshot.MANIFEST_LIMIT:raise ValueError('Oversized quick manifest')
        value=snapshot.validate_snapshot(json.loads(manifest.read_text()))
        if snapshot.identity(value)['input_snapshot_sha256']!=request['input_snapshot_sha256']:raise ValueError('Quick manifest binding mismatch')
        identity=build.provision()
        if identity!={key:request[key] for key in ('base','head','input_snapshot_sha256','recipe_sha256','files')}:
            raise ValueError('Quick input identity mismatch')
        if not snapshot.approved_rust(identity['files']['rust-inputs.tar']) or identity['files']['native.iso']['sha256']!='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4':
            raise ValueError('Unapproved quick tool bundle')
        source,registry=build.prepare_source();verify_source(source,value)
        cargo=build.prepare_rust();result['preparation_seconds']=round(time.monotonic()-started,3)
        result.update(run_checks(source,registry,cargo,value))
        verify_source(source,value)
    except Exception as error:
        result.update(unavailable(error,value))
    result['guest_seconds']=round(time.monotonic()-started,3)
    print('\nEQEMU_QUICK_RESULT '+base64.b64encode(snapshot.canonical(result)).decode(),flush=True)


if __name__=='__main__':main()
