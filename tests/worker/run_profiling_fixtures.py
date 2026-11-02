#!/usr/bin/python3
"""Explicit trusted host qualification. Compiles only the adjacent finite C fixture.

No worker/socket/VM, EQEmu source, Cargo, installed profiler, or policy mutation.
Extracted, version-pinned Heaptrack debs may be supplied with --heaptrack-root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import profiling
from profile_artifacts import inventory


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--heaptrack-root',type=Path)
    args=parser.parse_args()
    args.output.mkdir(mode=0o700)
    source=Path(__file__).with_name('profiling_fixture.c')
    binary=args.output/'fixture'
    flags=['-O2','-g','-fno-omit-frame-pointer','-fno-builtin-malloc']
    subprocess.run(['/usr/bin/gcc',*flags,str(source),'-o',str(binary)],check=True)
    metadata=dict(scope='trusted-host-fixture-only',source=profiling.file_identity(source),
        compiler=profiling.file_identity('/usr/bin/gcc'),flags=flags,
        workload=dict(live_bytes=16*1024**2,churn_calls=20000,churn_bytes_each=4096,busy_stack_seconds=.7,
                      repetitions=1,warmup=0,comparison=False))
    results={}
    for mode in ('timeline','heaptrack'):
        if mode=='heaptrack':
            if args.heaptrack_root is None:
                results[mode]=dict(available=False,reason='No extracted pinned Heaptrack root supplied'); continue
            tools=args.heaptrack_root
            printer=args.output/'heaptrack-print-private'
            printer.write_text('#!/bin/sh\nexec env LD_LIBRARY_PATH="'+str(tools/'usr/lib/x86_64-linux-gnu')+'" "'+str(tools/'usr/bin/heaptrack_print')+'" "$@"\n')
            printer.chmod(0o700)
            profiling.TOOLS['heaptrack']=(str(tools/'usr/lib/heaptrack/libheaptrack_preload.so'),
                str(tools/'usr/lib/heaptrack/libexec/heaptrack_interpret'),str(printer))
            metadata['extracted_tool_files']={str(path.relative_to(tools)):profiling.file_identity(path)
                for path in tools.rglob('*') if path.is_file() and not path.is_symlink() and '/share/' not in str(path)}
        for abrupt in (False,True):
            name=mode+('-kill' if abrupt else '-clean')
            with (args.output/(name+'-transport.jsonl')).open('xb') as output:
                session=profiling.Session(mode,args.output/name,{'zone':binary},os.getuid(),time.monotonic()+10,metadata)
                original=subprocess.Popen
                def launch(command,**kwargs):
                    if command[2]=='export': kwargs['stdout']=output
                    return original(command,**kwargs)
                with patch.object(profiling.subprocess,'Popen',side_effect=launch): session.start()
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
                if mode=='heaptrack':
                    env.update(LD_PRELOAD=profiling.TOOLS['heaptrack'][0],DUMP_HEAPTRACK_OUTPUT=str(session.directory/'zone.fifo'))
                start=time.monotonic()
                proc=subprocess.Popen([str(binary),'private-argv-marker'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    if abrupt:
                        time.sleep(1.35); proc.kill()
                    code=proc.wait(timeout=6)
                    before=(session.directory/'timeline.jsonl').stat().st_size
                    time.sleep(.4)
                    survived=(session.directory/'timeline.jsonl').stat().st_size>before
                    result=session.finish()
                    result.update(native_returncode=code,elapsed_seconds=round(time.monotonic()-start,3),
                        sampler_continued_after_child_exit=survived,traces_may_be_incomplete=abrupt,
                        artifacts=inventory_filtered(session.directory))
                    if mode=='heaptrack':
                        raw=(session.directory/'zone.heaptrack.raw').read_bytes()
                        if b'private-argv-marker' in raw or any(row.startswith(b'X') for row in raw.splitlines()):
                            raise RuntimeError('Raw argv filter failed')
                        analysis=(session.directory/'zone.heaptrack.analysis').read_text()
                        result['live_stack_found']='live_allocation' in analysis
                        result['churn_stack_found']='churn_allocations' in analysis
                    results[name]=result
                finally:
                    if proc.poll() is None: proc.kill(); proc.wait(timeout=3)
                    for child in (session.sampler,session.exporter):
                        if child.poll() is None: child.kill(); child.wait(timeout=3)
    perf=args.output/'perf-preflight.data'
    code=profiling.tool(['/usr/bin/perf','record','-e','task-clock:u','-F','99','--call-graph','fp,32',
        '--no-buildid-cache','-o',str(perf),'--',str(binary)],output=args.output/'perf-preflight.log')
    results['perf']=dict(requested_event='task-clock:u',returncode=code,available=code==0,
        paranoid=Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip(),
        tool=profiling.file_identity('/usr/bin/perf'),policy_changed=False)
    if code==0:
        analysis=args.output/'perf-stack.analysis'
        report=profiling.tool(['/usr/bin/perf','report','--stdio','-i',str(perf)],output=analysis)
        results['perf'].update(analysis_exit_code=report,busy_stack_found='busy_stack' in analysis.read_text())
    (args.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),results={key:dict(complete=value.get('complete'),available=value.get('available'),
        native_returncode=value.get('native_returncode'),samples=value.get('sampler',{}).get('samples')) for key,value in results.items()})))


def inventory_filtered(directory):
    # Internal config, FIFO and stop markers stay local and are never exported.
    from profile_artifacts import NAMES
    return {path.name:profiling.file_identity(path) for path in directory.iterdir() if path.name in NAMES}


if __name__=='__main__': main()
