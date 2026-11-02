"""Linux process sampler and opt-in Heaptrack/perf collection, independent of observers.

The sampler writes bounded local files. A separate exporter tails them to the
worker console, so workload probes and console backpressure cannot stall sampling.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True

from profile_artifacts import CHUNK, FILE_LIMIT, NAMES, TOTAL_LIMIT, canonical, frame

MODES = ('timeline', 'heaptrack', 'perf')
INTERVAL = .2
FINAL_DRAIN_SECONDS = 1.0
TOOLS = {'heaptrack': ('/usr/lib/heaptrack/libheaptrack_preload.so',
                      '/usr/lib/heaptrack/libexec/heaptrack_interpret', '/usr/bin/heaptrack_print'),
         'perf': ('/usr/bin/perf',)}


def file_identity(path):
    path = Path(path)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(bytes=path.stat().st_size, sha256=digest)


def write_json(path, value):
    raw = canonical(value) + b'\n'
    if len(raw) > 65536:
        raise ValueError('Profile JSON budget')
    with Path(path).open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(raw); stream.flush()


def proc_sample(pid, expected_start=None, proc=Path('/proc')):
    """Read identity on both sides of status to refuse PID reuse or torn samples."""
    root = proc / str(pid)
    def stat():
        return (root / 'stat').read_text().rsplit(')', 1)[1].split()
    before = stat()
    start = int(before[19])
    if expected_start is not None and start != expected_start:
        raise ValueError('process-identity-changed')
    status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    after = stat()
    if int(after[19]) != start:
        raise ValueError('process-identity-changed')
    def kib(name):
        text = status.get(name)
        return int(text.split()[0]) * 1024 if text else None
    return dict(pid=pid, start_ticks=start, state=after[0],
                cpu_user_ticks=int(after[11]), cpu_system_ticks=int(after[12]),
                rss_bytes=kib('VmRSS'), kernel_hwm_bytes=kib('VmHWM'),
                virtual_bytes=kib('VmSize'), uid=int(status['Uid'].split()[0]))


def pressure(proc=Path('/proc'), cgroup=Path('/sys/fs/cgroup')):
    """Guest-wide memory/PSI and sampler-cgroup counters, never per-process totals."""
    value = dict(scope='guest-wide; cgroup counters cover sampler cgroup including siblings')
    try:
        info = dict(line.split(':', 1) for line in (proc / 'meminfo').read_text().splitlines())
        value['guest_memory'] = {name: int(info[name].split()[0])*1024 for name in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree')}
        value['guest_memory_psi'] = (proc / 'pressure/memory').read_text()[:512]
        relative = next(row[3:] for row in (proc / 'self/cgroup').read_text().splitlines() if row.startswith('0::'))
        if '..' in Path(relative).parts:
            raise ValueError('Invalid cgroup')
        root = cgroup / relative.lstrip('/')
        value['cgroup_path'] = relative
        for name in ('memory.current', 'memory.peak', 'memory.max', 'memory.events', 'memory.pressure', 'cpu.stat'):
            try: value[name] = (root / name).read_text()[:512].strip()
            except OSError: value[name] = None
    except (OSError, ValueError, KeyError, StopIteration):
        value['unavailable'] = True
    return value


class Writer:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.total = 0
        self.sizes = {}
        self.truncated = set()

    def append(self, name, data):
        size = self.sizes.get(name, 0)
        if size + len(data) > FILE_LIMIT or self.total + len(data) > TOTAL_LIMIT - 65536:
            self.truncated.add(name)
            return False
        with (self.directory / name).open('ab') as stream:
            os.chmod(self.directory / name, 0o600)
            stream.write(data); stream.flush()
        self.sizes[name] = size + len(data); self.total += len(data)
        return True


def sampler(config):
    """Only fixed executable inodes/UIDs are admitted. Every identity stays separate."""
    directory = Path(config['directory'])
    writer = Writer(directory)
    known = {}; peaks = {}; last = None; gaps = 0; maximum_gap = 0.; count = 0
    stop = False
    def cancel(*_):
        nonlocal stop
        stop = True
    for sig in (signal.SIGTERM, signal.SIGINT): signal.signal(sig, cancel)
    expected = {}
    for name, path in config['binaries'].items():
        info = Path(path).stat()
        expected[(info.st_dev, info.st_ino)] = name
    selector = selectors.DefaultSelector()
    pending = {}
    fifo_fds = []
    if config['mode'] == 'heaptrack':
        for name in config['binaries']:
            fd = os.open(directory / (name + '.fifo'), os.O_RDWR | os.O_NONBLOCK)
            fifo_fds.append(fd); selector.register(fd, selectors.EVENT_READ, name); pending[name] = b''
    def drain(timeout):
        events=selector.select(timeout)
        for key,_ in events:
            try: block=os.read(key.fd,65536)
            except BlockingIOError: continue
            name=key.data;data=pending[name]+block
            rows=data.split(b'\n');pending[name]=rows.pop()
            if len(pending[name])>16384:
                writer.truncated.add(name+'.heaptrack.raw');pending[name]=b''
            for row in rows:
                if row[:1] in (b'v',b'x',b'I',b'c',b'R',b't',b'+',b'-',b'm'):
                    if len(row)>16384: writer.truncated.add(name+'.heaptrack.raw')
                    else: writer.append(name+'.heaptrack.raw',row+b'\n')
        return bool(events)
    (directory/'sampler.ready').touch()
    try:
        while not stop and time.monotonic() < config['deadline']:
            now = time.monotonic()
            gap = 0 if last is None else now-last
            last = now; maximum_gap = max(maximum_gap, gap)
            if gap > INTERVAL*1.5: gaps += 1
            samples = []; seen = set()
            for path in Path('/proc').glob('[0-9]*/exe'):
                try:
                    info = path.stat(); name = expected.get((info.st_dev, info.st_ino))
                    if name is None: continue
                    sample = proc_sample(int(path.parent.name))
                    if sample['uid'] != config['uid']: continue
                    key = str(sample['pid']) + ':' + str(sample['start_ticks'])
                    if key not in known and len(known) >= 16:
                        writer.truncated.add('process-identities'); continue
                    known[key] = name; seen.add(key)
                    sample['name'] = name; samples.append(sample)
                    peak = peaks.setdefault(key, dict(name=name, pid=sample['pid'], start_ticks=sample['start_ticks'], sampled_rss_max_bytes=0, observed_kernel_hwm_bytes=0))
                    peak['sampled_rss_max_bytes'] = max(peak['sampled_rss_max_bytes'], sample['rss_bytes'] or 0)
                    peak['observed_kernel_hwm_bytes'] = max(peak['observed_kernel_hwm_bytes'], sample['kernel_hwm_bytes'] or 0)
                except (OSError, ValueError, KeyError):
                    continue
            unavailable = []
            for key in known.keys() - seen:
                pid, start = map(int, key.split(':'))
                try:
                    sample = proc_sample(pid, start)
                    unavailable.append(dict(pid=pid, start_ticks=start, state=sample['state'], reason='executable-unavailable-or-changed'))
                except (OSError, ValueError, KeyError) as error:
                    unavailable.append(dict(pid=pid, start_ticks=start, reason='identity-changed' if isinstance(error, ValueError) else 'exited-or-inaccessible'))
            writer.append('timeline.jsonl', canonical(dict(monotonic_ns=time.monotonic_ns(), gap_seconds=round(gap,6), processes=samples, unavailable=unavailable, pressure=pressure()))+b'\n')
            count += 1
            end = now + INTERVAL
            # Drain allocation records independently of the observer. Strip Heaptrack's
            # X argv and S suppression records before any disk/console persistence.
            while time.monotonic() < end and not stop:
                drain(max(0,end-time.monotonic()))
                if not fifo_fds: time.sleep(max(0, end-time.monotonic()))
        # Termination can arrive during process sampling, before its normal FIFO
        # sweep. Drain already-flushed records even after stop has been requested.
        deadline=time.monotonic()+FINAL_DRAIN_SECONDS
        while fifo_fds and time.monotonic()<deadline:
            if not drain(0): break
        remainder=bool(fifo_fds and selector.select(0))
        partial_records=sorted(name for name,data in pending.items() if data)
        allocation_complete=not remainder and not partial_records
        if not allocation_complete: writer.truncated.add('allocation-finalization')
        summary = dict(version=1, mode=config['mode'], sampler_complete=stop and allocation_complete, stop_reason='requested' if stop else 'deadline',
            allocation_drain=dict(complete=allocation_complete,budget_seconds=FINAL_DRAIN_SECONDS,queued_remainder=remainder,partial_records=partial_records,
                scope='queued records at shutdown; future writes and complete native trace are not established'),
            samples=count, interval_seconds=INTERVAL, gap_count=gaps, maximum_gap_seconds=round(maximum_gap,6),
            processes=list(peaks.values()), truncated=sorted(writer.truncated),
            true_peak_known=False, overhead='sampler and selected profiler included; no overhead correction',
            coverage='fixed executable inodes and UID; short processes between samples may be missed')
        write_json(directory/'summary.json', summary)
    finally:
        selector.close()
        for fd in fifo_fds: os.close(fd)


def exporter(config):
    """Blocking transport lives in its own process, never in the sampling loop."""
    directory = Path(config['directory']); offsets = {}; total = 0
    while time.monotonic() < config['deadline'] + 5:
        # Finalization can appear during a sweep. Only a sweep begun after it
        # observes every immutable final artifact, including rewritten perf headers.
        finalized=(directory/'export.done').exists()
        for name in sorted(NAMES):
            path = directory/name
            # perf rewrites its header at finalization; export only the finalized bytes.
            if name.endswith('.perf.data') and not finalized: continue
            if not path.is_file() or path.is_symlink(): continue
            with path.open('rb') as stream:
                offset = offsets.get(name,0); stream.seek(offset)
                while total < TOTAL_LIMIT and (data := stream.read(min(CHUNK, FILE_LIMIT-offset, TOTAL_LIMIT-total))):
                    sys.stdout.buffer.write(frame(name,offset,data)); sys.stdout.buffer.flush()
                    offset += len(data); total += len(data); offsets[name] = offset
        if finalized: return
        time.sleep(.2)


def tool(args, *, output, stdin=None, seconds=30, prefix=(), diagnostics=None):
    """Finite tool process with bounded disk output and owned group cleanup."""
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (512*1024, 512*1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    from contextlib import ExitStack
    with ExitStack() as stack:
        stream=stack.enter_context(Path(output).open('xb'))
        diagnostic_stream=stack.enter_context(Path(diagnostics).open('xb')) if diagnostics else subprocess.STDOUT
        os.chmod(output,0o600)
        if diagnostics: os.chmod(diagnostics,0o600)
        proc = subprocess.Popen([*prefix,*map(str,args)], stdin=stdin or subprocess.DEVNULL,
            stdout=stream, stderr=diagnostic_stream, start_new_session=True, preexec_fn=limits,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/nonexistent','DEBUGINFOD_URLS':''})
        try: return proc.wait(timeout=seconds)
        finally:
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5)


def perf_limits():
    """Lower only: an unprivileged child cannot raise its observer's hard ceiling."""
    _,hard=resource.getrlimit(resource.RLIMIT_FSIZE)
    limit=FILE_LIMIT if hard==resource.RLIM_INFINITY else min(FILE_LIMIT,hard)
    resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))


def perf_preflight(directory,uid,prefix):
    """Run under the native identity with a finite directory that identity can write."""
    directory=Path(directory);directory.mkdir(mode=0o700)
    os.chown(directory,uid,-1)
    return tool(['/usr/bin/perf','record','-e','task-clock:u','-F','99','--call-graph','fp,32',
        '--no-buildid-cache','-o',str(directory/'perf.data'),'--','/bin/true'],
        prefix=prefix,output=directory.parent/'perf-preflight.log')


class Session:
    """Root guest owner; sampling/export children live outside the native session."""
    def __init__(self, mode, directory, binaries, uid, deadline, metadata):
        if mode not in MODES: raise ValueError('Unknown profiling mode')
        self.directory = Path(directory); self.directory.mkdir(mode=0o755)
        self.mode = mode; self.uid = uid; self.sampler = None; self.exporter = None; self.preflight = None
        self.config = dict(mode=mode, directory=str(directory), binaries={k:str(v) for k,v in binaries.items()}, uid=uid, deadline=deadline)
        self.tools = {path:file_identity(path) for path in TOOLS.get(mode,())}
        self.metadata = dict(metadata, mode=mode, tools=self.tools,
            kernel=os.uname().release, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), machine=os.uname().machine, clock_ticks_per_second=os.sysconf('SC_CLK_TCK'),
            binaries={name:file_identity(path) for name,path in binaries.items()})
        for name in binaries:
            if mode == 'heaptrack':
                os.mkfifo(self.directory/(name+'.fifo'),0o600); os.chown(self.directory/(name+'.fifo'),uid,-1)
        if mode == 'perf':
            for name in binaries:
                path=self.directory/(name+'.perf.data')
                path.touch(mode=0o600); os.chown(path,uid,-1)
        write_json(self.directory/'metadata.json',self.metadata)
        write_json(self.directory/'config.json',self.config)
        os.chmod(self.directory/'config.json',0o644)

    def start(self):
        script = str(Path(__file__).resolve())
        self.sampler = subprocess.Popen([sys.executable,script,'sample',str(self.directory/'config.json')], start_new_session=True)
        self.exporter = subprocess.Popen([sys.executable,script,'export',str(self.directory/'config.json')], start_new_session=True)
        self.stage('normal-world','started')
        end = time.monotonic()+3
        while not (self.directory/'sampler.ready').exists():
            if self.sampler.poll() is not None or time.monotonic()>=end:
                for child in (self.sampler,self.exporter):
                    if child.poll() is None: child.kill()
                    child.wait(timeout=3)
                raise RuntimeError('Independent sampler did not become ready')
            time.sleep(.02)
        return self

    def stage(self,name,state):
        if (not isinstance(name,str) or not name or len(name)>64 or not all(c.isalnum() or c in '-_.' for c in name)
                or state not in ('started','completed','failed')):
            raise ValueError('Untrusted profiling stage')
        path = self.directory/'stages.jsonl'
        if path.exists() and path.stat().st_size > 65536: raise ValueError('Stage budget')
        with path.open('ab') as stream:
            stream.write(canonical(dict(name=name,state=state,monotonic_ns=time.monotonic_ns()))+b'\n'); stream.flush()

    def finish(self, collector_exit_codes=None, collector_finalization_error=None):
        error = ('Requested perf collector failed or did not finalize'
                 if self.mode == 'perf' and (collector_finalization_error is not None or not isinstance(collector_exit_codes,list)
                     or len(collector_exit_codes)!=2 or any(type(code) is not int or code!=0 for code in collector_exit_codes)) else None)
        analysis = {}
        try:
            if self.sampler is not None:
                self.sampler.terminate()
                try: self.sampler.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.sampler.kill(); self.sampler.wait(timeout=3)
                    error = 'Sampler finalization timeout'
            if self.sampler is None or self.sampler.returncode:
                error = error or 'Sampler failed'
            if not (self.directory/'summary.json').is_file(): error = error or 'Sampler summary missing'
            if self.mode in ('heaptrack','perf'):
                for name in self.config['binaries']:
                    suffix = '.heaptrack.raw' if self.mode=='heaptrack' else '.perf.data'
                    raw = self.directory/(name+suffix)
                    if not raw.is_file() or raw.stat().st_size == 0:
                        error = error or 'Requested '+self.mode+' trace missing'; continue
                    if self.mode=='heaptrack':
                        interpreted=self.directory/(name+'.heaptrack.txt')
                        with raw.open('rb') as source:
                            code=tool([TOOLS['heaptrack'][1]],stdin=source,output=interpreted,diagnostics=self.directory/(name+'.heaptrack.interpret-log'))
                        analysis[name+'-interpret']=code
                        if code: error=error or 'Heaptrack interpretation failed'
                        args=[TOOLS['heaptrack'][2],str(interpreted)]
                    else:
                        args=[TOOLS['perf'][0],'report','--header','--stdio','--no-children','--percent-limit','1','-i',str(raw)]
                    code=tool(args,output=self.directory/(name+'.'+self.mode+'.analysis'))
                    analysis[name+'-analysis']=code
                    if code: error=error or 'Requested profiler analysis failed'
        except Exception as exc:
            error=error or 'Profiler finalization '+type(exc).__name__
        finally:
            self.stage('normal-world','completed' if error is None else 'failed')
            (self.directory/'export.done').touch()
            if self.exporter is not None:
                try: self.exporter.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.exporter.kill(); self.exporter.wait(timeout=3)
                    error=error or 'Profile transport incomplete'
                if self.exporter.returncode: error=error or 'Profile exporter failed'
        summary=json.loads((self.directory/'summary.json').read_text()) if (self.directory/'summary.json').is_file() else {}
        if error is None:
            if not summary.get('processes'): error='No target process sampled'
            elif summary.get('sampler_complete') is not True: error='Independent sampling or allocation finalization incomplete'
            elif summary.get('truncated'): error='Profile artifacts truncated'
        return dict(mode=self.mode,complete=error is None and summary.get('sampler_complete') is True and bool(summary.get('processes')) and not summary.get('truncated'),error=error,
                    sampler=summary,tools=self.tools,collector_exit_codes=collector_exit_codes,collector_finalization_error=collector_finalization_error,analysis_exit_codes=analysis,preflight=self.preflight,
                    lost_samples='not established for perf; inspect bounded report header and tool diagnostics',
                    trace_finalization='may be incomplete after native signal/cleanup; analysis success does not prove a complete trace')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('sample','export'))
    parser.add_argument('config',type=Path)
    args=parser.parse_args()
    config=json.loads(args.config.read_text())
    (sampler if args.operation=='sample' else exporter)(config)
