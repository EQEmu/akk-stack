#!/usr/bin/env python3
"""Bounded staging observer. No runtime mutation or automatic recovery."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

CONTAINERS = ('eqemu-staging-eqemu-server-1', 'eqemu-staging-mariadb-1')
BUDGET = 16 * 1024 * 1024
CAP = 1024 * 1024
INTERVAL = 300
SHA = re.compile(r'[0-9a-f]{64}')
BAD = re.compile(rb'\b(?:nan|[-+]?inf(?:inity)?|panic|segfault|oom|assertion failed|query fail(?:ed|ure)|failed query|addresssanitizer|runtime error)\b', re.I)


class Nonpass(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Nonpass(reason)


def encode(data):
    return (json.dumps(data, sort_keys=True, allow_nan=False) + '\n').encode()


def read(path, cap=CAP):
    with open(path, 'rb') as stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap, 'input_limit')
    return data


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for _ in range(512):
            chunk = stream.read(CAP)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)
        require(not stream.read(1), 'executable_size_limit')
    return h.hexdigest()


def command(argv, timeout=20, cap=CAP):
    """Drain a bounded pipe; kill only this observer-owned subprocess on failure."""
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    deadline = time.monotonic() + timeout
    data = bytearray()
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(p.stdout, selectors.EVENT_READ)
            while sel.get_map():
                require(time.monotonic() < deadline, 'command_timeout')
                for key, _ in sel.select(min(.2, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                    data.extend(chunk)
                    require(len(data) <= cap, 'command_output_limit')
            require(p.wait(timeout=max(.001, deadline-time.monotonic())) == 0, 'command_exit')
        return bytes(data)
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
        p.wait(timeout=2)
        p.stdout.close()


def number(value, positive=True):
    require(type(value) in (int, float) and math.isfinite(value), 'nonfinite_or_invalid_number')
    require(value > 0 if positive else value >= 0, 'invalid_limit')
    return value


def config(path):
    c = json.loads(read(path, 32768))
    require(re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', c['release']) is not None, 'release_required')
    require(re.fullmatch(r'[0-9a-f]{40}', c['source']) is not None, 'source_required')
    require(c['backend'] in ('ON', 'OFF'), 'backend_required')
    for key in ('world_sha256', 'zone_sha256', 'health_sha256'):
        require(SHA.fullmatch(c[key]) is not None, 'sha_required')
    require(Path(c['health_script']).is_absolute() and Path(c['health_script']).name == 'staging-health.py', 'health_path')
    require(0 < number(c['duration_hours']) <= 48, 'duration_limit')
    require(len(c['baseline_reference']) in range(1, 257), 'baseline_reference_required')
    require(len(c['logs']) in range(1, 33), 'log_count')
    require(len(set(c['logs'])) == len(c['logs']), 'duplicate_logs')
    for p in c['logs']:
        require(Path(p).is_absolute(), 'absolute_log_required')
    require(len(c['disk_paths']) in range(1, 9), 'disk_count')
    for p in c['disk_paths']:
        require(Path(p).is_absolute(), 'absolute_disk_required')
    limits = c['limits']
    for key in ('disk_free_bytes', 'log_growth_bytes', 'process_rss_bytes', 'host_available_bytes'):
        number(limits[key])
    require(set(limits['containers']) == set(CONTAINERS), 'fixed_containers_required')
    for v in limits['containers'].values():
        for key in ('memory_bytes', 'cpu_cores'):
            number(v[key])
    require(type(c['expected_zones']) is int and 1 <= c['expected_zones'] <= 16, 'zone_count')
    encode(c)  # Reject nonfinite JSON anywhere, including unknown fields.
    return c


class Artifacts:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700)  # Existing runs cannot be resumed or overwritten.
        self.used = 0

    def write(self, name, data, append=False):
        payload = encode(data)
        reserve = 65536 if name != 'summary.json' else 0
        require(self.used + len(payload) <= BUDGET-reserve, 'artifact_budget')
        with (self.root/name).open('ab' if append else 'xb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        self.used += len(payload)
        if not append:
            (self.root/name).chmod(0o400)


def counters(path):
    rows = read(path, 16384).decode().splitlines()
    return {key: int(value) for key, value in (row.split() for row in rows)}


def process(pid, hashes):
    root = Path('/proc')/str(pid)
    fields = read(root/'stat', 8192).decode().rsplit(')', 1)[1].split()
    exe = root/'exe'
    target = os.readlink(exe)
    info = exe.stat()
    identity = [pid, int(fields[19]), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
    if tuple(identity) not in hashes:
        hashes[tuple(identity)] = digest(exe)
    return {'identity': identity, 'sha256': hashes[tuple(identity)],
            'kind': Path(target).name, 'cpu_ticks': int(fields[11])+int(fields[12]),
            'rss_bytes': int(fields[21])*os.sysconf('SC_PAGE_SIZE')}


def log_sample(path, previous):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), 'rb') as stream:
        s = os.fstat(stream.fileno())
        require(stat.S_ISREG(s.st_mode), 'log_not_regular')
        identity = [s.st_dev, s.st_ino]
        offset = s.st_size if previous is None else previous['offset']
        if previous:
            require(identity == previous['identity'] and s.st_size >= offset, 'log_rotated_or_truncated')
        require(s.st_size-offset <= CAP, 'log_scan_backlog')
        stream.seek(offset)
        new = stream.read(s.st_size-offset)
        require(len(new) == s.st_size-offset, 'log_short_read')
    # Carry the last 256 bytes privately so split error tokens cannot disappear.
    combined = (previous.get('_tail', b'') if previous else b'') + new
    require(BAD.search(combined) is None, 'native_log_fault_or_nonfinite')
    return {'identity': identity, 'offset': s.st_size, 'new_bytes': len(new),
            '_tail': combined[-256:]}


class Observer:
    def __init__(self, c):
        self.c = c
        self.hashes = {}
        self.logs = {}
        self.baseline = None
        self.previous = None

    def sample(self, result):
        c = self.c
        result.update(monotonic=time.monotonic(), containers={}, processes=[], logs=[])
        for name in CONTAINERS:
            # Whitelist fields at Docker, never receive Config.Env or command lines.
            template = ('{{json .Id}} {{json .Image}} '
                        '{"Running":{{.State.Running}},"OOMKilled":{{.State.OOMKilled}},'
                        '"Restarting":{{.State.Restarting}},"Pid":{{.State.Pid}},'
                        '"StartedAt":{{json .State.StartedAt}},"HealthStatus":'
                        '{{if .State.Health}}{{json .State.Health.Status}}{{else}}"absent"{{end}}'
                        '} {{.RestartCount}} {{json .LogPath}}')
            raw = command(['docker', 'inspect', '--format', template, name]).decode()
            decoder = json.JSONDecoder()
            values = []
            for _ in range(5):
                value, end = decoder.raw_decode(raw.lstrip())
                values.append(value)
                raw = raw.lstrip()[end:]
            cid, image, state, restarts, log = values
            require(state['Running'] and not state['OOMKilled'] and not state.get('Restarting'), 'container_not_healthy')
            require(state['HealthStatus'] in ('healthy', 'absent'), 'docker_health')
            require(restarts == 0, 'container_restart_history')
            pid = state['Pid']
            cgline = read(f'/proc/{pid}/cgroup', 8192).decode().strip()
            require(cgline.startswith('0::/') and '\n' not in cgline, 'cgroup_v2_required')
            cg = Path('/sys/fs/cgroup')/cgline[4:]
            require(cg.resolve().is_relative_to('/sys/fs/cgroup'), 'cgroup_path')
            events = counters(cg/'memory.events')
            require(not any(events.get(k, 0) for k in ('oom', 'oom_kill', 'oom_group_kill')), 'cgroup_oom')
            v = {'id': cid, 'image': image, 'pid': pid, 'started': state['StartedAt'],
                 'init_process': process(pid, self.hashes),
                 'restarts': restarts, 'memory_bytes': int(read(cg/'memory.current', 64)),
                 'memory_events': events, 'cpu': counters(cg/'cpu.stat'),
                 'memory_max': read(cg/'memory.max', 64).decode().strip(),
                 'cpu_max': read(cg/'cpu.max', 64).decode().strip()}
            result['containers'][name] = v
            require(v['init_process']['rss_bytes'] <= c['limits']['process_rss_bytes'], 'process_memory_limit')
            require(v['memory_bytes'] <= c['limits']['containers'][name]['memory_bytes'], 'container_memory_limit')
            if name == CONTAINERS[0]:
                rows = command(['docker', 'top', name, '-eo', 'pid,comm']).decode().splitlines()[1:]
                require(len(rows) <= 128, 'process_count_limit')
                for row in rows:
                    p, comm = row.split()
                    if comm in ('world', 'zone'):
                        proc = process(int(p), self.hashes)
                        result['processes'].append(proc)
                        require(proc['sha256'] == c[comm+'_sha256'], 'executable_hash_mismatch')
                        require(proc['rss_bytes'] <= c['limits']['process_rss_bytes'], 'process_memory_limit')
        kinds = [p['kind'] for p in result['processes']]
        require(kinds.count('world') == 1 and kinds.count('zone') == c['expected_zones'], 'world_zone_count')
        for i, path in enumerate(c['logs']):
            self.logs[path] = log_sample(path, self.logs.get(path))
            result['logs'].append({k: v for k, v in self.logs[path].items() if k != '_tail'})
        result['disk_free_bytes'] = [os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in c['disk_paths']]
        require(min(result['disk_free_bytes']) >= c['limits']['disk_free_bytes'], 'disk_free_limit')
        mem = dict(line.split(':', 1) for line in read('/proc/meminfo', 16384).decode().splitlines())
        result['host_available_bytes'] = int(mem['MemAvailable'].split()[0])*1024
        require(result['host_available_bytes'] >= c['limits']['host_available_bytes'], 'host_memory_limit')
        require(digest(c['health_script']) == c['health_sha256'], 'health_script_changed')
        health = command([sys.executable, '-I', c['health_script']], timeout=20)
        result['health'] = {'exit': 0, 'output_bytes': len(health)}  # Never retain health output.
        self.check(result)
        self.previous = result
        if self.baseline is None:
            self.baseline = result

    def check(self, result):
        if self.baseline is None:
            return
        b, previous = self.baseline, self.previous
        require([p['identity'] for p in result['processes']] == [p['identity'] for p in b['processes']], 'process_identity_changed')
        for name, v in result['containers'].items():
            for key in ('id', 'image', 'pid', 'started', 'restarts', 'memory_max', 'cpu_max'):
                require(v[key] == b['containers'][name][key], 'container_identity_changed')
            require(v['init_process']['identity'] == b['containers'][name]['init_process']['identity'], 'init_identity_changed')
            require(v['memory_events'] == b['containers'][name]['memory_events'], 'memory_pressure_event')
            elapsed = result['monotonic']-previous['monotonic']
            delta = v['cpu']['usage_usec']-previous['containers'][name]['cpu']['usage_usec']
            require(elapsed > 0 and delta >= 0, 'invalid_cpu_delta')
            require(delta / 1e6 / elapsed <= self.c['limits']['containers'][name]['cpu_cores'], 'container_cpu_limit')
        growth = sum(v['offset']-old['offset'] for v, old in zip(result['logs'], b['logs']))
        require(growth <= self.c['limits']['log_growth_bytes'], 'log_growth_limit')


def interrupted(signum, frame):
    raise Nonpass('observer_signal_'+str(signum))


def run(c, out, observer=None, clock=time.monotonic, sleep=time.sleep):
    start = clock()
    deadline = start + c['duration_hours']*3600
    observer = observer or Observer(c)
    out.write('manifest.json', c)
    count, result = 0, {}
    status, reason = 'NONPASS', 'observer_failure'
    try:
        # At most 577 samples, including both endpoints of a 48h observation.
        for index in range(577):
            result = {'index': index, 'complete': False}
            target = min(start+index*INTERVAL, deadline)
            sleep(max(0, target-clock()))
            require(clock() <= deadline+90, 'deadline_overrun')
            result = {'index': index, 'wall_time': time.time(), 'complete': False}
            remaining = start + 48*3600 - clock()
            require(remaining > 0, 'hard_48h_deadline')
            signal.setitimer(signal.ITIMER_REAL, min(90, remaining))
            observer.sample(result)
            signal.alarm(0)
            result['complete'] = True
            if index == 0:
                out.write('baseline.json', result)
            out.write('samples.jsonl', result, append=True)
            count += 1
            if target == deadline:
                status, reason = 'PASS', 'observation_deadline_complete'
                break
    except Exception as exc:
        # Fixed reason codes only. Exception messages can contain credentials/logs.
        reason = str(exc) if isinstance(exc, Nonpass) else 'observer_'+type(exc).__name__
        result['complete'] = False
        try:
            out.write('partial.json', result)
        except Exception:
            reason += '_partial_write_failed'
    finally:
        signal.alarm(0)
        out.write('summary.json', {'status': status, 'reason': reason, 'samples': count,
                  'elapsed_seconds': clock()-start, 'monitor_only': True,
                  'abort_receipt': status != 'PASS', 'services_changed': False})
    return 0 if status == 'PASS' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupted)
    try:
        c = config(args.manifest)
        return run(c, Artifacts(args.output))
    except Exception:
        print('NONPASS: observer setup/artifact failure; inspect private run directory', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
