#!/usr/bin/env python3
"""Bounded staging observer. No runtime mutation or automatic recovery."""
import argparse
import hashlib
import gzip
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

LOG_ROOT = '/srv/eqemu-staging/state/server/logs/'
LOG_PATHS = (LOG_ROOT+'world_29.log', LOG_ROOT+'zone/poknowledge_version_0_inst_id_0_port_0_40.log',
             LOG_ROOT+'zone/qeynos2_version_0_inst_id_0_port_0_41.log', LOG_ROOT+'zone/zone_162.log')
POLICY_PATH = '/etc/logrotate.d/eqemu-staging'
POLICY_SHA = '908247ab7494a776b017c23caa121c02a95ffba61fb5cb94164bb95501198478'
LOG_CONTRACT = {'version':'copytruncate-visible-footprint-v1', 'policy_path':POLICY_PATH,
                'policy_sha256':POLICY_SHA, 'growth_metric':'visible_on_disk_footprint_high_water_increase',
                'content_claim':'observed_bytes_only', 'continuity':'UNPROVEN',
                'archive_suffixes':['.1']+['.'+str(i)+'.gz' for i in range(2,8)],
                'owner_uid':1000, 'owner_gid':1000, 'sample_read_expanded_budget_bytes':CAP}


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
    require(c.get('log_observation') == LOG_CONTRACT, 'log_contract_required')
    require(c['logs'] == list(LOG_PATHS), 'fixed_log_paths_required')
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
        if name == 'summary.json':
            self.terminal(payload)
            self.used += len(payload)
            return
        with (self.root/name).open('ab' if append else 'xb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        self.used += len(payload)
        if not append:
            (self.root/name).chmod(0o400)


    def terminal(self, payload):
        """Prepare privately; remove our publication if directory sync fails."""
        pending = self.root/'.summary.pending'
        final = self.root/'summary.json'
        published = False
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pending.open('x+b') as stream:
                stream.write(payload)
                stream.flush()
                os.fchmod(stream.fileno(), 0o400)
                os.fsync(stream.fileno())
                stream.seek(0)
                require(stream.read() == payload, 'terminal_readback')
            os.fsync(directory)
            os.link(pending, final)  # Exclusive publication, never replace a receipt.
            published = True
            pending.unlink()
            os.fsync(directory)
        except Exception:
            if published:
                final.unlink()
            pending.unlink(missing_ok=True)
            raise
        finally:
            os.close(directory)


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


def verify_policy():
    p = Path(POLICY_PATH)
    with os.fdopen(os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW),'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'unsafe_log_policy')
        raw = stream.read(8193)
        require(len(raw) <= 8192 and hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'log_policy_changed')
        after = p.lstat()
        require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns) ==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns), 'unstable_log_policy')
    return POLICY_SHA


def log_sample(path, previous, budget=None):
    """Only fixed policy archives; rotation is an explicit content gap, never recovery."""
    budget = [CAP] if budget is None else budget
    path = Path(path)
    def consume(raw):
        budget[0] -= len(raw)
        require(budget[0] >= 0, 'log_scan_backlog')
        return raw
    def signature(st):
        return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
    def opened(p):
        require(p.absolute() == p.resolve(), 'log_path_alias')
        stream = os.fdopen(os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW),'rb')
        try:
            st = os.fstat(stream.fileno())
            require(stat.S_ISREG(st.st_mode), 'log_not_regular')
            require(st.st_uid == 1000 and st.st_gid == 1000 and st.st_nlink == 1 and not st.st_mode & 0o022, 'unsafe_log_owner')
            return stream,st
        except BaseException:
            stream.close()
            raise
    def stable(p, stream, before):
        require(signature(os.fstat(stream.fileno())) == signature(before) == signature(p.lstat()) and p.absolute() == p.resolve(), 'unstable_log_read')
    allowed = {path.name+x for x in LOG_CONTRACT['archive_suffixes']}
    def inventory_names():
        names = set()
        for count,entry in enumerate(path.parent.iterdir(),1):
            require(count <= 4096, 'log_directory_bound')
            if entry.name.startswith(path.name+'.'):
                require(entry.name in allowed, 'unexpected_archive_name')
                names.add(entry.name)
        return names
    names = inventory_names()
    archives = {}
    for suffix in LOG_CONTRACT['archive_suffixes']:
        p = Path(str(path)+suffix)
        if not p.exists():
            require(not p.is_symlink(), 'archive_alias')
            continue
        stream,st = opened(p)
        with stream:
            require(st.st_size <= budget[0], 'archive_read_budget')
            raw = consume(stream.read(st.st_size+1))
            require(len(raw) == st.st_size, 'archive_short_read')
            if suffix.endswith('.gz'):
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as expanded:
                    data = consume(expanded.read(budget[0]+1))
            else:
                data = raw
            require(BAD.search(data) is None, 'native_log_fault_or_nonfinite')
            stable(p,stream,st)
        archives[suffix] = {'identity':[st.st_dev,st.st_ino], 'bytes':st.st_size,
                            'sha256':hashlib.sha256(raw).hexdigest(),
                            'content_sha256':hashlib.sha256(data).hexdigest(), '_data':data, '_stat':signature(st)}
    expected = LOG_CONTRACT['archive_suffixes'][:len(archives)]
    require(list(archives) == expected, 'archive_generation_gap')
    stream,st = opened(path)
    with stream:
        identity = [st.st_dev,st.st_ino]
        offset = st.st_size if previous is None else previous['offset']
        changed = previous is not None and {k:(v['identity'],v['sha256']) for k,v in archives.items()} != previous['_archive_signature']
        rotation = previous is not None and (st.st_size < offset or changed)
        event = None
        if previous and not rotation:
            old_anchor = previous['_anchor']
            stream.seek(max(0,offset-len(old_anchor)))
            verified = consume(stream.read(len(old_anchor)))
            require(BAD.search(verified) is None, 'native_log_fault_or_nonfinite')
            require(verified == old_anchor, 'log_prefix_changed')
        tail = previous.get('_tail',b'') if previous else b''
        if previous:
            require(identity == previous['identity'], 'unexpected_log_replacement')
        if rotation:
            require(changed and '.1' in archives, 'unexpected_log_truncation')
            old_archives = previous['_archives']
            require(archives['.1']['identity'] != old_archives.get('.1',{}).get('identity'), 'unexpected_archive_reuse')
            for index,suffix in enumerate(LOG_CONTRACT['archive_suffixes'][1:],1):
                prior = old_archives.get(LOG_CONTRACT['archive_suffixes'][index-1])
                current = archives.get(suffix)
                require((prior is None) == (current is None), 'unexpected_archive_generation')
                if prior:require(prior['content_sha256'] == current['content_sha256'], 'archive_content_changed')
            data = archives['.1']['_data']
            anchor = previous['_anchor']
            require(len(data) >= offset and data[max(0,offset-len(anchor)):offset] == anchor, 'archive_prefix_unverified')
            unread = data[offset:]
            require(BAD.search(tail+unread) is None, 'native_log_fault_or_nonfinite')
            event = {'kind':'policy_consistent_copytruncate','old_offset':offset,'archive_available_bytes':len(data),
                     'archive_unread_observed_bytes':len(unread), 'archive_observed_start':offset,
                     'archive_observed_end':len(data),'archive_observed_sha256':hashlib.sha256(unread).hexdigest(),'window_monotonic':[previous['_sample_time'],time.monotonic()],
                     'content_coverage':'GAP_POSSIBLE','no_lost_or_recovered_byte_claim':True}
            offset,tail = 0,b''  # Never join content across the unproved gap.
        require(st.st_size-offset <= budget[0], 'log_scan_backlog')
        stream.seek(offset);new = consume(stream.read(st.st_size-offset))
        require(len(new) == st.st_size-offset, 'log_short_read')
        require(BAD.search(tail+new) is None, 'native_log_fault_or_nonfinite')
        stream.seek(max(0,st.st_size-256));anchor = consume(stream.read(min(256,st.st_size)))
        require(BAD.search(anchor) is None, 'native_log_fault_or_nonfinite')
        stable(path,stream,st)
    require(inventory_names() == names, 'unstable_archive_inventory')
    require([suffix for suffix in LOG_CONTRACT['archive_suffixes'] if Path(str(path)+suffix).exists()] == list(archives), 'unstable_archive_inventory')
    for suffix,row in archives.items():
        require(signature(Path(str(path)+suffix).lstat()) == row['_stat'], 'unstable_archive_snapshot')
    public_archives = {k:{x:y for x,y in v.items() if not x.startswith('_')} for k,v in archives.items()}
    return {'identity':identity,'offset':st.st_size,'new_bytes':len(new),
            'observed_start':offset,'observed_end':st.st_size,'observed_sha256':hashlib.sha256(new).hexdigest(),
            'visible_footprint_bytes':st.st_size+sum(x['bytes'] for x in archives.values()),
            'archives':public_archives,'rotation':event,'coverage_gap':bool(event) or bool(previous and previous['coverage_gap']),
            '_tail':anchor,'_anchor':anchor,'_sample_time':time.monotonic(),
            '_archives':public_archives,'_archive_signature':{k:(v['identity'],v['sha256']) for k,v in archives.items()}}


class Observer:
    def __init__(self, c):
        self.c = c
        self.hashes = {}
        self.logs = {}
        self.baseline = None
        self.previous = None
        self.log_gap = False
        self.log_footprint_high_water = 0

    def sample(self, result):
        c = self.c
        policy_sha = verify_policy()
        result['log_policy_sha256'] = policy_sha
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
            cpu_start = time.monotonic()
            cpu = counters(cg/'cpu.stat')
            cpu_end = time.monotonic()
            v = {'id': cid, 'image': image, 'pid': pid, 'started': state['StartedAt'],
                 'init_process': process(pid, self.hashes),
                 'restarts': restarts, 'memory_bytes': int(read(cg/'memory.current', 64)),
                 'memory_events': events, 'cpu': cpu,
                 'cpu_read_window': [cpu_start, cpu_end],
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
        budget = [CAP]
        for i, path in enumerate(c['logs']):
            self.logs[path] = log_sample(path, self.logs.get(path),budget)
            self.log_gap |= self.logs[path]['coverage_gap']
            result['logs'].append({k:v for k,v in self.logs[path].items() if not k.startswith('_')})
        footprint = sum(x['visible_footprint_bytes'] for x in result['logs'])
        self.log_footprint_high_water = max(self.log_footprint_high_water,footprint)
        baseline = self.baseline['log_footprint']['baseline_bytes'] if self.baseline else footprint
        result['log_footprint'] = {'metric':LOG_CONTRACT['growth_metric'],'baseline_bytes':baseline,
            'current_bytes':footprint,'high_water_bytes':self.log_footprint_high_water,
            'increase_bytes':max(0,self.log_footprint_high_water-baseline)}
        result['log_coverage'] = 'GAP_POSSIBLE' if self.log_gap else 'SAMPLED_NO_OBSERVED_ROTATION'
        result['disk_free_bytes'] = [os.statvfs(p).f_bavail*os.statvfs(p).f_frsize for p in c['disk_paths']]
        require(min(result['disk_free_bytes']) >= c['limits']['disk_free_bytes'], 'disk_free_limit')
        mem = dict(line.split(':', 1) for line in read('/proc/meminfo', 16384).decode().splitlines())
        result['host_available_bytes'] = int(mem['MemAvailable'].split()[0])*1024
        require(result['host_available_bytes'] >= c['limits']['host_available_bytes'], 'host_memory_limit')
        require(digest(c['health_script']) == c['health_sha256'], 'health_script_changed')
        container_health = '/home/eqemu/server/bin/staging-health.py'
        observed = command(['docker', 'exec', CONTAINERS[0], 'sha256sum', container_health]).decode().split()
        require(observed and observed[0] == c['health_sha256'], 'container_health_script_changed')
        health = command(['docker', 'exec', CONTAINERS[0], 'python3', '-I', container_health], timeout=20)
        ready = json.loads(health)
        require(ready.get('ready') is True and ready.get('zones') == c['expected_zones']
                and {'qeynos2', 'poknowledge'} <= set(ready.get('static_zones', [])), 'native_readiness')
        result['health'] = {'ready': True, 'zones': ready['zones'], 'output_bytes': len(health)}
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
            # Use the shortest possible counter interval, never a sample-start proxy.
            elapsed = v['cpu_read_window'][0]-previous['containers'][name]['cpu_read_window'][1]
            delta = v['cpu']['usage_usec']-previous['containers'][name]['cpu']['usage_usec']
            require(elapsed > 0 and delta >= 0, 'invalid_cpu_delta')
            require(delta / 1e6 / elapsed <= self.c['limits']['containers'][name]['cpu_cores'], 'container_cpu_limit')
        require(result['log_footprint']['increase_bytes'] <= self.c['limits']['log_growth_bytes'], 'log_growth_limit')


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
            require(clock() <= target+90, 'sample_gap')
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
                status = 'PASS_WITH_LOG_COVERAGE_GAP' if getattr(observer,'log_gap',False) else 'PASS'
                reason = 'resource_health_deadline_complete'
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
                  'resource_health_status':'NONPASS' if status == 'NONPASS' else 'PASS',
                  'logcoverage':'GAP_POSSIBLE' if getattr(observer,'log_gap',False) else 'SAMPLED_NO_OBSERVED_ROTATION',
                  'log_continuity':'UNPROVEN','content_claim':'observed_bytes_only',
                  'growth_metric':LOG_CONTRACT['growth_metric'],
                  'last_complete_log_footprint':getattr(observer,'previous',None).get('log_footprint') if getattr(observer,'previous',None) else None,
                  'log_observation_contract':c['log_observation'],
                  'end_probe_eligible':False,'scope':'resource_health_identity_visible_log_footprint',
                  'abort_receipt': status == 'NONPASS', 'services_changed': False})
    return 1 if status == 'NONPASS' else 0


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
