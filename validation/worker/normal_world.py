"""Fixed disposable normal-world fixture. Never execute candidate code on the host.

Root prepares public data; the observer and all three native executables run as
nobody in the offline guest. The observer uses kernel-owned socket identities and
an echoed EQ stream session challenge, not startup log strings.
"""
import hashlib
from contextlib import ExitStack, contextmanager, nullcontext
import json
import os
from pathlib import Path
import pwd
import math
import resource
import re
import stat
import signal
import socket
import shutil
import struct
import subprocess
import sys
import time

SECONDS = 1800
OBSERVE_SECONDS = 120
BASELINE_SECONDS = 5
INSERVER_LIMIT = 4096
EVIDENCE_LIMIT = 16384
PROBE_ALLOCATION_ATTEMPTS = 16
PROBE_PORT_LIMIT = 1200


class InserverFailure(Exception):
    """Candidate suite did not produce complete, consistent native test evidence."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate in-server result key")
        result[key] = value
    return result


def validate_inserver(value, run_id=None):
    """The fixture knows the report protocol, never scenario names or assertions."""
    fields = {"version", "run_id", "suite", "selected", "started", "completed",
              "failed", "finalized", "passed", "tests"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Missing or malformed in-server completion")
    if (type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["run_id"], str) or not re.fullmatch("[a-f0-9]{32}", value["run_id"])
            or (run_id is not None and value["run_id"] != run_id)
            or value["suite"] != "zone" or value["finalized"] is not True
            or type(value["passed"]) is not bool):
        raise ValueError("Invalid in-server identity or completion")
    tests = value["tests"]
    if (not isinstance(tests, list) or not 1 <= len(tests) <= 32
            or any(type(value[name]) is not int for name in ("selected", "started", "completed", "failed"))
            or not value["selected"] == value["started"] == value["completed"] == len(tests)):
        raise ValueError("Incomplete in-server tests")
    names = set()
    for test in tests:
        if (not isinstance(test, dict) or set(test) != {"name", "passed", "diagnostic"}
                or not isinstance(test["name"], str) or not 1 <= len(test["name"]) <= 64
                or test["name"] in names or type(test["passed"]) is not bool
                or not isinstance(test["diagnostic"], str) or len(test["diagnostic"]) > 256):
            raise ValueError("Invalid or duplicate in-server test")
        names.add(test["name"])
    failed = sum(not test["passed"] for test in tests)
    if (value["failed"] != failed or value["passed"] != (failed == 0)
            or len(json.dumps(value, separators=(",", ":")).encode()) > INSERVER_LIMIT):
        raise ValueError("Inconsistent or oversized in-server completion")
    return value


def read_inserver(path, run_id):
    """Read bounded regular bytes without following candidate-created links or pipes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise InserverFailure(str(error)) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= INSERVER_LIMIT:
            raise ValueError("In-server result must be a bounded regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(INSERVER_LIMIT + 1)
        if len(data) != info.st_size:
            raise ValueError("In-server result changed while reading")
        value = validate_inserver(json.loads(data, object_pairs_hook=unique_object), run_id)
        return value, (info.st_dev, info.st_ino, info.st_mtime_ns, data)
    except (ValueError, OSError) as error:
        raise InserverFailure(str(error)) from error
    finally:
        os.close(fd)


def cpu_ticks(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[11]) + int(fields[12])


def socket_inodes(pid):
    result = set()
    for fd in Path('/proc', str(pid), 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            result.add(target[8:-1])
    return result


def world_connected(world, zone):
    """Require both ends of an established loopback connection owned by our PIDs."""
    world_inodes, zone_inodes = socket_inodes(world), socket_inodes(zone)
    rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    for row in rows:
        if (row[3] == '01' and row[9] in zone_inodes
                and row[2] == '0100007F:2328' and row[1].startswith('0100007F:')):
            if any(peer[3] == '01' and peer[9] in world_inodes
                   and peer[1] == row[2] and peer[2] == row[1] for peer in rows):
                return True
    return False


def probe(port=7000, *, used_ports=None, diagnostics=None):
    """Echo a fresh session; the observer retains used source ports for its lifetime."""
    if used_ports is None:
        used_ports = set()
    if diagnostics is not None:
        diagnostics.update(source_port=None, discarded_allocations=0)
    # EQ streams retain endpoint/session identity after the UDP client closes.
    # Never transmit a new challenge on an endpoint used by an earlier sample.
    if len(used_ports) < PROBE_PORT_LIMIT:
        for attempt in range(PROBE_ALLOCATION_ATTEMPTS):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                stream.connect(('127.0.0.1', port))
                source_port = stream.getsockname()[1]
                if diagnostics is not None:
                    diagnostics['source_port'] = source_port
                if source_port in used_ports:
                    if diagnostics is not None:
                        diagnostics['discarded_allocations'] = attempt + 1
                    continue
                used_ports.add(source_port)
                challenge = os.urandom(4)
                stream.settimeout(.25)
                stream.send(b'\x00\x01' + struct.pack('!I', 2) + challenge + struct.pack('!I', 512))
                try:
                    response = stream.recv(512)
                except (TimeoutError, ConnectionRefusedError) as error:
                    if diagnostics is not None:
                        diagnostics['condition'] = 'udp-timeout' if isinstance(error, TimeoutError) else 'udp-refused'
                    return False
                valid = len(response) >= 6 and response[:2] == b'\x00\x02' and response[2:6] == challenge
                if diagnostics is not None:
                    diagnostics['condition'] = 'responsive' if valid else 'udp-malformed-reply'
                return valid
    if diagnostics is not None:
        diagnostics['condition'] = 'udp-allocation-exhausted'
    raise RuntimeError('Unused UDP probe source port allocation exhausted')



def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()


def bounded_text(value, limit):
    return str(value).encode('utf-8', 'replace')[-limit:].decode('utf-8', 'ignore') if limit > 0 else ''



def bounded_json_text(value, limit):
    """Keep error metadata bounded after JSON escaping, even for control characters."""
    value = bounded_text(value, limit)
    while len(encoded(value)) > limit:
        value = value[max(1, len(value)//2):]
    return value


def console_bytes(path):
    """Candidate-controlled paths must never redirect the observer into devices."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024**2:
            raise ValueError('Console is not a bounded regular file')
        return stream.read(1024**2 + 1)


@contextmanager
def observer_credential_pipe(snapshot):
    """Only root's original guest credentials reach observer stdin, never argv/config."""
    if len(snapshot) > 1024:
        raise ValueError('Observer credential budget')
    read, write = os.pipe2(os.O_CLOEXEC)
    with ExitStack() as stack:
        reader = stack.enter_context(os.fdopen(read, 'rb'))
        writer = stack.enter_context(os.fdopen(write, 'wb'))
        writer.write(snapshot)
        writer.close()
        yield reader


def read_observer_secrets():
    stream = sys.stdin.buffer
    if not stat.S_ISFIFO(os.fstat(stream.fileno()).st_mode):
        raise ValueError('Observer requires a credential pipe')
    raw = stream.read(1025)
    if len(raw) > 1024:
        raise ValueError('Observer credential budget')
    values = json.loads(raw)
    if (not isinstance(values, list) or len(values) != 2
            or any(not isinstance(value, str) or not 1 <= len(value) <= 128 for value in values)):
        raise ValueError('Invalid disposable credential snapshot')
    return values


def case_progress(data, run_id):
    """Progress is advisory. Ignore malformed/stale events, never accept a suite."""
    active = completed = None
    rejected = 0
    for line in data.splitlines():
        if not line.startswith(b'EQEMU_INSERVER_PROGRESS '):
            continue
        try:
            if len(line) > 4096:
                raise ValueError('Oversized progress')
            value = json.loads(line.removeprefix(b'EQEMU_INSERVER_PROGRESS '), object_pairs_hook=unique_object)
            end = value.get('event') == 'case-end'
            fields = {'version', 'run_id', 'event', 'name', 'elapsed_ms'} | ({'passed', 'diagnostic'} if end else set())
            if (set(value) != fields or type(value['version']) is not int or value['version'] != 1
                    or value['run_id'] != run_id or value['event'] not in ('case-start', 'case-end')
                    or not isinstance(value['name'], str) or not 1 <= len(value['name']) <= 64
                    or type(value['elapsed_ms']) is not int or not 0 <= value['elapsed_ms'] <= 2**64-1
                    or (end and (type(value['passed']) is not bool or not isinstance(value['diagnostic'], str)
                                 or len(value['diagnostic']) > 256))):
                raise ValueError('Malformed progress')
            if end:
                if active is None or active['name'] != value['name']:
                    raise ValueError('Unmatched case end')
                completed, active = value, None
            else:
                active = value
        except (ValueError, TypeError, AttributeError, KeyError):
            rejected += 1
    return dict(active_case=active, last_completed_case=completed, rejected_events=rejected)


def source_diagnostics(data):
    """Retain advisory text from this run's zone console, never suite evidence."""
    result = dict(advisory=True)
    stack = None
    collecting = complete = truncated = False
    frames = 0
    for line in data.removesuffix(b'\n').split(b'\n'):
        line = line.removesuffix(b'\r')
        if line.startswith(b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT '):
            result['context'] = bounded_json_text(
                line.removeprefix(b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT ').decode(errors='replace'), 500)
        elif line == b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN':
            stack = bytearray()
            collecting, complete, truncated, frames = True, False, False, 0
        elif line == b'EQEMU_NATIVE_DIAGNOSTIC_STACK_END':
            if collecting:
                complete, collecting = True, False
        elif collecting:
            frame = line + b'\n'
            if frames < 32:
                remaining = 4096 - len(stack)
                stack.extend(frame[:remaining])
                truncated |= len(frame) > remaining
            else:
                truncated = True
            frames += 1
    if stack is not None:
        text = stack.decode(errors='replace')
        result['stack'] = bounded_json_text(text, 3000)
        result['stack_complete'] = complete
        result['stack_truncated'] = truncated or result['stack'] != text
    return result if len(result) > 1 else None


def first_sanitizer_diagnostic(data):
    """Keep the first recognizable diagnostic independently of long stack tails.

    Candidate text is advisory, never a verdict. Console bytes have already been
    scrubbed before any excerpt boundaries are selected.
    """
    marker = re.search(rb'ERROR: (?:AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer):|'
                       rb'(?:AddressSanitizer|UndefinedBehaviorSanitizer):DEADLYSIGNAL|runtime error:', data)
    if marker is None:
        return None
    line = data.rfind(b'\n', 0, marker.start()) + 1
    start = max(line, marker.start() - 200)
    text = data[start:start + 4096].decode(errors='replace')
    # Prefix truncation must preserve the diagnostic header, including under
    # hostile UTF-8/control-character escaping. Tail budgets remain separate.
    low, high = 0, min(len(text), 1000)
    while low < high:
        middle = (low + high + 1) // 2
        if len(encoded(text[:middle])) <= 1000:
            low = middle
        else:
            high = middle - 1
    text = text[:low]
    # An excessively escaped source prefix must not crowd out the marker itself.
    if marker.group().decode() not in text:
        start = marker.start()
        text = data[start:start + 1000].decode(errors='replace')
        while len(encoded(text)) > 1000:
            text = text[:len(text)//2]
    return dict(advisory=True, marker=marker.group().decode(), offset=marker.start(),
                context=bounded_json_text(data[max(0, line-128):line].decode(errors='replace'), 200),
                text=text, leading_line_truncated=start > line,
                truncated=start > 0 or len(text) < len(data[start:].decode(errors='replace')))


# Failure telemetry contains only bounded numbers and fixed enums. It is never
# suite evidence, and the first poll observation is kept separate from final exits.
CAPTURE_STATES = ('ok', 'unavailable', 'exited', 'identity-changed', 'invalid', 'budget',
                  'denied', 'not-opened', 'read-error', 'overrun', 'would-block')
CAPTURE_CONDITIONS = ('starting', 'responsive', 'child-exit', 'cancelled', 'deadline',
    'console-budget', 'world-connection-lost', 'udp-rejected', 'udp-timeout', 'udp-refused',
    'udp-malformed-reply', 'udp-allocation-exhausted', 'assertion')
MEM_FIELDS = dict(MemTotal='total_kib', MemAvailable='available_kib',
                  SwapTotal='swap_kib', SwapFree='swap_free_kib')


def unsigned(value):
    if not re.fullmatch(r'[0-9]{1,20}', value) or int(value) > 2**64-1:
        raise ValueError('Invalid numeric observation')
    return int(value)


def proc_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('Invalid proc file')
        data = stream.read(limit+1)
        if len(data) > limit: raise ValueError('Proc input budget')
        return data.decode('ascii')


def capture_state(error):
    if isinstance(error, PermissionError): return 'denied'
    if isinstance(error, FileNotFoundError): return 'exited'
    return 'invalid' if isinstance(error, (ValueError, UnicodeError, IndexError)) else 'read-error'


def start_ticks(proc, pid):
    # stat's comm may contain spaces and parentheses. Never export that text.
    return unsigned(proc_bytes(proc / str(pid) / 'stat', 8192).rsplit(')', 1)[1].split()[19])


def guest_memory(proc):
    value = dict(state='ok', **{key: None for key in (*MEM_FIELDS.values(), 'oom_kill')})
    try:
        for line in proc_bytes(proc/'meminfo', 8192).splitlines():
            fields = line.split()
            if fields and fields[0].rstrip(':') in MEM_FIELDS:
                if len(fields) != 3 or fields[2] != 'kB': raise ValueError('Memory units')
                value[MEM_FIELDS[fields[0].rstrip(':')]] = unsigned(fields[1])
        for line in proc_bytes(proc/'vmstat', 65536).splitlines():
            fields = line.split()
            if fields and fields[0] == 'oom_kill':
                if len(fields) != 2: raise ValueError('Counter fields')
                value['oom_kill'] = unsigned(fields[1])
        if any(item is None for key, item in value.items() if key != 'state'):
            value['state'] = 'unavailable'
    except (OSError, ValueError, UnicodeError) as error:
        value['state'] = capture_state(error)
    return value


class FailureCapture:
    """Sample at existing guard opportunities; latch before any cleanup signal."""
    def __init__(self, start, proc=Path('/proc')):
        self.start, self.proc = start, proc
        self.children = []
        self.pre = None
        self.baseline = guest_memory(proc)
        self.failure = None
        self.last_sample = None

    def elapsed(self): return max(0, min(2**32-1, int((time.monotonic()-self.start)*1000)))

    def watch(self, name, process):
        item = dict(name=name, pid=process.pid, start_ticks=None, samples=0, last_ms=None,
                    max_gap_ms=0, rss_kib=None, hwm_kib=None, state='unavailable')
        try: item['start_ticks'] = start_ticks(self.proc, process.pid)
        except (OSError, ValueError, UnicodeError, IndexError) as error: item['state'] = capture_state(error)
        self.children.append(item)

    def sample(self, force=False):
        now = self.elapsed()
        if not force and self.last_sample is not None and now-self.last_sample < 100: return
        self.last_sample = now
        for item in self.children:
            gap = now - (item['last_ms'] if item['last_ms'] is not None else 0)
            item['max_gap_ms'] = max(item['max_gap_ms'], gap)
            try:
                before = start_ticks(self.proc, item['pid'])
                if item['start_ticks'] is None or before != item['start_ticks']:
                    item['state'] = 'identity-changed'; continue
                fields = {}
                for line in proc_bytes(self.proc/str(item['pid'])/'status', 8192).splitlines():
                    parts = line.split()
                    if parts and parts[0] in ('VmRSS:', 'VmHWM:'):
                        if len(parts) != 3 or parts[2] != 'kB': raise ValueError('Process units')
                        fields[parts[0]] = unsigned(parts[1])
                if start_ticks(self.proc, item['pid']) != before:
                    item['state'] = 'identity-changed'; continue
                if set(fields) != {'VmRSS:', 'VmHWM:'}: raise ValueError('Missing process memory')
                item.update(samples=min(2**32-1, item['samples']+1), last_ms=now,
                    max_gap_ms=max(item['max_gap_ms'], gap), state='ok',
                    rss_kib=max(item['rss_kib'] or 0, fields['VmRSS:']),
                    hwm_kib=max(item['hwm_kib'] or 0, fields['VmHWM:']))
            except (OSError, ValueError, UnicodeError, IndexError) as error: item['state'] = capture_state(error)

    def latch(self, processes, condition, polls=None):
        if self.pre is not None: return
        polls = [p.poll() for p in processes[:2]] if polls is None else polls
        observed_ms = self.elapsed()
        self.sample(force=True)
        items = [dict(name=item['name'], pid=item['pid'], start_ticks=item['start_ticks'], returncode=code)
                 for item, code in zip(self.children, polls)]
        exited = [item['name'] for item in items if item['returncode'] is not None]
        self.pre = dict(version=1, elapsed_ms=observed_ms,
            condition=condition if condition in CAPTURE_CONDITIONS else 'assertion', processes=items,
            first_observed_exited=next(iter(exited), None), simultaneous_observed=len(exited) > 1)
        self.failure = guest_memory(self.proc)

    def finish(self):
        final = guest_memory(self.proc)
        first, last = self.baseline['oom_kill'], final['oom_kill']
        middle = (self.failure or final)['oom_kill']
        counters = [value for value in (first, middle, last) if value is not None]
        reset = any(b < a for a, b in zip(counters, counters[1:]))
        return fit_resources(dict(version=1, processes=self.children,
            guest=dict(baseline=self.baseline, failure=self.failure or final, final=final,
                       delta=None if first is None or last is None or reset else last-first,
                       failure_delta=None if first is None or middle is None or reset else middle-first, reset=reset),
            kernel=kernel_facts('not-opened'), truncated=False),
            min(1536, 2048-len(encoded(self.pre))-60))


def fit_resources(value, budget=1536):
    """Drop only optional numeric detail, explicitly, before any outer truncation."""
    value = json.loads(json.dumps(value))
    if len(encoded(value)) > budget:
        value['truncated'] = True
        kernel = value['kernel']
        while kernel['records'] and len(encoded(value)) > budget:
            kernel['records'].pop(); kernel['additional'] += 1; kernel['truncated'] = True
        for record in value['guest'].values():
            if isinstance(record, dict):
                for key in MEM_FIELDS.values():
                    if len(encoded(value)) <= budget: break
                    record[key] = None; record['state'] = 'budget'
        for record in value['processes']:
            if len(encoded(value)) <= budget: break
            record.update(rss_kib=None, hwm_kib=None, state='budget')
    if len(encoded(value)) > budget: raise ValueError('Failure resource metadata budget')
    return value


def kernel_facts(state, opened_us=None):
    # SEEK_END establishes a cursor boundary but does not expose its sequence.
    # Kernel record timestamps are retained as supplied; wall-clock/sender
    # attribution is not inferred from these monotonic collector boundaries.
    return dict(state=state, records=[], truncated=False, additional=0, unparsed=0,
        scope='observer-through-cleanup', basis='pid-in-cursor-window',
        boundary='cursor-end' if opened_us is not None else 'unavailable',
        opened_us=opened_us, closed_us=None, opening_sequence=None)


class KernelOOM:
    """Guest-root-only nonblocking kernel window; no raw kernel text escapes."""
    def __init__(self):
        self.fd = None
        self.opened_us = None
        self.state = 'not-opened'
        if os.geteuid() != 0 or not Path('/opt/eqemu-worker-build-guest').is_file(): return
        try:
            self.fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            os.lseek(self.fd, 0, os.SEEK_END)
            self.opened_us = int(time.monotonic()*1000000)
            self.state = 'ok'
        except OSError as error:
            self.state = capture_state(error)
            self.close()

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None

    def finish(self, pids):
        result = kernel_facts(self.state, self.opened_us)
        try:
            if self.fd is None: return result
            end = time.monotonic()+.05
            total = 0
            for _ in range(256):
                if time.monotonic() >= end or total >= 65536:
                    result.update(state='budget', truncated=True); break
                try: raw = os.read(self.fd, min(8192, 65536-total))
                except BlockingIOError:
                    result['state'] = 'would-block'; break
                except OSError as error:
                    result['state'] = 'overrun' if error.errno == 32 else capture_state(error)
                    result['truncated'] = True; break
                if not raw: break
                total += len(raw)
                # kmsg metadata and message grammar are checked independently.
                meta, sep, message = raw.partition(b';')
                fields = meta.split(b',')
                candidate = b'Killed process ' in message
                if not sep or len(fields) != 4:
                    result['unparsed'] += int(candidate); continue
                match = re.fullmatch(rb'(?:Out of memory: |Memory cgroup out of memory: )Killed process ([0-9]+) \([^\n]*\) total-vm:([0-9]+)kB, anon-rss:([0-9]+)kB, file-rss:([0-9]+)kB, shmem-rss:([0-9]+)kB[^\n]*(?:\n)?', message)
                if match is None:
                    result['unparsed'] += int(candidate); continue
                try:
                    if unsigned(fields[0].decode('ascii')) > 191 or fields[3] not in (b'-', b'c'):
                        result['unparsed'] += 1; continue
                    seq, usec = unsigned(fields[1].decode('ascii')), unsigned(fields[2].decode('ascii'))
                    numbers = [unsigned(x.decode('ascii')) for x in match.groups()]
                except (ValueError, UnicodeError):
                    result['unparsed'] += 1; continue
                if numbers[0] not in pids: continue
                if len(result['records']) == 2:
                    result['additional'] += 1; result['truncated'] = True; continue
                result['records'].append(dict(pid=numbers[0], sequence=seq, time_us=usec,
                    total_vm_kib=numbers[1], anon_rss_kib=numbers[2], file_rss_kib=numbers[3], shmem_rss_kib=numbers[4]))
            else: result.update(state='budget', truncated=True)
            return result
        finally:
            if self.opened_us is not None: result['closed_us'] = int(time.monotonic()*1000000)
            self.close()


def validate_capture(value):
    """Reject raw strings, unknown keys and bool-as-int in advisory telemetry."""
    if 'capture_error' in value and value['capture_error'] not in ('pre-snapshot-unavailable',
            'post-snapshot-unavailable','resources-unavailable','root-capture-unavailable',
            'kernel-init-unavailable','kernel-merge-unavailable','kernel-close-unavailable'):
        raise ValueError('Invalid capture error')
    def number(n, signed=False):
        if n is not None and (type(n) is not int or not (-2**31 if signed else 0) <= n <= 2**64-1):
            raise ValueError('Invalid failure capture number')
    def record(item, numbers, extras=()):
        if not isinstance(item, dict) or set(item) != set(numbers) | set(extras):
            raise ValueError('Invalid failure capture fields')
        for key in numbers: number(item[key], signed=key == 'returncode')
    def processes(items, pre=False):
        if not isinstance(items, list) or len(items) > 2: raise ValueError('Invalid failure capture processes')
        for name, item in zip(('world', 'zone'), items):
            numbers = ('pid', 'start_ticks', 'returncode') if pre else ('pid','start_ticks','samples','last_ms','max_gap_ms','rss_kib','hwm_kib')
            record(item, numbers, ('name',) if pre else ('name','state'))
            if item['name'] != name or item['pid'] is None: raise ValueError('Invalid failure capture process identity')
            if not pre and item['state'] not in CAPTURE_STATES: raise ValueError('Invalid failure capture state')
    pre = value.get('pre_cleanup_observation')
    resources = value.get('failure_resources')
    if pre is not None:
        record(pre, ('version','elapsed_ms'), ('condition','processes','first_observed_exited','simultaneous_observed'))
        processes(pre['processes'], pre=True)
        exited = [p['name'] for p in pre['processes'] if p['returncode'] is not None]
        if (pre['version'] != 1 or pre['condition'] not in CAPTURE_CONDITIONS
                or pre['first_observed_exited'] != next(iter(exited), None)
                or type(pre['simultaneous_observed']) is not bool or pre['simultaneous_observed'] != (len(exited)>1)
                or len(encoded(pre)) > 512): raise ValueError('Invalid first failure observation')
    if resources is not None:
        record(resources, ('version',), ('processes','guest','kernel','truncated'))
        processes(resources['processes'])
        guest = resources['guest']; record(guest, ('delta','failure_delta'), ('baseline','failure','final','reset'))
        for key in ('baseline','failure','final'):
            record(guest[key], (*MEM_FIELDS.values(),'oom_kill'), ('state',))
            if guest[key]['state'] not in CAPTURE_STATES: raise ValueError('Invalid guest memory state')
        kernel = resources['kernel']; record(kernel, ('additional','unparsed','opened_us','closed_us','opening_sequence'),
            ('state','records','truncated','scope','basis','boundary'))
        if (kernel['scope'] != 'observer-through-cleanup' or kernel['basis'] != 'pid-in-cursor-window'
                or kernel['boundary'] not in ('cursor-end','unavailable')):
            raise ValueError('Invalid kernel correlation scope')
        if kernel['state'] not in CAPTURE_STATES or not isinstance(kernel['records'], list) or len(kernel['records'])>2:
            raise ValueError('Invalid kernel facts')
        for item in kernel['records']:
            record(item, ('pid','sequence','time_us','total_vm_kib','anon_rss_kib','file_rss_kib','shmem_rss_kib'))
            if item['pid'] not in [p['pid'] for p in resources['processes']]: raise ValueError('Unmatched kernel target')
        if (resources['version'] != 1 or any(type(x) is not bool for x in
                (resources['truncated'], guest['reset'], kernel['truncated'])) or len(encoded(resources))>1536):
            raise ValueError('Invalid resource facts')
        if pre is not None and ([(p['name'],p['pid'],p['start_ticks']) for p in pre['processes']]
                != [(p['name'],p['pid'],p['start_ticks']) for p in resources['processes']]):
            raise ValueError('Failure capture identity differs')
    fields = {key:value[key] for key in ('pre_cleanup_observation','failure_resources') if key in value}
    if len(encoded(fields))>2048: raise ValueError('Combined failure capture budget')


def shrink_failure_evidence(evidence):
    """Spend whole-record budgets on headers and facts before optional text."""
    console = evidence.get('console', {})
    names = [name for name, text in console.items() if isinstance(text, str) and text] if isinstance(console, dict) else []
    if names:
        name = max(names, key=lambda key: len(encoded(console[key])))
        console[name] = bounded_text(console[name], len(console[name].encode())//2)
        evidence.setdefault('console_truncated', {})[name] = True
    else:
        choices = []
        progress = evidence.get('progress', {})
        for event in ('active_case','last_completed_case'):
            item = progress.get(event) if isinstance(progress, dict) else None
            if not isinstance(item, dict): continue
            for field in ('name','diagnostic'):
                if isinstance(item.get(field), str) and item[field]:
                    choices.append((len(encoded(item[field])), 'progress', item, field))
        source = evidence.get('source_diagnostics', {})
        if isinstance(source, dict):
            for field in ('stack','context'):
                if isinstance(source.get(field), str) and source[field]:
                    choices.append((len(encoded(source[field])), 'source', source, field))
        if not choices: return False
        size, kind, item, field = max(choices, key=lambda choice: choice[0])
        item[field] = bounded_json_text(item[field], max(2, size//2))
        if kind == 'progress': evidence['progress_truncated'] = True
        else: item[field + '_truncated'] = True
    evidence['truncated'] = True
    return True


def failure_snapshot(processes, logs, run_id, start, observation, secrets=(), reserved=0):
    """Bound console evidence independently from the latched pre-cleanup poll."""
    evidence = dict(version=1, run_id=run_id, elapsed_ms=max(0, int((time.monotonic()-start)*1000)),
                    observation=dict(observation), processes=[], console={}, console_truncated={},
                    progress=dict(active_case=None, last_completed_case=None, rejected_events=0),
                    stack_capture=dict(available=shutil.which('gdb') is not None, captured=False,
                                       reason='deferred-no-reviewed-attachment'))
    for name, process in zip(('world', 'zone'), processes[:2]):
        item = dict(name=name, pid=process.pid, returncode=process.poll())
        try:
            item['state'] = Path('/proc', str(process.pid), 'stat').read_text().rsplit(')', 1)[1].split()[0]
            item['wait'] = Path('/proc', str(process.pid), 'wchan').read_text().strip()[:48]
        except (OSError, ValueError, IndexError):
            item['state'] = 'unavailable'
        evidence['processes'].append(item)
    for path in logs[:2]:
        try:
            data = console_bytes(path)
            # Scrub complete guest credentials before selecting any excerpt. A
            # later whole-secret scrub cannot recognize a truncated fragment.
            # Equal-length masks preserve byte offsets into the original log.
            for secret in secrets:
                raw = secret.encode()
                if raw:
                    data = data.replace(raw, b'*' * len(raw))
            evidence['console'][path.name] = bounded_text(data.decode(errors='replace'), 2500)
            evidence['console_truncated'][path.name] = len(data) > 2500
            if os.environ.get('ASAN_OPTIONS'):
                first = first_sanitizer_diagnostic(data)
                if first is not None:
                    evidence.setdefault('first_sanitizer_diagnostic', {})[path.name] = first
            if path.name == 'zone-console.log':
                evidence['progress'] = case_progress(data, run_id)
                # JSON escapes can hide a complete secret from the raw-byte
                # mask. Scrub decoded progress before its own budget boundaries.
                for event in ('active_case','last_completed_case'):
                    item = evidence['progress'].get(event)
                    if not isinstance(item, dict): continue
                    for field in ('name','diagnostic'):
                        if field in item:
                            for secret in secrets:
                                item[field] = item[field].replace(secret, '*'*len(secret))
                source = source_diagnostics(data)
                if source is not None:
                    evidence['source_diagnostics'] = source
        except (OSError, ValueError) as error:
            evidence['console'][path.name] = bounded_text('unavailable: ' + str(error), 256)
    # Bound JSON-encoded bytes, including escaping of hostile console text.
    evidence['truncated'] = False
    while len(encoded(evidence)) > 12000-reserved:
        if not shrink_failure_evidence(evidence):
            raise ValueError('Failure metadata exceeds evidence budget')
    return evidence


def owned_members():
    """Observer and native children share the session owned by the root adapter."""
    group = os.getpgrp()
    result = []
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            pid = int(path.parent.name)
            if pid != os.getpid() and fields[0] != 'Z' and int(fields[2]) == group:
                result.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def finalize_collectors(processes,collectors):
    """Let perf finish on target exit before exhaustive owned-group cleanup."""
    try:
        for process in processes:
            if process.poll() is None:
                try: process.terminate()
                except ProcessLookupError: pass
        deadline=time.monotonic()+10
        for process in processes: process.wait(timeout=max(.01,deadline-time.monotonic()))
        deadline=time.monotonic()+5
        for collector in collectors: collector.wait(timeout=max(.01,deadline-time.monotonic()))
    except Exception as error:
        return type(error).__name__
    return None


def stop(processes, *, diagnostics=None):
    """Clean the exact owned session even when a native leader exited first."""
    def send(sig):
        for pid in owned_members():
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
    def snapshot(members):
        values = []
        for pid in members[:8]:
            item = dict(pid=pid)
            try:
                text = Path('/proc', str(pid), 'stat').read_text()
                item.update(name=text.split('(', 1)[1].rsplit(')', 1)[0][:32],
                            state=text.rsplit(')', 1)[1].split()[0],
                            wait=Path('/proc', str(pid), 'wchan').read_text().strip()[:48])
            except (OSError, ValueError):
                item['state'] = 'unavailable'
            values.append(item)
        return values
    send(signal.SIGTERM)
    end = time.monotonic() + 10
    while owned_members() and time.monotonic() < end:
        time.sleep(.05)
    survivors = owned_members()
    clean = not survivors
    if not clean:
        if diagnostics is not None:
            diagnostics.update(grace_seconds=10, forced_kill=True,
                               survivors_before_kill=snapshot(survivors))
        send(signal.SIGKILL)
    for process in processes:
        process.wait(timeout=5)
    end = time.monotonic() + 2
    while owned_members() and time.monotonic() < end:
        time.sleep(.05)
    remaining = owned_members()
    if diagnostics is not None and (not clean or remaining):
        diagnostics.update(forced_kill=not clean, survivors_after_kill=snapshot(remaining),
                           child_exits=[dict(pid=p.pid, returncode=p.poll()) for p in processes[:8]])
    return clean and not remaining


def validate(value):
    """Host-safe success gate; CPU scheduler ticks are not gameplay tick counts."""
    required = {'exit_code', 'cleanup_complete', 'control', 'ready_seconds', 'baseline_seconds',
                'responsive_samples', 'cpu_ticks', 'clock_ticks_per_second',
                'fixture_manifest_sha256', 'binaries', 'database_cleanup', 'inserver_tests'}
    optional={'profiling','profile_processes'} if isinstance(value,dict) and 'profiling' in value else set()
    if not isinstance(value, dict) or set(value) not in (required | optional, required | optional | {'native_exit_codes'}):
        raise ValueError('Missing normal-world baseline')
    if 'native_exit_codes' in value:
        exits = value['native_exit_codes']
        if (not isinstance(exits, list) or len(exits) != 2
                or any(not isinstance(item, dict) or set(item) != {'name', 'returncode'}
                    or item['name'] != name or type(item['returncode']) is not int or item['returncode'] != 0
                    for name, item in zip(('world', 'zone'), exits))):
            raise ValueError('Sanitized native exit codes did not pass')
    if (type(value['exit_code']) is not int or value['exit_code'] != 0 or value['control'] is not None
            or value['cleanup_complete'] is not True or value['database_cleanup'] is not True):
        raise ValueError('Normal-world completion/cleanup')
    for name, low, high in [('ready_seconds', 0, OBSERVE_SECONDS), ('baseline_seconds', BASELINE_SECONDS, OBSERVE_SECONDS)]:
        number = value[name]
        if type(number) not in (int, float) or not math.isfinite(number) or not low <= number <= high:
            raise ValueError('Invalid normal-world timing')
    if (type(value['responsive_samples']) is not int or not 2 <= value['responsive_samples'] <= 1200
            or type(value['clock_ticks_per_second']) is not int or not 1 <= value['clock_ticks_per_second'] <= 10000
            or not isinstance(value['cpu_ticks'], list) or len(value['cpu_ticks']) != 2
            or any(type(t) is not int or not 0 <= t <= 10000000 for t in value['cpu_ticks'])
            or value['cpu_ticks'][1] <= 0):
        raise ValueError('Invalid normal-world activity')
    if (not isinstance(value['fixture_manifest_sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', value['fixture_manifest_sha256'])
            or not isinstance(value['binaries'], dict) or set(value['binaries']) != {'world', 'zone', 'shared_memory'}
            or any(not isinstance(d, str) or not re.fullmatch('[a-f0-9]{64}', d) for d in value['binaries'].values())):
        raise ValueError('Normal-world input/output identity')
    if optional and (not isinstance(value['profiling'],dict) or value['profiling'].get('complete') is not True):
        raise ValueError('Requested profiling incomplete')
    suite = validate_inserver(value['inserver_tests'])
    if suite['passed'] is not True:
        raise ValueError('In-server suite failed')
    return value


def observe(binary_dir, server, control, profile_config=None):
    """Unprivileged source-owned assertion with bounded diagnostics on every path."""
    if os.geteuid() == 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Unprivileged disposable guest only')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    processes = []
    profilers = []
    if profile_config is not None and os.environ.get('ASAN_OPTIONS'):
        raise RuntimeError('Sanitizers and profiling are mutually exclusive')
    profile = json.loads(Path(profile_config).read_text()) if profile_config else None
    logs = []
    cancelled = False
    ready = False
    run_id = os.urandom(16).hex()
    result_path = server / ('inserver-' + run_id + '.json')
    suite_snapshot = None
    observation = dict(condition="starting", last_success_ms=None)
    used_probe_ports = set()
    def cancel(*_):
        nonlocal cancelled
        cancelled = True
    prior = {sig: signal.signal(sig, cancel) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    result = dict(exit_code=2, cleanup_complete=False, control=control)
    start = time.monotonic()
    secrets = ()
    capture_error = None
    capture = FailureCapture(start) if os.environ.get('ASAN_OPTIONS') else None
    try:
        if os.environ.get('ASAN_OPTIONS'):
            secrets = read_observer_secrets()
        def guard():
            if cancelled:
                observation['condition'] = 'cancelled'
                raise RuntimeError('Normal-world cancellation')
            if time.monotonic() - start >= OBSERVE_SECONDS:
                observation['condition'] = 'deadline'
                error = InserverFailure if ready and control != 'cancel' else RuntimeError
                raise error('Normal-world deadline or missing in-server completion')
            polls = [p.poll() for p in processes] if capture else None
            if (any(code is not None for code in polls) if capture else any(p.poll() is not None for p in processes)):
                observation['condition'] = 'child-exit'
                if capture: capture.latch(processes, 'child-exit', polls)
                error = InserverFailure if ready else RuntimeError
                raise error('Normal server exited before assertion completed')
            if any(p.poll() is not None for p in profilers):
                raise RuntimeError('Requested perf collector exited early')
            if capture: capture.sample()
            if any(path.stat().st_size > 1024**2 for path in logs):
                observation['condition'] = 'console-budget'
                raise RuntimeError('Normal server console budget')
        def responsive():
            if not world_connected(processes[0].pid, processes[1].pid):
                observation['condition'] = 'world-connection-lost'
                return False
            observation['condition'] = 'udp-rejected'
            if not probe(used_ports=used_probe_ports, diagnostics=observation):
                return False
            observation.update(condition='responsive', last_success_ms=max(0, int((time.monotonic()-start)*1000)))
            return True
        if result_path.exists() or result_path.is_symlink():
            raise RuntimeError('In-server result path is not fresh')
        for name, args in (('world', []), ('zone', ['poknowledge', '7000'])):
            path = server / (name + '-console.log'); logs.append(path)
            with path.open('xb') as log:
                # Native config discovery searches cwd AND its immediate parent.
                # Keep both empty without moving/removing the positive fixture config.
                cwd = server
                if control == 'startup' and name == 'world':
                    cwd = server / 'missing-config' / 'world'; cwd.mkdir(parents=True)
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith('EQEMU_INSERVER_TEST_')}
                if name == 'zone':
                    env.update(EQEMU_INSERVER_TEST_RUN=run_id, EQEMU_INSERVER_TEST_RESULT=str(result_path))
                    if control == 'assertion':
                        env['EQEMU_INSERVER_TEST_CONTROL'] = 'assertion'
                if profile and profile['mode']=='heaptrack':
                    from profiling import TOOLS
                    env.update(LD_PRELOAD=TOOLS['heaptrack'][0], DUMP_HEAPTRACK_OUTPUT=str(Path(profile['directory'])/(name+'.fifo')))
                processes.append(subprocess.Popen([str(binary_dir / name), *args], cwd=cwd, env=env,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
                if profile and profile['mode']=='perf':
                    from profiling import perf_limits
                    profilers.append(subprocess.Popen(['/usr/bin/perf','record','-e','task-clock:u','-F','99',
                        '--call-graph','fp,32','--no-buildid-cache','-m','64','-o',
                        str(Path(profile['directory'])/(name+'.perf.data')),'-p',str(processes[-1].pid)],
                        stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,preexec_fn=perf_limits))
                if capture: capture.watch(name, processes[-1])
        while True:
            guard()
            if responsive():
                break
            time.sleep(.1)
        ready = True
        result['ready_seconds'] = round(time.monotonic() - start, 3)
        print('NORMAL_WORLD_READY', flush=True)
        before = [cpu_ticks(p.pid) for p in processes]
        baseline = time.monotonic(); samples = 0
        while time.monotonic() - baseline < BASELINE_SECONDS or control == 'cancel':
            guard()
            if not responsive():
                raise InserverFailure('Normal zone lost world connection or application responsiveness')
            samples += 1
            time.sleep(.1)
        delta = [cpu_ticks(p.pid) - tick for p, tick in zip(processes, before)]
        result.update(baseline_seconds=round(time.monotonic() - baseline, 3),
                      responsive_samples=samples, cpu_ticks=delta, clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
        while suite_snapshot is None:
            guard()
            suite_snapshot = read_inserver(result_path, run_id)
            if suite_snapshot is None:
                if not responsive():
                    raise InserverFailure('Normal zone lost responsiveness before suite completion')
                time.sleep(.1)
        suite = suite_snapshot[0]
        result['inserver_tests'] = suite
        if samples < 2 or delta[1] <= 0:
            result.update(exit_code=1, error='Normal-world readiness/activity assertion failed')
        elif not suite['passed']:
            result.update(exit_code=1, error='In-server test assertions failed')
        elif control is not None:
            raise InserverFailure('Qualification control unexpectedly completed')
        else:
            result['exit_code'] = 0
    except Exception as error:
        result.update(exit_code=1 if isinstance(error, InserverFailure) else 2, error=bounded_json_text(error, 500))
    finally:
        try:
            try:
                if capture:
                    category = observation['condition']
                    if result['exit_code'] != 0 and category in ('starting','responsive'): category = 'assertion'
                    capture.latch(processes, category)
                before_cleanup = failure_snapshot(processes, logs, run_id, start, observation, secrets, 2176 if capture else 0)
            except Exception as error:
                capture_error = 'pre-snapshot-unavailable'
                before_cleanup = dict(version=1, run_id=run_id, capture_error=capture_error)
            cleanup = {}
            if profile:
                result['profile_processes']=dict(before_cleanup=[dict(name=name,pid=p.pid,returncode=p.poll()) for name,p in zip(('world','zone'),processes)],
                    traces_may_be_incomplete=True, reason='Native shutdown is owned by existing cleanup, which may terminate profilers before finalization')
            try:
                try:
                    if profilers:
                        result['profile_processes']['perf_finalization_error']=finalize_collectors(processes,profilers)
                finally:
                    result['cleanup_complete'] = stop(processes, diagnostics=cleanup)
                for p in profilers: p.wait(timeout=5)
                if profile:
                    result['profile_processes']['after_cleanup']=[dict(name=name,pid=p.pid,returncode=p.poll()) for name,p in zip(('world','zone'),processes)]
                    result['profile_processes']['perf_exit_codes']=[p.returncode for p in profilers]
                if os.environ.get('ASAN_OPTIONS'):
                    # Sanitizers can report during graceful shutdown, after the
                    # source-owned suite already wrote its passed JSON frame.
                    result['native_exit_codes'] = [dict(name=name, returncode=process.poll())
                        for name, process in zip(('world', 'zone'), processes[:2])]
                    if any(item['returncode'] != 0 for item in result['native_exit_codes']):
                        result.update(exit_code=1, error='Sanitized native process exited nonzero during execution/shutdown')
            except Exception as error:
                result.update(exit_code=2, cleanup_complete=False, cleanup_error=bounded_json_text(error, 500))
                cleanup['error'] = result['cleanup_error']
            # Evidence capture is advisory and cannot overwrite stop's result.
            if capture:
                try: before_cleanup = failure_snapshot(processes, logs, run_id, start, observation, secrets, 2176)
                except Exception: capture_error = 'post-snapshot-unavailable'
            if result['cleanup_complete'] is not True:
                result['cleanup_diagnostics'] = cleanup
            if suite_snapshot is not None:
                try:
                    final = read_inserver(result_path, run_id)
                    if final is None or final != suite_snapshot:
                        raise InserverFailure('In-server result changed or disappeared after completion')
                except Exception as error:
                    result.update(exit_code=1, error=bounded_json_text(error, 500))
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
            for name, text in before_cleanup.get('console', {}).items():
                # The root adapter scrubs before persisting or exporting these bytes.
                print(name + ': ' + text, flush=True)
        if not result['cleanup_complete']:
            result['exit_code'] = 2
        if result['exit_code'] != 0:
            result['failure_evidence'] = before_cleanup
            if capture:
                result['pre_cleanup_observation'] = capture.pre
                try:
                    result['failure_resources'] = capture.finish()
                    validate_capture(result)
                except Exception:
                    result.pop('failure_resources', None)
                    try: validate_capture(result)
                    except Exception: result.pop('pre_cleanup_observation', None)
                    capture_error = 'resources-unavailable'
            if capture_error: result['capture_error'] = capture_error
    print('NORMAL_WORLD_RESULT ' + json.dumps(result, separators=(',', ':')), flush=True)



class EvidenceBudgetError(ValueError):
    """Irreducible artifact data cannot fit; the worker verdict remains intact."""


def export_evidence(report, head, directory):
    """Retain one private exact-candidate diagnostic using AFK's existing file contract."""
    if type(report.get('exit_code')) is not int or report['exit_code'] not in (0, 1, 2):
        return None
    normal = report.get('guest', {}).get('normal_world')
    if not isinstance(normal, dict):
        return None
    if (not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head)
            or report.get('candidate') != head or not isinstance(report.get('run_id'), str)
            or not re.fullmatch('[a-f0-9]{32}', report['run_id'])):
        raise ValueError('Native artifact candidate/run identity mismatch')
    validate_capture(normal)
    passed = report['exit_code'] == 0
    profile = report.get('diagnostic_profile')
    if profile:
        from sanitizers import PROFILE
        if profile != PROFILE: raise ValueError('Unknown diagnostic artifact profile')
    artifact = dict(schema_version=1, head=head, worker_run_id=report['run_id'],
                    exit_code=report['exit_code'], vm_cleanup_complete=report.get('cleanup_complete'),
                    normal_world=normal, advisory=True, truncated=False)
    if profile:
        sanitizer = report.get('guest', {}).get('sanitizers', {})
        artifact.update(diagnostic_profile=profile, sanitizer_identity={
            key: sanitizer[key] for key in ('environment', 'symbolizer', 'runtime_libraries', 'binaries',
                'compile_commands_sha256', 'exclusions', 'optimization_exceptions') if key in sanitizer},
            worker_implementation_sha256=report.get('implementation_sha256'),
            payload_sha256=report.get('payload_sha256'))
    artifact = json.loads(json.dumps(artifact))
    detail = artifact['normal_world'].get('failure_evidence', {})
    while len(encoded(artifact)) + 1 > EVIDENCE_LIMIT:
        artifact['truncated'] = True
        if not shrink_failure_evidence(detail):
            raise EvidenceBudgetError('irreducible-artifact-budget')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Hold the owned directory inode while writing fixed filenames. No final links,
    # devices or replacement of a previous invocation's evidence are permitted.
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    def write(name, value):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(value) + b'\n')
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('Native evidence directory must be owned and nonwritable by others')
        name = 'normal-world-' + (profile + '-' if profile else '') + ('success.json' if passed else 'failure.json')
        write(name, artifact)
        write('diagnostic-files.json', dict(schema_version=1, head=head, files=[name],
            sha256={name: hashlib.sha256(encoded(artifact) + b'\n').hexdigest()},
            **({'profile': profile} if profile else {})))
        condition = detail.get('observation', {}).get('condition')
        allowed = {'world-connection-lost', 'udp-timeout', 'udp-refused', 'udp-malformed-reply',
                   'udp-rejected', 'udp-allocation-exhausted', 'child-exit', 'deadline', 'cancelled', 'console-budget'}
        code = 'native-' + condition if condition in allowed else 'native-nonpass'
        write('public-summary.json', dict(schema_version=1, head=head, profile=profile or 'eqemu-worker', status='passed' if passed else 'failed',
            step='normal-world', diagnostic_codes=[] if passed else [code], timings_ms=dict(validation=None, restore=None)))
    finally:
        os.close(directory_fd)
    return directory/name


def run(build, identity):
    """Reuse the identified public fixture; preparation is never a host recipe."""
    from actor_runtime import Runtime, ROOT, MEDIA
    if os.geteuid() != 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Disposable build guest only')
    if build.DEADLINE - time.monotonic() < SECONDS:
        raise RuntimeError('Insufficient remaining normal-world runtime budget')
    fixture = json.loads(Path('/opt/runtime-fixture.json').read_text())
    control = identity.get('world_control')
    if control not in (None, 'startup', 'assertion', 'cancel'):
        raise RuntimeError('Unknown normal-world control')
    # Existing helper has its own explicit guest budget, allocation guards and redaction.
    ROOT.mkdir(mode=0o755)
    runtime = Runtime(build, None, fixture)
    prior = {sig: signal.signal(sig, lambda *_: setattr(runtime, 'cancelled', True))
             for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    clean = False
    result = None
    error = None
    profiling_session = None
    profile_result = None
    kernel = None
    capture_error = None
    binaries = {name: build.sha(build.WORK / 'build/bin' / name) for name in ('world', 'zone', 'shared_memory')}
    try:
        MEDIA.mkdir()
        runtime.command('normal-mount-runtime', ['mount', '-o', 'loop,ro,nosuid,nodev,noexec',
                        '/media/eqemu-input/runtime.iso', str(MEDIA)])
        runtime.verify_inputs()
        runtime.install_packages()
        runtime.initialize_database(); runtime.import_database()
        # Native Zone construction reads the selected zone row, not a rule_values
        # entry. Disable idle processing before boot; seconds_before_idle is then
        # irrelevant. Match the exact default PoK row verified by import_database.
        runtime.query('normal-activity', "UPDATE zone SET idle_when_empty=0 WHERE zoneidnumber=202 AND version=0 AND short_name='poknowledge';")
        if runtime.query('normal-activity-check', "SELECT zoneidnumber,version,short_name,idle_when_empty FROM zone WHERE zoneidnumber=202 AND version=0 AND short_name='poknowledge';").strip() != '202\t0\tpoknowledge\t0':
            raise RuntimeError('Empty-zone activity configuration missing')
        server = runtime.configure()
        # Freeze the authoritative values before ownership transfer or any native
        # execution. Candidate configuration changes cannot replace this snapshot.
        credential_snapshot = encoded(tuple(runtime.secrets)) if build.ENV.get('ASAN_OPTIONS') else None
        config_path = server / 'eqemu_config.json'
        config = json.loads(config_path.read_text())
        config['server']['world']['loginserver'] = {'host': '127.0.0.1', 'port': '5998', 'account': '', 'password': ''}
        config_path.write_text(json.dumps(config))
        account = pwd.getpwnam('nobody')
        # Only the disposable runtime belongs to the native user, not tools or source.
        for path in [server, *server.rglob('*')]:
            if not path.is_symlink():
                os.chown(path, account.pw_uid, account.pw_gid)
        prefix = ['/usr/bin/setpriv', '--reuid=' + str(account.pw_uid), '--regid=' + str(account.pw_gid),
                  '--clear-groups', '--no-new-privs']
        if identity.get('profiling'):
            from profiling import Session, tool
            mode=identity['profiling']
            profiling_session=Session(mode, build.WORK/'profiles', {name:build.WORK/'build/bin'/name for name in ('world','zone')},
                account.pw_uid, min(build.DEADLINE,time.monotonic()+SECONDS),
                dict(source=identity, build=build.BUILD_METADATA, workload=dict(name='master-normal-world',control=control,
                    warmup='readiness probe',repetitions=1,baseline_seconds=BASELINE_SECONDS,comparison=False),
                    fixture_manifest_sha256=fixture['manifest_sha256'])).start()
            if mode=='perf':
                from profiling import perf_preflight
                check=perf_preflight(build.WORK/'perf-preflight',account.pw_uid,prefix)
                from profiling import write_json
                try: policy=Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip()
                except OSError: policy=None
                profiling_session.preflight=dict(exit_code=check,event='task-clock:u',uid=account.pw_uid,perf_event_paranoid=policy)
                write_json(profiling_session.directory/'preflight.json',profiling_session.preflight)
                shutil.copyfile(build.WORK/'perf-preflight.log',profiling_session.directory/'perf-preflight.analysis')
                if check: raise RuntimeError('Requested perf mode unavailable for guest event task-clock:u under native identity')
            profiling_session.stage('shared-memory','started')
        runtime.command('normal-shared-memory', [*prefix, str(build.WORK / 'build/bin/shared_memory')], cwd=server, timeout=180)
        for name in ('items', 'spells'):
            path = server / 'shared' / name
            if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 768*1024**2:
                raise RuntimeError('Missing generated shared data: ' + name)
        if profiling_session: profiling_session.stage('shared-memory','completed')
        ready = False
        def phase(line):
            nonlocal ready
            if line == b'NORMAL_WORLD_READY':
                if ready:
                    raise RuntimeError('Duplicate normal-world readiness phase')
                ready = True
                if profiling_session:
                    profiling_session.stage('startup','completed')
                    profiling_session.stage('ready','completed')
                build.emit({'kind': 'stage', 'name': 'normal-world-ready', 'state': 'started'})
        if profiling_session: profiling_session.stage('startup','started')
        if credential_snapshot is not None:
            try: kernel = KernelOOM()
            except Exception: capture_error = 'kernel-init-unavailable'
        with (observer_credential_pipe(credential_snapshot) if credential_snapshot is not None
              else nullcontext()) as credentials:
            output = runtime.command('normal-world', [*prefix, '/usr/bin/python3', '/opt/normal_world.py',
                                      str(build.WORK / 'build/bin'), str(server), control or 'positive',
                                      *([str(profiling_session.directory/'config.json')] if profiling_session else [])],
                                     timeout=OBSERVE_SECONDS+30, on_line=phase,
                                     **({'stdin': credentials} if credentials is not None else {}))
        frames = [json.loads(line.removeprefix('NORMAL_WORLD_RESULT ')) for line in output.splitlines()
                  if line.startswith('NORMAL_WORLD_RESULT ')]
        if len(frames) != 1:
            raise RuntimeError('Missing/duplicate normal-world assertion completion')
        result = json.loads(runtime.scrub(json.dumps(frames[0], separators=(',', ':'))))
        if isinstance(result, dict):
            try: validate_capture(result)
            except Exception:
                capture_error = capture_error or 'root-capture-unavailable'
                # Retain independently valid observer facts, never malformed raw
                # telemetry. Resource identities must still match a retained latch.
                retained = {}
                for field in ('pre_cleanup_observation', 'failure_resources'):
                    if field not in result: continue
                    candidate = dict(retained, **{field: result[field]})
                    try: validate_capture(candidate)
                    except Exception: continue
                    retained = candidate
                for field in ('pre_cleanup_observation', 'failure_resources', 'capture_error'):
                    result.pop(field, None)
                result.update(retained)
            if kernel is not None and isinstance(result.get('failure_resources'), dict):
                try:
                    # Publish only after the complete merge is bounded and valid.
                    merged = dict(result)
                    resources = dict(result['failure_resources'])
                    resources['kernel'] = kernel.finish([p['pid'] for p in resources['processes']])
                    merged['failure_resources'] = fit_resources(resources,
                        min(1536, 2048-len(encoded(result.get('pre_cleanup_observation')))-60))
                    validate_capture(merged)
                except Exception: capture_error = capture_error or 'kernel-merge-unavailable'
                else: result = merged
        if (not isinstance(result, dict) or type(result.get('exit_code')) is not int
                or result['exit_code'] not in (0, 1, 2) or result.get('cleanup_complete') is not True):
            # Keep the observer's own cleanup evidence. Host VM destruction is a
            # separate cleanup layer and cannot make this native result clean.
            if isinstance(result, dict):
                observed = {key: result.get(key) for key in
                            ('exit_code', 'cleanup_complete', 'cleanup_diagnostics', 'control', 'error')}
                suite = result.get('inserver_tests')
                if isinstance(suite, dict):
                    observed['inserver_tests'] = {key: suite.get(key) for key in
                        ('selected', 'started', 'completed', 'failed', 'finalized', 'passed')}
                    tests = suite.get('tests')
                    if isinstance(tests, list):
                        observed['inserver_tests']['tests'] = [
                            {key: test.get(key) for key in ('name', 'passed', 'diagnostic')}
                            for test in tests[:3] if isinstance(test, dict)]
            else:
                observed = result
            detail = runtime.scrub(json.dumps(observed, separators=(',', ':')))[:2400]
            raise RuntimeError('Incomplete normal-world cleanup/result; observer=' + detail)
        if control is not None and result['exit_code'] == 0:
            raise RuntimeError('Qualification control cannot pass')
        runtime.verify_inputs()
        for name, digest in binaries.items():
            if build.sha(build.WORK / 'build/bin' / name) != digest:
                raise RuntimeError('Candidate executable changed: ' + name)
    except Exception as exc:
        error = runtime.scrub(str(exc))[-3000:]
    finally:
        try:
            if kernel is not None: kernel.close()
        except Exception: capture_error = capture_error or 'kernel-close-unavailable'
        # Advisory descriptor failures cannot prevent authoritative cleanup.
        try:
            clean = runtime.cleanup()
        except Exception as exc:
            clean = False
            error = runtime.scrub(str(exc))[-1000:]
        finally:
            if profiling_session:
                try:
                    profile_result=profiling_session.finish(
                        collector_exit_codes=(result or {}).get('profile_processes',{}).get('perf_exit_codes'),
                        collector_finalization_error=(result or {}).get('profile_processes',{}).get('perf_finalization_error'))
                    if not profile_result['complete']:
                        error=error or 'Requested profiling incomplete: '+str(profile_result.get('error') or 'artifact truncated')
                except Exception as exc:
                    error=error or 'Requested profiling finalization failed: '+type(exc).__name__
                    profile_result=dict(mode=identity['profiling'],complete=False,error=type(exc).__name__)
            for sig, handler in prior.items():
                signal.signal(sig, handler)
    if profile_result is not None and result is None:
        result=dict(exit_code=2,cleanup_complete=False,control=control)
    if isinstance(result, dict):
        if profile_result is not None: result['profiling']=profile_result
        result.update(fixture_manifest_sha256=fixture['manifest_sha256'], binaries=binaries, database_cleanup=clean)
        if capture_error and result.get('exit_code') != 0:
            result['capture_error'] = capture_error
        if error:
            result['adapter_error'] = bounded_json_text(error, 1000)
    if error or not clean or result is None:
        failure = RuntimeError('Normal-world fixture: ' + (error or 'Database/native cleanup incomplete'))
        failure.result = result
        raise failure
    if result['exit_code'] == 1:
        failure = build.CandidateFailure('Normal-world assertion failed: ' + runtime.scrub(output)[-3000:])
        failure.result = result
        raise failure
    if result['exit_code'] != 0:
        failure = RuntimeError('Normal-world non-pass: ' + runtime.scrub(output)[-3000:])
        failure.result = result
        raise failure
    return validate(result)


if __name__ == '__main__':
    observe(Path(sys.argv[1]), Path(sys.argv[2]), None if sys.argv[3] == 'positive' else sys.argv[3], sys.argv[4] if len(sys.argv)>4 else None)
