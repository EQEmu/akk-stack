"""Fixed disposable normal-world fixture. Never execute candidate code on the host.

Root prepares public data; the observer and all three native executables run as
nobody in the offline guest. The observer uses kernel-owned socket identities and
an echoed EQ stream session challenge, not startup log strings.
"""
import hashlib
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


def failure_snapshot(processes, logs, run_id, start, observation):
    """Snapshot before TERM/KILL; later shutdown chatter cannot replace this evidence."""
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
            evidence['console'][path.name] = bounded_text(data.decode(errors='replace'), 2500)
            evidence['console_truncated'][path.name] = len(data) > 2500
            if path.name == 'zone-console.log':
                evidence['progress'] = case_progress(data, run_id)
                source = source_diagnostics(data)
                if source is not None:
                    evidence['source_diagnostics'] = source
        except (OSError, ValueError) as error:
            evidence['console'][path.name] = bounded_text('unavailable: ' + str(error), 256)
    # Bound JSON-encoded bytes, including escaping of hostile console text.
    evidence['truncated'] = False
    while len(encoded(evidence)) > 12000:
        evidence['truncated'] = True
        name = max(evidence['console'], key=lambda name: len(evidence['console'][name]), default=None)
        if name is None or not evidence['console'][name]:
            raise ValueError('Failure metadata exceeds evidence budget')
        evidence['console'][name] = bounded_text(evidence['console'][name], len(evidence['console'][name].encode())//2)
        evidence['console_truncated'][name] = True
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
    if not isinstance(value, dict) or set(value) not in (required, required | {'native_exit_codes'}):
        raise ValueError('Missing normal-world baseline')
    if 'native_exit_codes' in value and value['native_exit_codes'] != [
            dict(name='world', returncode=0), dict(name='zone', returncode=0)]:
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
    suite = validate_inserver(value['inserver_tests'])
    if suite['passed'] is not True:
        raise ValueError('In-server suite failed')
    return value


def observe(binary_dir, server, control):
    """Unprivileged source-owned assertion with bounded diagnostics on every path."""
    if os.geteuid() == 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Unprivileged disposable guest only')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    processes = []
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
    try:
        def guard():
            if cancelled:
                observation['condition'] = 'cancelled'
                raise RuntimeError('Normal-world cancellation')
            if time.monotonic() - start >= OBSERVE_SECONDS:
                observation['condition'] = 'deadline'
                error = InserverFailure if ready and control != 'cancel' else RuntimeError
                raise error('Normal-world deadline or missing in-server completion')
            if any(p.poll() is not None for p in processes):
                observation['condition'] = 'child-exit'
                error = InserverFailure if ready else RuntimeError
                raise error('Normal server exited before assertion completed')
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
                processes.append(subprocess.Popen([str(binary_dir / name), *args], cwd=cwd, env=env,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
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
                before_cleanup = failure_snapshot(processes, logs, run_id, start, observation)
            except Exception as error:
                before_cleanup = dict(version=1, run_id=run_id, capture_error=bounded_text(error, 256))
            cleanup = {}
            try:
                result['cleanup_complete'] = stop(processes, diagnostics=cleanup)
                if os.environ.get('ASAN_OPTIONS'):
                    # Sanitizers can report during graceful shutdown, after the
                    # source-owned suite already wrote its passed JSON frame.
                    result['native_exit_codes'] = [dict(name=name, returncode=process.poll())
                        for name, process in zip(('world', 'zone'), processes[:2])]
                    if any(item['returncode'] != 0 for item in result['native_exit_codes']):
                        result.update(exit_code=1, error='Sanitized native process exited nonzero during execution/shutdown')
                    before_cleanup = failure_snapshot(processes, logs, run_id, start, observation)
            except Exception as error:
                result.update(exit_code=2, cleanup_complete=False, cleanup_error=bounded_json_text(error, 500))
                cleanup['error'] = result['cleanup_error']
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
    print('NORMAL_WORLD_RESULT ' + json.dumps(result, separators=(',', ':')), flush=True)



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
    passed = report['exit_code'] == 0
    artifact = dict(schema_version=1, head=head, worker_run_id=report['run_id'],
                    exit_code=report['exit_code'], vm_cleanup_complete=report.get('cleanup_complete'),
                    normal_world=normal, advisory=True, truncated=False)
    artifact = json.loads(json.dumps(artifact))
    detail = artifact['normal_world'].get('failure_evidence', {})
    console = detail.get('console', {})
    while len(encoded(artifact)) + 1 > EVIDENCE_LIMIT:
        artifact['truncated'] = True
        if isinstance(console, dict) and any(isinstance(text, str) and text for text in console.values()):
            name = max(console, key=lambda name: len(console[name]) if isinstance(console[name], str) else 0)
            console[name] = bounded_text(console[name], len(console[name].encode())//2)
            detail.setdefault('console_truncated', {})[name] = True
        else:
            raise ValueError('Structured native evidence exceeds artifact budget')
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
        name = 'normal-world-success.json' if passed else 'normal-world-failure.json'
        write(name, artifact)
        write('diagnostic-files.json', dict(schema_version=1, head=head, files=[name],
            sha256={name: hashlib.sha256(encoded(artifact) + b'\n').hexdigest()}))
        condition = detail.get('observation', {}).get('condition')
        allowed = {'world-connection-lost', 'udp-timeout', 'udp-refused', 'udp-malformed-reply',
                   'udp-rejected', 'udp-allocation-exhausted', 'child-exit', 'deadline', 'cancelled', 'console-budget'}
        code = 'native-' + condition if condition in allowed else 'native-nonpass'
        write('public-summary.json', dict(schema_version=1, head=head, profile='eqemu-worker', status='passed' if passed else 'failed',
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
        runtime.command('normal-shared-memory', [*prefix, str(build.WORK / 'build/bin/shared_memory')], cwd=server, timeout=180)
        for name in ('items', 'spells'):
            path = server / 'shared' / name
            if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 768*1024**2:
                raise RuntimeError('Missing generated shared data: ' + name)
        ready = False
        def phase(line):
            nonlocal ready
            if line == b'NORMAL_WORLD_READY':
                if ready:
                    raise RuntimeError('Duplicate normal-world readiness phase')
                ready = True
                build.emit({'kind': 'stage', 'name': 'normal-world-ready', 'state': 'started'})
        output = runtime.command('normal-world', [*prefix, '/usr/bin/python3', '/opt/normal_world.py',
                                  str(build.WORK / 'build/bin'), str(server), control or 'positive'],
                                 timeout=OBSERVE_SECONDS+30, on_line=phase)
        frames = [json.loads(line.removeprefix('NORMAL_WORLD_RESULT ')) for line in output.splitlines()
                  if line.startswith('NORMAL_WORLD_RESULT ')]
        if len(frames) != 1:
            raise RuntimeError('Missing/duplicate normal-world assertion completion')
        result = json.loads(runtime.scrub(json.dumps(frames[0], separators=(',', ':'))))
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
            clean = runtime.cleanup()
        except Exception as exc:
            clean = False
            error = runtime.scrub(str(exc))[-1000:]
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
    if isinstance(result, dict):
        result.update(fixture_manifest_sha256=fixture['manifest_sha256'], binaries=binaries, database_cleanup=clean)
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
    observe(Path(sys.argv[1]), Path(sys.argv[2]), None if sys.argv[3] == 'positive' else sys.argv[3])
