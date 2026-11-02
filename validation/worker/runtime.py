#!/usr/bin/python3 -I
"""One offline VM under a dedicated worker. Candidate code runs only in the guest."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guest import user_data, build_user_data, format_user_data, quick_user_data, BUILD_CHECKS

CONFIG = Path('/etc/eqemu-validator/config.json')
QEMU = '/usr/bin/qemu-system-x86_64'
QEMU_IMG = '/usr/bin/qemu-img'
GENISOIMAGE = '/usr/bin/genisoimage'
SECONDS = 300
LOG_LIMIT = 1024**2
BUILD_SECONDS = 18000
PAYLOAD_LIMIT = 1024**3
BASE_LIMIT = 2 * 1024**3
CONTROLS = ('pass', 'assertion', 'missing-result', 'deadline', 'controller-death')
OWNED_CONTROLS = (*CONTROLS, 'build', 'format', 'check-format', 'quick')
FORMAT_SECONDS = 900
IMPLEMENTATION_FILES = ('validation/worker/runtime.py', 'validation/worker/guest.py',
    'validation/worker/profile_contract.py', 'validation/worker/profiling.py', 'validation/worker/profile_artifacts.py', 'validation/worker/profile_inputs.py',
    'validation/worker/build_guest.py', 'validation/worker/normal_world.py', 'validation/actor.py',
    'validation/actor_runtime.py', 'validation/debugger.py', 'validation/runtime-fixture.json',
    'validation/worker/client.py', 'scripts/check-validation-worker',
    'validation/worker/format_guest.py', 'validation/worker/snapshot.py',
    'validation/worker/quick_guest.py', 'validation/worker/quick_snapshot.py')


class CleanupError(RuntimeError):
    pass
SCRATCH = ('disk.qcow2', 'seed.iso', 'user-data', 'meta-data', 'payload.iso')


def read_json(path, limit=16384):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('JSON size limit: ' + str(path))
    return json.loads(data)


def root_file(path):
    """Configuration and the public base are selected outside worker control."""
    path = Path(path)
    if not path.is_absolute() or any(ch in str(path) for ch in ',\n\r'):
        raise ValueError('Unsupported absolute path')
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('Expected root-owned nonwritable input: ' + str(parent))
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected regular input: ' + str(path))
    return path


def config(path=CONFIG):
    value = read_json(root_file(path))
    required = {'version', 'user', 'worker_uid', 'worker_gid', 'state_dir', 'code_dir', 'submitter', 'socket', 'base_image'}
    from profile_contract import EXTRA_FIELDS, validate as validate_profile, verify_release
    profiling=value.get('selection')=='profiling-v1'
    if set(value) != required | (EXTRA_FIELDS if profiling else set()) or type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Unsupported worker configuration')
    if profiling:
        validate_profile(value,path,read_json(root_file(CONFIG)))
        verify_release(value,root_file)
    for key in ('state_dir', 'code_dir', 'socket', 'base_image'):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute() or any(ch in value[key] for ch in ',\n\r'):
            raise ValueError('Unsupported configured path: ' + key)
    account = pwd.getpwnam(value['user'])
    if (account.pw_uid == 0 or account.pw_uid != value['worker_uid'] or account.pw_gid != value['worker_gid']
            or os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid):
        raise ValueError('Runtime must run as the configured nonroot worker')
    state = Path(value['state_dir'])
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Worker state must be a private owned directory')
    if state.resolve() != state or Path(value['code_dir']).resolve() != Path(value['code_dir']):
        raise ValueError('Worker paths must not traverse symlinks')
    return value


def service_cgroup():
    """Locate this invocation's actual cgroup, shared by its child processes."""
    location = Path('/proc/self/cgroup').read_text().strip().splitlines()
    row = next(line for line in location if line.startswith('0::'))
    relative = row[3:].lstrip('/')
    if '..' in Path(relative).parts:
        raise ValueError('Unexpected cgroup path')
    return Path('/sys/fs/cgroup') / relative


def service_processes():
    return sorted(int(pid) for pid in (service_cgroup() / 'cgroup.procs').read_text().split())


def resource_state():
    """Observe the actual service cgroup, including children, rather than unit text."""
    root = service_cgroup()
    values = {name: (root / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    values.update(no_new_privileges=status['NoNewPrivs'].strip(), effective_capabilities=status['CapEff'].strip())
    return values


def ready(value):
    observed = {'uid': os.geteuid(), 'gid': os.getegid(), 'user': pwd.getpwuid(os.geteuid()).pw_name}
    checks = {}
    try:
        observed['invocation_id'] = invocation(); checks['systemd_invocation'] = True
    except ValueError:
        checks['systemd_invocation'] = False
    for name, tool in (('qemu', QEMU), ('qemu_img', QEMU_IMG), ('genisoimage', GENISOIMAGE)):
        checks[name] = os.path.isfile(tool) and os.access(tool, os.X_OK)
    try:
        fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
        checks['kvm'] = True
    except OSError:
        checks['kvm'] = False
    try:
        observed['apparmor'] = Path('/proc/self/attr/current').read_text().strip()
        # An unconfined stack member does not remove the enforcing profile's restrictions.
        name='eqemu-validator-profiling' if value.get('selection')=='profiling-v1' else 'eqemu-validator'
        checks['apparmor'] = observed['apparmor'] in (
            name+' (enforce)',name+'//&unconfined (enforce)','unconfined//&'+name+' (enforce)',
        )
    except OSError:
        checks['apparmor'] = False
    try:
        limits = resource_state(); observed['resources'] = limits
        quota, period = limits['cpu.max'].split()
        checks['resources'] = (0 < int(limits['memory.max']) <= 6 * 1024**3 and limits['memory.swap.max'] == '0'
                               and 0 < int(limits['pids.max']) <= 128 and 0 < int(quota) <= 2 * int(period)
                               and limits['no_new_privileges'] == '1' and int(limits['effective_capabilities'], 16) == 0)
    except (OSError, ValueError, KeyError, StopIteration):
        checks['resources'] = False
    try:
        base = root_file(value['base_image'])
        checks['public_base'] = 0 < base.stat().st_size <= BASE_LIMIT and os.access(base, os.R_OK)
    except (OSError, ValueError):
        checks['public_base'] = False
    home = pwd.getpwnam(value['submitter']).pw_dir
    checks['submitter_home_hidden'] = not os.access(home, os.R_OK | os.X_OK)
    return {'version': 1, 'operation': 'check', 'scope': 'worker-readiness', 'exit_code': 0 if all(checks.values()) else 2,
            'checks': checks, 'observed': observed, 'vm_started': False, 'execution_qualified': False}


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('Unexpected worker temporary record')
        json.dump(value, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def persisted_report(report):
    """Last-result is an observation, never a second export of source bytes."""
    if report.get('scope') not in ('working-snapshot-format','working-snapshot-quickcheck'):
        return report
    value = dict(report)
    # Rustfmt diagnostics can contain private source lines and diffs. Retain them
    # only in the explicit private invocation artifact and owned serial log.
    value.pop('error', None)
    value.pop('cleanup_error', None)
    if report.get('scope')=='working-snapshot-quickcheck':
        value['checks']=[{key:item[key] for key in ('name','status','reason','seconds')} for item in report.get('checks',[])]
        native=report.get('native_scope',{})
        value['native_scope']=dict(changed_translation_unit_count=len(native.get('changed_translation_units',[]))+native.get('omitted_translation_units',0),
            selected_object_count=len(native.get('selected_objects',[])),limitation_count=len(native.get('limitations',[]))+native.get('omitted_limitations',0))
    if report.get('exit_code') != 0:
        prefix='quick' if report.get('scope')=='working-snapshot-quickcheck' else 'formatter'
        value['failure_class'] = prefix+('-candidate-failure' if report.get('exit_code') == 1 else
                                       '-infrastructure-failure' if report.get('cleanup_complete') is True else '-cleanup-unconfirmed')
    value['changed_files'] = [{key: item[key] for key in ('path', 'before_sha256', 'after_sha256')}
                              for item in report.get('changed_files', [])]
    # Keep the established read-only last-result protocol below 16 KiB too.
    if len(json.dumps(value).encode()) > 15000:
        value['changed_files'] = []
        value['changed_file_count'] = len(report.get('changed_files', []))
    return value


def acquire(value):
    from profile_contract import SHARED_LOCK
    profiling=value.get('selection')=='profiling-v1'
    if profiling and value.get('shared_lock')!=SHARED_LOCK: raise ValueError('Unexpected shared profiling lock')
    path=Path(SHARED_LOCK) if profiling else Path(value['state_dir'])/'worker.lock'
    if profiling and path.resolve()!=path: raise ValueError('Shared lock path traverses a symlink')
    fd=os.open(path,os.O_RDWR | os.O_NOFOLLOW | (0 if profiling else os.O_CREAT),0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=value['worker_uid'] or info.st_gid!=value['worker_gid'] or stat.S_IMODE(info.st_mode)!=0o600:
            raise ValueError('Worker lock must be an owned regular mode-0600 file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise RuntimeError('Another worker operation is active')
    return fd


def scratch_cleanup(job):
    scratch = job / 'scratch'
    if scratch.exists():
        if scratch.is_symlink() or scratch.stat().st_uid != os.geteuid():
            raise RuntimeError('Unexpected worker scratch ownership')
        if not {item.name for item in scratch.iterdir()} <= set(SCRATCH) | {'profile-requested'}:
            raise RuntimeError('Unexpected worker scratch contents')
        for item in scratch.iterdir():
            if item.is_symlink() or not item.is_file():
                raise RuntimeError('Unexpected worker scratch file')
            item.unlink()
        scratch.rmdir()


def invocation():
    identity = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch('[a-f0-9]{32}', identity):
        raise ValueError('Worker requires its systemd invocation identity')
    return identity


def cleanup(value):
    """ExecStopPost recovers this invocation only; checks never mutate older jobs."""
    active = Path(value['state_dir']) / 'active.json'
    if not active.exists():
        return 0
    if read_json(active).get('invocation_id') != invocation():
        return 0
    try:
        lock = acquire(value)
    except RuntimeError:
        return 0  # Another accepted connection owns the active run.
    try:
        active = Path(value['state_dir']) / 'active.json'
        if active.exists():
            record = read_json(active)
            if (set(record) != {'run_id', 'invocation_id', 'control', 'qemu_pid'}
                    or record['invocation_id'] != invocation()
                    or record['control'] not in OWNED_CONTROLS
                    or (record['qemu_pid'] is not None and (type(record['qemu_pid']) is not int or record['qemu_pid'] <= 0))
                    or not re.fullmatch('[a-f0-9]{32}', record['run_id'])):
                raise ValueError('Unexpected active job record')
            job = Path(value['state_dir']) / record['run_id']
            operation = {'build': 'build', 'format': 'format', 'check-format': 'check','quick':'quick'}.get(record['control'], 'smoke')
            report = {'version': 1, 'operation': operation,
                      'scope': 'working-snapshot-quickcheck' if record['control']=='quick' else
                               'working-snapshot-format' if record['control'] in ('format', 'check-format') else
                               'worker-build' if record['control'] == 'build' else 'worker-smoke', 'run_id': record['run_id'],
                      'control': record['control'], 'qemu_pid': record['qemu_pid'],
                      'vm_started': record['qemu_pid'] is not None, 'exit_code': 2,
                      'error': 'Controller stopped before final completion',
                      'cleanup_complete': False, 'scratch_removed': False}
            try:
                processes = service_processes()
                report['service_processes'] = processes
                report['only_cleanup_process_remains'] = processes == [os.getpid()]
                if not report['only_cleanup_process_remains']:
                    raise CleanupError('Service cgroup still contains another process')
                if job.exists():
                    if job.is_symlink() or not job.is_dir() or job.stat().st_uid != os.geteuid():
                        raise ValueError('Unexpected active job directory')
                    scratch_cleanup(job)
                report['scratch_removed'] = True
            except (OSError, ValueError, CleanupError) as error:
                report['cleanup_error'] = str(error)[:1000]
            if (job/'profiles').exists():
                retain_profiles(job,Path(value['state_dir']),job.name,report)
            atomic_json(Path(value['state_dir']) / 'last-result.json', report)
            if not report['scratch_removed']:
                return 2  # Retain the active marker and scratch when process absence is uncertain.
            if (job / 'serial.log').exists():
                os.replace(job / 'serial.log', Path(value['state_dir']) / 'last-serial.log')
            if job.exists():
                job.rmdir()
            active.unlink()
        return 0
    finally:
        os.close(lock)


def tool(args, deadline):
    remaining = min(30, deadline - time.monotonic())
    if remaining <= 0:
        raise RuntimeError('Worker deadline exceeded')
    # Tools share the same owned-session cleanup as QEMU; descendants cannot outlive a timeout.
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True)
    try:
        code = process.wait(timeout=remaining)
        if code:
            raise RuntimeError(Path(args[0]).name + ': exit ' + str(code))
    finally:
        stop_process(process)


def disconnected(connection):
    try:
        value = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        if value:
            raise RuntimeError('Unexpected extra client data')
        return True
    except BlockingIOError:
        return False


def stop_process(process):
    """Always reap QEMU and its owned session, including exceptional exits."""
    try:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        raise CleanupError('Owned process group remains')
    except CleanupError:
        raise
    except BaseException as error:
        # Signal handlers and interpreter cancellation can interrupt kill/wait too.
        # Until every cleanup step returns, callers must retain the owned scratch.
        raise CleanupError('Owned process cleanup could not be confirmed') from error


def supervise(args, scratch, log, connection, deadline, nonce, on_started=None, build_result=None, format_result=None, quick_result=None):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               cwd=scratch, start_new_session=True, close_fds=True,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(scratch)})
    output = bytearray()
    pending = bytearray()
    discarding = False
    notified = False
    profile_sink = None
    profile_error = None
    profile_mode = None
    if build_result is not None and (scratch/'profile-requested').exists():
        from profile_artifacts import Sink
        profile_sink=Sink(scratch.parent/'profiles')
        profile_request=json.loads((scratch/'profile-requested').read_text())
        profile_mode=profile_request['profiling']
    started_at = time.monotonic()
    try:
        if on_started is not None:
            if process.poll() is not None:
                raise RuntimeError('QEMU exited before ownership was recorded')
            on_started(process.pid)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector, log.open('xb') as stream:
            selector.register(process.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Worker deadline exceeded')
                if disconnected(connection):
                    raise RuntimeError('Client disconnected; worker cancelled')
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        eof = True; selector.unregister(key.fileobj)
                        continue
                    if stream.tell() + len(block) > (64 * LOG_LIMIT if build_result is not None or format_result is not None or quick_result is not None else LOG_LIMIT):
                        raise RuntimeError('Worker serial output limit exceeded')
                    output.extend(block); stream.write(block); stream.flush()
                    if (format_result is not None and 'boot_seconds' not in format_result
                            and b'EQEMU_STAGE mount-job' in output):
                        format_result['boot_seconds'] = round(time.monotonic() - started_at, 3)
                    if quick_result is not None and 'boot_seconds' not in quick_result and b'EQEMU_STAGE mount-job' in output:
                        quick_result['boot_seconds']=round(time.monotonic()-started_at,3)
                    if build_result is not None:
                        pending.extend(block)
                        while b'\n' in pending:
                            line, _, rest = pending.partition(b'\n')
                            pending = bytearray(rest)
                            if (not discarding and not notified and line.rstrip(b'\r') ==
                                    b'EQEMU_RUNTIME {"kind":"stage","name":"normal-world-ready","state":"started"}'):
                                notified = True
                                # Advisory only, never completion evidence. Bound socket backpressure.
                                connection.settimeout(1)
                                try:
                                    connection.sendall(b'{"version":1,"kind":"progress","name":"normal-world-ready"}\n')
                                finally:
                                    connection.settimeout(None)
                            if not discarding and profile_sink is not None and line.startswith(b'EQEMU_PROFILE '):
                                try:
                                    profile_sink.accept(json.loads(line.removeprefix(b'EQEMU_PROFILE ')))
                                except Exception as error:
                                    profile_error=type(error).__name__
                            discarding = False
                        # Ignore oversized serial lines; never forward guest text.
                        if len(pending) > 65536:
                            pending.clear()
                            discarding = True

                    if ((build_result is not None or format_result is not None or quick_result is not None)
                            and b'cc_scripts_user.py[WARNING]: Failed to run module scripts_user' in output):
                        # Cloud-init has returned from our command. An idle login
                        # prompt cannot complete the job; retain diagnostics and fail now.
                        raise RuntimeError('Guest cloud-init command failed before shutdown: '
                                           + output[-900:].decode(errors='replace').strip())
                    # Keep only the diagnostic tail in RAM; complete console output stays bounded on disk.
                    del output[:-16384]
            code = process.wait(timeout=5)
            if code != 0:
                detail = output[-900:].decode(errors='replace').strip()
                raise RuntimeError('QEMU exited ' + str(code) + ': ' + detail)
    finally:
        stop_process(process)
        process.stdout.close()
        if profile_sink is not None:
            build_result['profile_transport']=dict(artifacts=profile_sink.inventory(),export_error=profile_error,
                complete=False,partial=True)
    results = []
    with log.open('rb') as stream:
        for line in stream:
            if quick_result is not None and line.startswith(b'EQEMU_QUICK_RESULT '):
                from quick_snapshot import RESULT_LIMIT
                if len(line)>RESULT_LIMIT*2:raise RuntimeError('Oversized quick completion')
                results.append(json.loads(base64.b64decode(line.removeprefix(b'EQEMU_QUICK_RESULT ').strip(),validate=True)))
            if format_result is not None and line.startswith(b'EQEMU_FORMAT_RESULT '):
                from snapshot import RESULT_LIMIT
                if len(line) > RESULT_LIMIT * 2:
                    raise RuntimeError('Oversized formatter completion')
                results.append(json.loads(base64.b64decode(line.removeprefix(b'EQEMU_FORMAT_RESULT ').strip(), validate=True)))
            if line.startswith(b'EQEMU_WORKER_RESULT '):
                if len(line) > (32768 if build_result is not None else 8192):
                    raise RuntimeError('Oversized guest completion')
                results.append(json.loads(line.removeprefix(b'EQEMU_WORKER_RESULT ')))
    if len(results) != 1:
        raise RuntimeError('Missing or duplicate guest completion')
    result = results[0]
    if quick_result is not None:
        from quick_snapshot import validate_detail
        validate_detail(result)
        if (type(result.get('version')) is not int or result['version']!=1 or result.get('nonce')!=nonce
                or result.get('scope')!='working-snapshot-quickcheck'):
            raise RuntimeError('Malformed quick completion')
        quick_result.update(result)
        return result['exit_code']
    if format_result is not None:
        from snapshot import RESULT_LIMIT, canonical
        if (not isinstance(result, dict) or len(canonical(result)) > RESULT_LIMIT
                or result.get('nonce') != nonce or result.get('scope') != 'working-snapshot-format'
                or type(result.get('version')) is not int or result['version'] != 1
                or type(result.get('exit_code')) is not int or result['exit_code'] not in (0, 1, 2)
                or not isinstance(result.get('changed_files'), list)
                or not isinstance(result.get('output_snapshot_sha256'), str)
                or not re.fullmatch('[a-f0-9]{64}', result['output_snapshot_sha256'])):
            raise RuntimeError('Malformed formatter completion')
        format_result.update(result)
        return result['exit_code']
    if (not isinstance(result, dict) or (set(result) != {'version', 'nonce', 'scope', 'exit_code'} if build_result is None
                                                else not set(result) <= {'version', 'nonce', 'scope', 'exit_code', 'stage', 'error', 'zone_sha256', 'utilities', 'normal_world', 'selected_checks', 'completed_checks'})
            or type(result.get('version')) is not int or result['version'] != 1 or result.get('nonce') != nonce or result.get('scope') != ('worker-smoke' if build_result is None else 'worker-build')
            or type(result.get('exit_code')) is not int or result['exit_code'] not in ((0, 1) if build_result is None else (0, 1, 2))):
        raise RuntimeError('Malformed guest completion')
    if build_result is not None:
        completed = result.get('completed_checks')
        if (result.get('selected_checks') != list(BUILD_CHECKS) or not isinstance(completed, list)
                or not all(isinstance(name, str) for name in completed)
                or len(completed) != len(set(completed)) or not set(completed) <= set(BUILD_CHECKS)
                or (result['exit_code'] == 0 and completed != list(BUILD_CHECKS))):
            raise RuntimeError('Incomplete or malformed build check evidence')
        if not isinstance(result.get('stage'), str) or len(result['stage']) > 100:
            raise RuntimeError('Build stage missing or oversized')
        if 'error' in result and (not isinstance(result['error'], str) or len(result['error']) > 3500):
            raise RuntimeError('Malformed build diagnostic')
        if result['exit_code'] == 0 and (not isinstance(result.get('zone_sha256'), str)
                or not re.fullmatch('[a-f0-9]{64}', result['zone_sha256']) or not isinstance(result.get('utilities'), dict)):
            raise RuntimeError('Build completion missing zone or utility evidence')
        if result['exit_code'] == 0:
            from normal_world import validate
            normal = validate(result.get('normal_world'))
            if normal['binaries']['zone'] != result['zone_sha256']:
                raise RuntimeError('Normal-world zone differs from built candidate')
        build_result.update(result)
        if profile_sink is not None:
            complete=not profile_error and result.get('normal_world',{}).get('profiling',{}).get('complete') is True and result['normal_world']['profiling'].get('mode')==profile_mode
            if complete:
                try:
                    from profile_artifacts import validate_collection
                    validate_collection(profile_sink.directory,profile_mode,profile_request['candidate'],
                        profile_request['tree'],result['normal_world']['binaries'])
                except Exception as error:
                    complete=False
                    build_result['profile_transport']['export_error']=type(error).__name__
            build_result['profile_transport'].update(complete=complete,partial=not complete)
            if not complete: return 2
    return result['exit_code']


def receive_payload(connection, target, expected, deadline):
    """Stream opaque bytes into owned scratch; no host extraction or candidate execution."""
    digest = hashlib.sha256(); remaining = expected['bytes']
    connection.settimeout(5)
    try:
        with target.open('xb') as stream:
            while remaining:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Input transfer deadline exceeded')
                block = connection.recv(min(1024**2, remaining))
                if not block:
                    raise RuntimeError('Client disconnected during input transfer')
                remaining -= len(block); digest.update(block); stream.write(block)
        if digest.hexdigest() != expected['sha256']:
            raise ValueError('Input payload SHA256 mismatch')
    finally:
        connection.settimeout(None)


def implementation_identity(value):
    """Digest the finite reviewed worker implementation, independent of candidate inputs."""
    digests = {}
    for name in IMPLEMENTATION_FILES:
        with (Path(value['code_dir']) / name).open('rb') as stream:
            digests[name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return hashlib.sha256(json.dumps(digests, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def run_vm(value, connection, control='pass', build=None, formatting=None, quick=None):
    started_at = time.monotonic()
    lock = acquire(value)
    state = Path(value['state_dir']); active = state / 'active.json'
    run_id = uuid.uuid4().hex; job = state / run_id
    report = {'version': 1, 'operation': 'smoke', 'scope': 'worker-smoke', 'run_id': run_id,
              'control': control, 'exit_code': 2, 'cleanup_complete': False, 'vm_started': False,
              'worker_uid': os.geteuid(), 'coverage': ['tiny-cloud-init'], 'candidate': None}
    if build is not None:
        control = 'build'
        report.update(operation='build', scope='worker-build', control='build',
                      candidate=build['candidate'], tree=build['tree'], payload_sha256=build['sha256'],
                      coverage=[], selected_checks=list(BUILD_CHECKS), completed_checks=[])
    if formatting is not None:
        control = 'format' if formatting['operation'] == 'format' else 'check-format'
        report.update(operation=formatting['operation'], scope='working-snapshot-format', control=control,
                      coverage=[], candidate=None, changed_files=[],
                      **{key: formatting[key] for key in ('base', 'head', 'input_snapshot_sha256', 'recipe_sha256')},
                      output_snapshot_sha256=formatting['input_snapshot_sha256'],
                      rust_input_sha256=formatting['files']['rust-inputs.tar']['sha256'])
    if quick is not None:
        control='quick'
        report.update(operation='quick',scope='working-snapshot-quickcheck',control=control,coverage=[],advisory=True,
            **{key:quick[key] for key in ('base','head','input_snapshot_sha256','recipe_sha256')},
            output_snapshot_sha256=quick['input_snapshot_sha256'],rust_input_sha256=quick['files']['rust-inputs.tar']['sha256'],
            native_input_sha256=quick['files']['native.iso']['sha256'])
    try:
        if active.exists():
            raise RuntimeError('Previous worker job requires service cleanup')
        probe = ready(value); report['readiness'] = probe
        if probe['exit_code'] != 0:
            raise RuntimeError('Worker readiness failed')
        if build is not None or formatting is not None or quick is not None:
            report['implementation_sha256'] = implementation_identity(value)
        if build is not None or quick is not None:
            if int(resource_state()['memory.max']) < 6 * 1024**3:
                raise RuntimeError('Server build needs the reviewed 6 GiB service resource update')
        required_space = 50 if build is not None or quick is not None else 10
        if shutil.disk_usage(state).free < required_space * 1024**3:
            raise RuntimeError('Worker needs ' + str(required_space) + ' GiB free space')
        active_record = {'run_id': run_id, 'invocation_id': invocation(), 'control': control, 'qemu_pid': None}
        atomic_json(active, active_record)
        job.mkdir(mode=0o700); scratch = job / 'scratch'; scratch.mkdir(mode=0o700)
        deadline = time.monotonic() + (BUILD_SECONDS if build is not None else 3600 if quick is not None else FORMAT_SECONDS if formatting is not None else SECONDS)
        base = root_file(value['base_image'])
        with base.open('rb') as stream:
            report['base_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        payload = build if build is not None else quick if quick is not None else formatting
        if payload is not None:
            receive_payload(connection, scratch / 'payload.iso', payload, time.monotonic() + 120)
        if build is not None and build.get('profiling'):
            (scratch/'profile-requested').write_text(json.dumps({key:build[key] for key in ('profiling','candidate','tree')}))
        (scratch / 'user-data').write_text(build_user_data(run_id) if build is not None else
                                         quick_user_data(run_id,quick) if quick is not None else
                                         format_user_data(run_id, formatting) if formatting is not None else user_data(run_id, control))
        (scratch / 'meta-data').write_text('instance-id: eqemu-smoke-' + run_id + '\n')
        tool([QEMU_IMG, 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(scratch / 'disk.qcow2'), '48G' if build is not None or quick is not None else '8G'], deadline)
        tool([GENISOIMAGE, '-output', str(scratch / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
              str(scratch / 'user-data'), str(scratch / 'meta-data')], deadline)
        args = [QEMU, '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '4096' if build is not None or quick is not None else '1024',
                # Leave room beneath TasksMax for vCPUs, supervision and bounded I/O workers.
                '-object', 'main-loop,id=main-loop,thread-pool-min=0,thread-pool-max=8',
                '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
                '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                '-drive', 'file=' + str(scratch / 'disk.qcow2') + ',if=virtio,format=qcow2,cache=none',
                '-drive', 'file=' + str(scratch / 'seed.iso') + ',media=cdrom,readonly=on,format=raw']
        if payload is not None:
            args += ['-drive', 'file=' + str(scratch / 'payload.iso') + ',media=cdrom,readonly=on,format=raw']
        def started(pid):
            report['vm_started'] = True
            report['qemu_pid'] = pid
            active_record['qemu_pid'] = pid
            atomic_json(active, active_record)
            if control == 'controller-death':
                # Explicit qualification control: bypass Python finally, exercising systemd's
                # cgroup kill and ExecStopPost rather than the controller's normal cleanup.
                os.kill(os.getpid(), signal.SIGKILL)
        if quick is not None:
            detail={}
            report['exit_code']=supervise(args,scratch,job/'serial.log',connection,deadline,run_id,started,quick_result=detail)
            report.update({key:detail[key] for key in ('selected_checks','completed_checks','failed_checks','unavailable_checks','skipped_checks','checks','native_scope')})
            report['timings']=dict(boot_seconds=detail.get('boot_seconds',0),preparation_seconds=detail.get('preparation_seconds',0))
            if report['implementation_sha256']!=implementation_identity(value):raise RuntimeError('Worker implementation changed during quick checks')
        elif formatting is not None:
            detail = {}
            report['exit_code'] = supervise(args, scratch, job / 'serial.log', connection, deadline, run_id, started,
                                            format_result=detail)
            report.update(changed_files=detail['changed_files'], output_snapshot_sha256=detail['output_snapshot_sha256'])
            if 'error' in detail:
                report['error'] = detail['error']
            report['timings'] = dict(boot_seconds=detail.get('boot_seconds', 0),
                preparation_seconds=detail.get('preparation_seconds', 0), format_seconds=detail.get('format_seconds', 0))
            if report['implementation_sha256'] != implementation_identity(value):
                raise RuntimeError('Worker implementation changed during formatting')
        elif build is None:
            report['exit_code'] = supervise(args, scratch, job / 'serial.log', connection, deadline, run_id, started)
        else:
            detail = {}
            report['guest'] = detail
            report['exit_code'] = supervise(args, scratch, job / 'serial.log', connection, deadline, run_id, started, detail)
            report['completed_checks'] = detail['completed_checks']
            if report['implementation_sha256'] != implementation_identity(value):
                raise RuntimeError('Worker implementation changed during the job')
            if report['exit_code'] == 0:
                report['coverage'] = ['rust-checks', 'server-build', 'native-utilities', 'normal-world']
    except Exception as error:
        report['error'] = str(error)[:1000]
        report['exit_code'] = 2
        if isinstance(error, CleanupError):
            report['cleanup_error'] = str(error)[:1000]
        if formatting is not None:
            report.update(changed_files=[], output_snapshot_sha256=formatting['input_snapshot_sha256'])
        if quick is not None:
            from quick_guest import unavailable
            report.update(unavailable(error))
    finally:
        try:
            if 'cleanup_error' not in report:
                if job.exists():
                    scratch_cleanup(job)
                report['cleanup_complete'] = True
        except Exception as error:
            report['cleanup_error'] = str(error)[:1000]; report['exit_code'] = 2
        if formatting is not None or quick is not None:
            report.setdefault('timings', {})['total_seconds'] = round(time.monotonic() - started_at, 3)
            if formatting is not None and report['exit_code'] != 0:
                report.update(changed_files=[], output_snapshot_sha256=formatting['input_snapshot_sha256'])
        if (job/'profiles').exists():
            try: retain_profiles(job,state,run_id,report)
            except Exception as error:
                report.update(exit_code=2,profile_export_error=type(error).__name__,profile_retention_complete=False)
        if job.exists():
            atomic_json(state / 'last-result.json', persisted_report(report))
            if (job / 'serial.log').exists():
                os.replace(job / 'serial.log', state / 'last-serial.log')
            if report['cleanup_complete'] and not (job/'profiles').exists():
                job.rmdir()
        if active.exists() and read_json(active).get('run_id') == run_id and report['cleanup_complete'] and report.get('profile_retention_complete',True):
            active.unlink()
        if report.get('profile_artifacts'):
            try:
                from profile_artifacts import send
                connection.settimeout(30)
                with connection.makefile('wb') as stream:
                    send(state/'last-profile',stream)
            except Exception as error:
                report.update(exit_code=2,profile_client_export_error=type(error).__name__)
                atomic_json(state/'last-result.json',persisted_report(report))
            finally: connection.settimeout(None)
        os.close(lock)
    return report


def retain_profiles(job,state,run_id,report):
    """Retain one bounded private collection independently of disposable VM cleanup."""
    from profile_artifacts import inventory
    current=state/'last-profile'
    if current.exists():
        inventory(current)
        for path in current.iterdir(): path.unlink()
        current.rmdir()
    os.replace(job/'profiles',current)
    report['profile_artifacts']=dict(run_id=run_id,files=inventory(current),
        partial=report.get('guest',{}).get('profile_transport',{}).get('complete') is not True,
        retention='one collection, replaced by next profiling run; operator may delete sooner')


def request(connection, value):
    """One bounded request on systemd's accepted fd0 socket; no listener or host RPC."""
    peer_uid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    if peer_uid != pwd.getpwnam(value['submitter']).pw_uid:
        raise ValueError('Socket peer is not the configured submitter')
    connection.settimeout(5)
    raw = bytearray()
    while b'\n' not in raw:
        block = connection.recv(1)
        if not block:
            raise ValueError('Missing worker request')
        raw.extend(block)
        if len(raw) > 4096:
            raise ValueError('Worker request limit exceeded')
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('One worker request required')
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('Unsupported worker request')
    if data == {'version': 1, 'operation': 'check'}:
        return ready(value)
    if data == {'version': 1, 'operation': 'last-result'}:
        return {'version': 1, 'operation': 'last-result', 'scope': 'worker-observation',
                'exit_code': 0, 'result': read_json(Path(value['state_dir']) / 'last-result.json', limit=65536)}
    if data.get('operation')=='profile-artifacts':
        if set(data)!={'version','operation','run_id'} or not isinstance(data['run_id'],str) or not re.fullmatch('[a-f0-9]{32}',data['run_id']):
            raise ValueError('Exact profiling run ID required')
        from profile_artifacts import inventory, send
        lock=acquire(value)
        try:
            report=read_json(Path(value['state_dir'])/'last-result.json',limit=65536)
            if report.get('run_id')!=data['run_id'] or report.get('profile_artifacts',{}).get('run_id')!=data['run_id']:
                raise ValueError('Requested profile is no longer retained')
            directory=Path(value['state_dir'])/'last-profile'
            files=inventory(directory)
            if files!=report['profile_artifacts']['files']: raise ValueError('Retained profile changed')
            connection.settimeout(30)
            with connection.makefile('wb') as stream: send(directory,stream)
            return dict(version=1,operation='profile-artifacts',scope='profile-export-only',exit_code=0,executed=False,
                run_id=data['run_id'],workload_exit_code=report['exit_code'],profile_artifacts=report['profile_artifacts'])
        finally: os.close(lock)
    if data.get('operation') == 'build':
        if (set(data) != {'version', 'operation', 'candidate', 'tree', 'bytes', 'sha256'} | ({'profiling'} if 'profiling' in data else set())
                or ('profiling' in data and data['profiling'] not in ('timeline','heaptrack','perf'))
                or not all(isinstance(data[key], str) and re.fullmatch('[a-f0-9]{40}', data[key]) for key in ('candidate', 'tree'))
                or not isinstance(data['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', data['sha256'])
                or type(data['bytes']) is not int or not 0 < data['bytes'] <= PAYLOAD_LIMIT):
            raise ValueError('Malformed build request')
        connection.settimeout(None)
        return run_vm(value, connection, build=data)
    if data.get('operation')=='quick':
        from snapshot import RUST_INPUT_SHA256
        from quick_snapshot import ARCHIVE_LIMIT, MANIFEST_LIMIT
        if (set(data)!={'version','operation','base','head','input_snapshot_sha256','recipe_sha256','files','bytes','sha256'}
                or any(not isinstance(data.get(key),str) or not re.fullmatch('[a-f0-9]{40}',data[key]) for key in ('base','head'))
                or any(not isinstance(data.get(key),str) or not re.fullmatch('[a-f0-9]{64}',data[key]) for key in ('input_snapshot_sha256','recipe_sha256','sha256'))
                or type(data['bytes']) is not int or not 0<data['bytes']<=PAYLOAD_LIMIT
                or not isinstance(data['files'],dict) or set(data['files'])!={'snapshot.json','eqemu.tar','websocketpp.tar','native.iso','rust-inputs.tar'}
                or any(not isinstance(entry,dict) or set(entry)!={'bytes','sha256'} or type(entry['bytes']) is not int
                       or not 0<entry['bytes']<=PAYLOAD_LIMIT or not isinstance(entry['sha256'],str)
                       or not re.fullmatch('[a-f0-9]{64}',entry['sha256']) for entry in data['files'].values())
                or data['files']['rust-inputs.tar']['sha256']!=RUST_INPUT_SHA256
                or data['files']['native.iso']['sha256']!='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'
                or data['files']['snapshot.json']['bytes']>MANIFEST_LIMIT or data['files']['eqemu.tar']['bytes']>ARCHIVE_LIMIT):
            raise ValueError('Malformed quick request')
        connection.settimeout(None)
        return run_vm(value,connection,quick=data)
    if data.get('operation') in ('format', 'check'):
        from snapshot import RUST_INPUT_SHA256 as RUST_SHA
        if (set(data) != {'version', 'operation', 'base', 'head', 'input_snapshot_sha256', 'recipe_sha256', 'files', 'bytes', 'sha256'}
                or any(not isinstance(data.get(k), str) or not re.fullmatch('[a-f0-9]{40}', data[k]) for k in ('base', 'head'))
                or any(not isinstance(data.get(k), str) or not re.fullmatch('[a-f0-9]{64}', data[k])
                       for k in ('input_snapshot_sha256', 'recipe_sha256', 'sha256'))
                or type(data['bytes']) is not int or not 0 < data['bytes'] <= PAYLOAD_LIMIT
                or not isinstance(data['files'], dict) or set(data['files']) != {'snapshot.json', 'rust-inputs.tar'}
                or any(not isinstance(entry, dict) or set(entry) != {'bytes', 'sha256'}
                       or type(entry['bytes']) is not int or not 0 < entry['bytes'] <= PAYLOAD_LIMIT
                       or not isinstance(entry['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256'])
                       for entry in data['files'].values())
                or data['files']['rust-inputs.tar']['sha256'] != RUST_SHA
                or data['files']['snapshot.json']['bytes'] > 8 * 1024**2):
            raise ValueError('Malformed formatter request')
        connection.settimeout(None)
        return run_vm(value, connection, formatting=data)
    if set(data) != {'version', 'operation', 'control'} or data['operation'] != 'smoke' or data['control'] not in CONTROLS:
        raise ValueError('Unsupported worker operation')
    connection.settimeout(None)  # MSG_DONTWAIT EOF probes must not inherit the request-read timeout.
    return run_vm(value, connection, data['control'])


def interrupted(signum, _):
    raise RuntimeError('Worker interrupted by signal ' + str(signum))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('serve', 'cleanup'))
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    connection = None
    try:
        value = config(args.config)
        if args.operation == 'cleanup':
            return cleanup(value)
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, interrupted)
        connection = socket.socket(fileno=os.dup(0))
        try:
            result = request(connection, value)
        except Exception as error:
            result = {'version': 1, 'exit_code': 2, 'error': str(error)[:1000], 'scope': 'worker-smoke'}
        try:
            connection.settimeout(30)
            connection.sendall((json.dumps(result, separators=(',', ':')) + '\n').encode())
        except OSError:
            pass  # A disconnected client cannot prevent owned cleanup/result persistence.
        return result['exit_code']
    except Exception as error:
        print('worker: ' + str(error)[:1000], file=sys.stderr)
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
