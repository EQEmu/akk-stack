"""Small host-only job/result/callback helper. No candidate commands run here.

Private artifacts are owned by the submitting UID. Linux pidfds and recorded
boot/start identities prevent cancellation from signalling a recycled PID.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JOBS = Path.home() / '.local/state/eqemu-validation-jobs'
LOG_LIMIT = 64 * 1024**2
CALLBACK_LIMIT = 16384
GRACE = 780


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def write(path, value):
    """Publish complete JSON, including an fsync before atomic replacement."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def private(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or path.resolve() != path):
        raise ValueError('Expected private owned nonsymlink directory: ' + str(path))
    return path


def job_path(root, job_id):
    if not re.fullmatch(r'[a-f0-9]{32}', job_id):
        raise ValueError('Expected exact job ID')
    private(root)
    path = private(root / job_id)
    spec = read(path / 'job.json')
    if spec['job_id'] != job_id or spec['uid'] != os.getuid():
        raise ValueError('Job ownership mismatch')
    return path


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 1024**2:
            raise ValueError('Invalid owned job record')
        return json.load(stream)


@contextlib.contextmanager
def locked(path, blocking=True):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Invalid job lock')
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def process_identity(pid):
    directory = Path('/proc') / str(pid)
    fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(pid=pid, start=fields[19], boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                uid=directory.stat().st_uid)


def signal_owned(owner, signum):
    """Open first, then verify identity; the signal targets that exact kernel task."""
    fd = os.pidfd_open(owner['pid'])
    try:
        if process_identity(owner['pid']) != owner or owner['uid'] != os.getuid():
            raise ValueError('Process ownership mismatch; refusing signal')
        signal.pidfd_send_signal(fd, signum)
    finally:
        os.close(fd)


def stop_owned(owner, grace=GRACE):
    """Cancel an orphaned frontend via one pidfd, retaining its grace deadline."""
    fd = os.pidfd_open(owner['pid'])
    try:
        if process_identity(owner['pid']) != owner or owner['uid'] != os.getuid():
            raise ValueError('Process ownership mismatch; refusing cancellation')
        signal.pidfd_send_signal(fd, signal.SIGINT)
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            escalated = not bool(selector.select(grace))
            if escalated: signal.pidfd_send_signal(fd, signal.SIGKILL)
            if not selector.select(5): raise RuntimeError('Owned frontend exit not confirmed')
        return dict(frontend_exit_confirmed=True, escalated=escalated, cleanup_complete=None)
    finally:
        os.close(fd)


def cancel_abandoned(path):
    """Notification-independent cancellation only, never launches validation."""
    with locked(path / 'cancel.lock', blocking=False):
        with locked(path / 'state.lock'):
            state = read(path / 'state.json')
            if state.get('canceller') != process_identity(os.getpid()):
                raise ValueError('Not the selected cancellation process')
        detail = dict(frontend_exit_confirmed=False, cleanup_complete=None)
        try:
            if alive(state['validator']): detail.update(stop_owned(state['validator']))
            else: detail['frontend_exit_confirmed'] = True
        except Exception as error:
            detail['error'] = str(error)[:1000]
        detail['finished'] = now()
        write(path / 'cancellation.json', detail)
        with locked(path / 'state.lock'):
            recover(path, cancelled=True)
        notify(path)


def start(root, spec, snapshot=False):
    """Internal process seam accepts trusted test fixtures; CLI exposes only full."""
    root = root.absolute()
    root.mkdir(parents=True, mode=0o700, exist_ok=True); private(root)
    job_id = uuid.uuid4().hex
    path = root / job_id; path.mkdir(mode=0o700)
    if snapshot:
        # Freeze the small trusted frontend closure, never the candidate's code.
        from identity import FRONTEND_FILES
        files = list(FRONTEND_FILES)
        files += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'validation/worker').glob('*.py'))
                  if p.name != 'jobs.py']
        records = {}
        for name in dict.fromkeys(files):
            target = path / 'client' / name; target.parent.mkdir(parents=True, exist_ok=True)
            data = (ROOT / name).read_bytes(); target.write_bytes(data)
            target.chmod(0o700 if name.startswith('scripts/') else 0o600)
            records[name] = hashlib.sha256(data).hexdigest()
        spec = dict(spec, client_files_sha256=records,
                    command=[str(path / 'client/scripts/validate-worker-candidate'), *spec['command'][1:]])
    runner = path / 'runner.py'
    runner.write_bytes(Path(__file__).read_bytes())
    spec = dict(spec, version=1, job_id=job_id, uid=os.getuid(), created=now(),
                runner_sha256=hashlib.sha256(runner.read_bytes()).hexdigest())
    write(path / 'job.json', spec)
    write(path / 'notification.json', dict(status='pending', attempts=0))
    # The child waits for the parent to persist its exact identity before launch.
    with locked(path / 'state.lock'):
        write(path / 'state.json', dict(status='starting'))
        try:
            with (path / 'runner.log').open('xb') as log:
                process = subprocess.Popen(['/usr/bin/python3', '-I', str(runner),
                    '--run', str(root), job_id], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                    start_new_session=True, close_fds=True)
            write(path / 'state.json', dict(status='running', runner=process_identity(process.pid)))
            # Reap in long-lived callers; a short CLI can exit immediately.
            threading.Thread(target=process.wait, daemon=True).start()
        except Exception as error:
            write(path / 'state.json', dict(status='launch_failed', error=str(error)[:1000]))
            write(path / 'result.json', dict(status='launch_failed', returncode=None, finished=now(),
                                           cleanup_complete=None, error=str(error)[:1000]))
    if (path / 'result.json').exists():
        background_notify(path)
    return dict(job_id=job_id, artifacts=str(path))


def background_notify(path):
    """One detached delivery attempt for terminal paths without a live runner."""
    try:
        with (path / 'notification-runner.log').open('ab') as log:
            process = subprocess.Popen(['/usr/bin/python3', '-I', str(path / 'runner.py'), '--notify',
                str(path.parent), path.name], stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True, close_fds=True)
        threading.Thread(target=process.wait, daemon=True).start()
    except Exception as error:
        with locked(path / 'notification.lock'):
            previous = read(path / 'notification.json')
            write(path / 'notification.json', dict(previous, status='failed', error=str(error)[:1000]))


def alive(owner):
    try:
        state = (Path('/proc') / str(owner['pid']) / 'stat').read_text().rsplit(')', 1)[1].split()[0]
        return state != 'Z' and process_identity(owner['pid']) == owner
    except (FileNotFoundError, ProcessLookupError): return False


def recover(path, cancelled=False):
    """A dead supervisor cannot supply an exit code or remote cleanup receipt."""
    if not (path / 'result.json').exists():
        state = read(path / 'state.json')
        if state.get('runner') and alive(state['runner']):
            raise ValueError('Job is still running')
        write(path / 'result.json', dict(status='cancelled' if cancelled else 'interrupted',
            returncode=None, cleanup_complete=None, finished=now(),
            error='Runner exited without a final validator receipt; remote cleanup unknown'))


def notify(path):
    """Retry delivery only. An uncertain acknowledgement can duplicate the job ID."""
    with locked(path / 'notification.lock', blocking=False):
        with locked(path / 'state.lock'):
            recover(path)
        result = read(path / 'result.json')
        previous = read(path / 'notification.json')
        if previous['status'] == 'sent':
            return previous
        spec = read(path / 'job.json')
        message = 'Validation evidence only; no new work requested. Recognize duplicate job_id. ' + json.dumps(
            dict(job_id=spec['job_id'], candidate=spec['candidate'], profile=spec['profile'],
                 outcome=result['status'], returncode=result['returncode'],
                 cleanup_complete=result['cleanup_complete'], artifacts=str(path),
                 result=str(path / 'result.json'), validator_result=str(path / 'validator-result.json')),
            separators=(',', ':'))
        if len(message.encode()) > 8192:
            raise ValueError('Callback summary exceeds limit')
        attempt = previous['attempts'] + 1
        notification = dict(status='sending', attempts=attempt, started=now())
        write(path / 'notification.json', notification)
        try:
            code, detail = capture([spec['adapter'], '--base-dir', spec['t3_base_dir'], '--thread', spec['thread']],
                path / ('callback-' + str(attempt)), message.encode(), seconds=60, limit=CALLBACK_LIMIT)
            notification.update(status='sent' if code == 0 and not detail['pipe_drain_incomplete'] else 'failed', returncode=code)
        except Exception as error:
            notification.update(status='failed', error=str(error)[:1000])
        notification['finished'] = now()
        write(path / 'notification.json', notification)
        return notification


def capture(argv, prefix, message=None, *, seconds=None, limit=LOG_LIMIT, cancel=None, on_started=None, env=None):
    """Drain both real pipes to finite raw logs, preserving the process exit code."""
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if message is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=env)
    started = time.monotonic(); interrupted = exited = killed = None
    total = [0, 0]; tail = bytearray(); incomplete = False
    try:
        if on_started: on_started(process_identity(process.pid))
        if message is not None:
            process.stdin.write(message); process.stdin.close()
        with selectors.DefaultSelector() as selector, Path(str(prefix) + '.stdout.log').open('xb') as stdout, \
                Path(str(prefix) + '.stderr.log').open('xb') as stderr:
            for index, pipe in enumerate((process.stdout, process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (index, (stdout, stderr)[index]))
            while True:
                current = time.monotonic()
                # Keep the session leader unreaped until pipe draining finishes.
                # Its PID/PGID cannot be reused while signalling this owned group.
                ended = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if ended is not None and exited is None: exited = current
                if not selector.get_map() and exited is not None: break
                if interrupted is None and ((cancel is not None and cancel()) or
                        (seconds is not None and current - started > seconds)):
                    interrupted = current
                    os.killpg(process.pid, signal.SIGINT)
                if killed is None and ((interrupted is not None and current - interrupted > (5 if seconds else GRACE))
                        or (exited is not None and current - exited > 2)):
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    killed = current
                if killed is not None and current - killed > 2:
                    incomplete = bool(selector.get_map())
                    break
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj); continue
                    index, stream = key.data
                    stream.write(block[:max(0, limit - total[index])]); stream.flush()
                    total[index] += len(block)
                    if index == 0:
                        tail.extend(block); del tail[:-131072]
            return process.wait(), dict(stdout_bytes=total[0], stderr_bytes=total[1],
                log_limit=limit, truncated=any(count > limit for count in total),
                pipe_drain_incomplete=incomplete, tail=bytes(tail))
    finally:
        if process.returncode is None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        process.wait()
        process.stdout.close(); process.stderr.close()


def run(root, job_id):
    path = job_path(root, job_id)
    with locked(path / 'run.lock', blocking=False):
        with locked(path / 'state.lock'):
            state = read(path / 'state.json')
            if state.get('runner') != process_identity(os.getpid()) or (path / 'result.json').exists():
                raise ValueError('Runner is not the selected job process')
        cancelled = False
        def interrupt(signum, frame):
            nonlocal cancelled
            cancelled = True
        for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupt)
        spec = read(path / 'job.json')
        result = dict(status='launch_failed', returncode=None, cleanup_complete=None, started=now())
        def selected(owner):
            with locked(path / 'state.lock'):
                state['validator'] = owner; write(path / 'state.json', state)
        try:
            if (path / 'cancel.json').exists():
                result['status'] = 'cancelled'
                raise InterruptedError('Cancelled before validator launch')
            environment = dict(os.environ, VALIDATION_AFK_EVIDENCE_DIR=str(path / 'evidence'))
            code, logs = capture(spec['command'], path / 'validator', cancel=lambda: cancelled or
                (path / 'cancel.json').exists(), on_started=selected, env=environment)
            tail = logs.pop('tail')
            result.update(status='cancelled' if cancelled or (path / 'cancel.json').exists() else 'completed',
                          returncode=code, logs=logs)
            try:
                report = json.loads(tail.splitlines()[-1])
                if isinstance(report, dict):
                    write(path / 'validator-result.json', report)
                    # Only an explicit final worker receipt confirms remote cleanup.
                    cleanup = report.get('cleanup_complete')
                    result['cleanup_complete'] = cleanup if type(cleanup) is bool else None
            except (ValueError, IndexError):
                pass
        except Exception as error:
            result['error'] = str(error)[:1000]
        result['finished'] = now()
        write(path / 'result.json', result)
        with locked(path / 'state.lock'):
            state['status'] = result['status']; write(path / 'state.json', state)
        notify(path)


def status(path):
    state = read(path / 'state.json')
    result = read(path / 'result.json') if (path / 'result.json').exists() else None
    if result is None and state.get('runner'):
        if not alive(state['runner']):
            state = dict(state, status='interrupted', cleanup_complete=None)
    return dict(job_id=path.name, artifacts=str(path), state=state, result=result,
                cancellation=read(path / 'cancellation.json') if (path / 'cancellation.json').exists() else None,
                notification=read(path / 'notification.json'))


def cancel(path):
    with locked(path / 'state.lock'):
        state = read(path / 'state.json')
        # Verify before recording cancellation; never signal another process.
        if not state.get('runner') or not alive(state['runner']):
            if state.get('validator') and alive(state['validator']):
                signal_owned(state['validator'], 0)
                if not state.get('canceller') or not alive(state['canceller']):
                    with (path / 'cancellation-runner.log').open('ab') as log:
                        process = subprocess.Popen(['/usr/bin/python3', '-I', str(path / 'runner.py'),
                            '--cancel-owned', str(path.parent), path.name], stdin=subprocess.DEVNULL,
                            stdout=log, stderr=log, start_new_session=True, close_fds=True)
                    state['canceller'] = process_identity(process.pid)
                    write(path / 'state.json', state)
                    threading.Thread(target=process.wait, daemon=True).start()
            else:
                recover(path, cancelled=True)
        else:
            if (path / 'result.json').exists(): return status(path)
            # Marker also works before Python installs its signal handlers.
            signal_owned(state['runner'], 0)
        write(path / 'cancel.json', dict(requested=now()))
    if (path / 'result.json').exists(): background_notify(path)
    return status(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs-dir', type=Path, default=DEFAULT_JOBS)
    sub = parser.add_subparsers(dest='action', required=True)
    launch = sub.add_parser('start')
    launch.add_argument('profile', choices=('full', 'full-sanitizers'))
    launch.add_argument('--repo', type=Path, required=True)
    launch.add_argument('--commit', required=True, help='Exact immutable 40-character source commit')
    launch.add_argument('--thread', required=True)
    launch.add_argument('--t3-base-dir', type=Path, required=True)
    launch.add_argument('--notify-adapter', type=Path, default=ROOT / 'scripts/t3-validation-notify')
    launch.add_argument('--websocketpp', type=Path, required=True)
    launch.add_argument('--rust-input', type=Path, help='Finite source-pinned full-build Rust bundle; original default if omitted')
    launch.add_argument('--config', type=Path, default=Path('/etc/eqemu-validator/config.json'))
    for name in ('status', 'cancel', 'retry-notification'):
        sub.add_parser(name).add_argument('job_id')
    args = parser.parse_args(argv)
    try:
        if args.action == 'start':
            if not re.fullmatch('[a-f0-9]{40}', args.commit): raise ValueError('Expected full source commit SHA')
            if (not args.thread or len(args.thread) > 512 or args.thread.startswith('-')
                    or any(ord(ch) < 33 or ord(ch) == 127 for ch in args.thread)):
                raise ValueError('Expected bounded explicit control-free thread ID')
            if not args.t3_base_dir.is_absolute() or not args.t3_base_dir.is_dir():
                raise ValueError('Expected explicit existing T3 data directory')
            # GitTree reads objects without candidate hooks/config or code execution.
            # Keep worker helpers first: validation also contains prepare.py.
            sys.path.append(str(ROOT / 'validation'))
            from inputs import GitTree
            with tempfile.TemporaryDirectory() as temporary:
                view = GitTree(args.repo, Path(temporary))
                tree = view.git('rev-parse', args.commit + '^{tree}').decode().strip()
                head = view.location('HEAD')
            command = [str(ROOT / 'scripts/validate-worker-candidate'), '--repo', str(args.repo.resolve()),
                '--commit', args.commit, '--websocketpp', str(args.websocketpp.resolve()), '--config', str(args.config.resolve())]
            if args.rust_input is not None:
                command += ['--rust-input', str(args.rust_input.resolve())]
            if args.profile == 'full-sanitizers':
                from sanitizers import PROFILE
                config = json.loads(args.config.read_text())
                if config.get('diagnostic_profile') != PROFILE:
                    raise ValueError('full-sanitizers requires the exact admitted diagnostic --config')
                command += ['--profile', PROFILE]
            value = start(args.jobs_dir, dict(profile=args.profile, candidate=args.commit, tree=tree,
                observed_head=head, source_selection='immutable commit; full validator rejects dirty checkout; no dirty snapshot',
                command=command, validator_sha256=hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),
                adapter=str(args.notify_adapter.resolve()), thread=args.thread, t3_base_dir=str(args.t3_base_dir)), snapshot=True)
        else:
            path = job_path(args.jobs_dir.absolute(), args.job_id)
            value = notify(path) if args.action == 'retry-notification' else cancel(path) if args.action == 'cancel' else status(path)
        print(json.dumps(value, sort_keys=True)); return 0
    except Exception as error:
        print(json.dumps(dict(error=str(error)[:1000])), file=sys.stderr); return 2


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--run':
        run(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == '--notify':
        notify(job_path(Path(sys.argv[2]), sys.argv[3]))
    elif len(sys.argv) == 4 and sys.argv[1] == '--cancel-owned':
        cancel_abandoned(job_path(Path(sys.argv[2]), sys.argv[3]))
    else:
        raise SystemExit(main())
