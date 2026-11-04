"""Copy a finite worker runtime and an explicitly hashed public image as data."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

FILES = ('validation/worker/actor_integration.py', 'validation/worker/integration_artifacts.py', 'validation/actor-integration-fixture.json', 'validation/worker/profile_contract.py', 'validation/worker/profiling.py', 'validation/worker/profile_artifacts.py',
         'validation/worker/profile_inputs.py', 'validation/worker/runtime.py', 'validation/worker/guest.py',
         'validation/worker/sanitizers.py',
         'validation/worker/client.py', 'validation/worker/build_guest.py',
         'validation/worker/snapshot.py', 'validation/worker/format_guest.py',
         'validation/worker/quick_snapshot.py','validation/worker/quick_guest.py',
         'validation/worker/normal_world.py', 'validation/actor.py', 'validation/actor_runtime.py',
         'validation/debugger.py', 'validation/runtime-fixture.json', 'scripts/check-validation-worker')
DIRECTORIES = ('', 'validation', 'validation/worker', 'scripts')
SOURCE = Path(__file__).resolve().parents[2]
MAX_IMAGE = 2 * 1024**3


def regular(path, *, limit, owners, host=None, source_code=False):
    """Open without following the final symlink, then check the opened inode."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if host is not None:
            # Fake hosts use recorded ownership but keep real file types and bytes.
            owner = host.info(path).st_uid
        else:
            owner = info.st_uid
        if (not stat.S_ISREG(info.st_mode) or owner not in owners
                or (not source_code and info.st_mode & 0o022) or not 0 < info.st_size <= limit):
            raise ValueError('Unexpected source type, ownership, permissions or size: '+str(path))
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def digest(stream, destination=None):
    result = hashlib.sha256()
    total = 0
    while chunk := stream.read(1024**2):
        total += len(chunk)
        if total > MAX_IMAGE:
            raise ValueError('Public image grew past the size limit')
        result.update(chunk)
        if destination is not None:
            destination.write(chunk)
    return result.hexdigest()


def target_parents(host, path):
    """Every existing destination ancestor must be a protected root directory."""
    for parent in path.parents:
        if parent.exists() or parent.is_symlink():
            info = host.info(parent)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != host.admin_uid
                    or info.st_mode & 0o022):
                raise ValueError('Staging needs protected destination ancestors: '+str(parent))
        if parent == host.root:
            break


def existing_code(host, code, uid, expected):
    """Read existing mutable code through directory descriptors; never write it as root."""
    def visit(path, fd, prefix):
        info = host.info(path)
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o755:
            raise ValueError('Staged code directory ownership or mode changed: '+str(path))
        allowed = {p[len(prefix):].split('/')[0] for p in (*FILES, *DIRECTORIES)
                   if p.startswith(prefix) and p != prefix.rstrip('/')}
        found = set()
        with os.scandir(fd) as entries:
            for entry in entries:
                if entry.name not in allowed:
                    raise ValueError('Staged code contains missing or unknown entries: '+str(path))
                found.add(entry.name)
        if found != allowed:
            raise ValueError('Staged code contains missing or unknown entries: '+str(path))
        for name in sorted(allowed):
            relative = prefix+name
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            directory = relative in DIRECTORIES
            if directory:
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=fd)
            try:
                if directory:
                    visit(path/name, child, relative+'/')
                else:
                    info = os.fstat(child)
                    mode = 0o755 if relative.startswith('scripts/') else 0o644
                    if (not stat.S_ISREG(info.st_mode) or host.info(path/name).st_uid != uid
                            or stat.S_IMODE(info.st_mode) != mode or info.st_size > 1024**2):
                        raise ValueError('Staged code asset ownership, type or mode changed: '+relative)
                    with os.fdopen(os.dup(child), 'rb') as source:
                        if source.read(1024**2+1) != expected[relative]:
                            raise ValueError('Staged code differs; update reviewed code as the submitter: '+relative)
            finally:
                os.close(child)
    fd = os.open(code, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(code, fd, '')
    finally:
        os.close(fd)


def prepare(host, args, submitter):
    if not getattr(args, 'stage', False):
        if getattr(args, 'base_source', None) or getattr(args, 'base_sha256', None):
            raise ValueError('--base-source and --base-sha256 require --stage')
        return None
    if args.account_only or args.check:
        raise ValueError('--stage requires full setup apply or dry-run')
    if not args.base_source or not re.fullmatch(r'[a-f0-9]{64}', args.base_sha256 or ''):
        raise ValueError('--stage requires --base-source and an explicit lowercase --base-sha256')
    code, base = host.path(args.code_dir), host.path(args.base_image)
    for path in (code, base):
        target_parents(host, path)
    data = {}
    for name in FILES:
        with regular(SOURCE/name, limit=1024**2, owners={submitter.pw_uid, host.admin_uid, os.getuid()},
                     source_code=True) as source:
            data[name] = source.read(1024**2+1)
    with regular(Path(args.base_source), limit=MAX_IMAGE,
                 owners={submitter.pw_uid, host.admin_uid}, host=host) as source:
        if digest(source) != args.base_sha256:
            raise ValueError('Public base source SHA256 does not match --base-sha256')
    code_exists = code.exists() or code.is_symlink()
    base_exists = base.exists() or base.is_symlink()
    if code_exists:
        existing_code(host, code, submitter.pw_uid, data)
    if base_exists:
        with regular(base, limit=MAX_IMAGE, owners={host.admin_uid}, host=host) as source:
            if stat.S_IMODE(host.info(base).st_mode) != 0o644 or digest(source) != args.base_sha256:
                raise ValueError('Existing public base differs in bytes or permissions')
    return dict(code=code, base=base, data=data, code_exists=code_exists,
                base_exists=base_exists, image_sha256=args.base_sha256)


def parents(host, path):
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        host.chown(directory, host.admin_uid, 0)
        directory.chmod(0o755)


def publish(host, args, submitter, plan):
    """Publish from root-private temporary paths under protected destination parents."""
    code, base = plan['code'], plan['base']
    # Recheck protected parents immediately before root writes. Existing code is untouched.
    for path in (code, base):
        target_parents(host, path)
    if not plan['base_exists']:
        parents(host, base.parent)
        fd, temporary = tempfile.mkstemp(prefix='.eqemu-base-', dir=base.parent)
        temporary = Path(temporary)
        try:
            with os.fdopen(fd, 'wb') as target:
                with regular(Path(args.base_source), limit=MAX_IMAGE,
                             owners={submitter.pw_uid, host.admin_uid}, host=host) as source:
                    if digest(source, target) != plan['image_sha256']:
                        raise ValueError('Public base changed during staging')
                target.flush()
                os.fsync(target.fileno())
            with temporary.open('rb') as staged:
                if digest(staged) != plan['image_sha256']:
                    raise ValueError('Copied public base SHA256 does not match')
            host.chown(temporary, host.admin_uid, 0)
            temporary.chmod(0o644)
            # Hard-link is an atomic no-replacement publication on this filesystem.
            os.link(temporary, base, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
    if not plan['code_exists']:
        parents(host, code.parent)
        container = Path(tempfile.mkdtemp(prefix='.eqemu-code-', dir=code.parent))
        temporary = container/'code'
        temporary.mkdir(mode=0o700)
        try:
            for name in DIRECTORIES[1:]:
                (temporary/name).mkdir(mode=0o755)
                (temporary/name).chmod(0o755)
            for name, data in plan['data'].items():
                path = temporary/name
                with path.open('xb') as target:
                    target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
                path.chmod(0o755 if name.startswith('scripts/') else 0o644)
                host.chown(path, submitter.pw_uid, submitter.pw_gid)
            # Hand off descendants while the root remains private and root-owned.
            for name in reversed(DIRECTORIES[1:]):
                host.chown(temporary/name, submitter.pw_uid, submitter.pw_gid)
            temporary.chmod(0o755)
            host.chown(temporary, submitter.pw_uid, submitter.pw_gid)
            if code.exists() or code.is_symlink():
                raise ValueError('Code destination appeared during staging')
            temporary.rename(code)
        finally:
            shutil.rmtree(container)
