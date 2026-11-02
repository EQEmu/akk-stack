"""Finite additive ASan worker package/operator. No ordinary release is replaced.

Preparation is unprivileged. Apply/rollback require a real root operator outside
the agent's NoNewPrivs boundary. Root only copies verified data and loads policy;
the nonroot systemd worker alone executes the trusted runtime and guest payload.
"""
import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile

NAME = 'eqemu-validator-asan-v3'
CONFIG = Path('/etc/eqemu-validator/config.json')
DIAGNOSTIC_CONFIG = Path('/etc/eqemu-validator/asan-v3.json')
PARENT = Path('/srv/eqemu-validator-asan-v3')
STATE = Path('/var/lib/eqemu-validator/asan-v3')
RETAINED_STATE = Path('/var/lib/eqemu-validator/asan-v1')
RETAINED_V1 = (Path('/etc/eqemu-validator/asan-v1.json'),
    Path('/etc/systemd/system/eqemu-validator-asan-v1.socket'),
    Path('/etc/systemd/system/eqemu-validator-asan-v1@.service'),
    Path('/etc/apparmor.d/eqemu-validator-asan-v1'))
RETAINED_V2 = (Path('/etc/eqemu-validator/asan-v2.json'),
    Path('/etc/systemd/system/eqemu-validator-asan-v2.socket'),
    Path('/etc/systemd/system/eqemu-validator-asan-v2@.service'),
    Path('/etc/apparmor.d/eqemu-validator-asan-v2'))
PROFILE = 'asan-ubsan-native-v1'
ORDINARY = (CONFIG, Path('/etc/systemd/system/eqemu-validator.socket'),
    Path('/etc/systemd/system/eqemu-validator@.service'), Path('/etc/apparmor.d/eqemu-validator'))


def sha(data): return hashlib.sha256(data).hexdigest()


def load(path, limit=1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Expected bounded regular data file: ' + str(path))
        data = stream.read(limit + 1)
        if len(data) != info.st_size: raise ValueError('Data changed during read')
        return data


def run(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=30, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    if result.returncode: raise RuntimeError('Operator command failed: ' + repr(argv) + ': ' + result.stderr[-1000:])
    return result.stdout


def retained_assets(version, release_files):
    """Retain policy AND installed immutable helper bytes for each older selection."""
    paths = RETAINED_V1 if version == 1 else RETAINED_V2
    config = json.loads(load(paths[0]))
    name = 'eqemu-validator-asan-v' + str(version)
    code = config.get('code_dir', '')
    if (not re.fullmatch('/srv/' + name + '/[a-f0-9]{40}', code)
            or config.get('diagnostic_profile') != PROFILE
            or config.get('diagnostic_policy', 'eqemu-validator-asan-v1') != name
            or config.get('socket') != '/run/' + name + '.sock'
            or config.get('state_dir') != '/var/lib/eqemu-validator/asan-v' + str(version)):
        raise ValueError('Retained diagnostic selection differs from inspected baseline')
    return (*paths, *(Path(code) / item for item in release_files))


def preconditions(manifest):
    """Preserve ordinary/v1/v2 assets and require all four workers to be idle."""
    if os.geteuid() != 0: raise ValueError('Real root operator required; do not bypass NoNewPrivs')
    for name, expected in manifest['ordinary_sha256'].items():
        if sha(load(Path(name))) != expected: raise ValueError('Ordinary policy changed: ' + name)
    for version in (1, 2):
        values = manifest['retained_v' + str(version) + '_sha256']
        if set(values) != {str(path) for path in retained_assets(version, manifest['release_files'])}:
            raise ValueError('Retained policy inventory mismatch')
        for name, expected in values.items():
            if sha(load(Path(name))) != expected: raise ValueError('Retained policy changed: ' + name)
    current = json.loads(load(CONFIG))
    expected = dict(manifest['configuration'])
    expected.pop('diagnostic_profile'); expected.pop('diagnostic_policy'); expected.update(code_dir='/srv/eqemu-validator-code',
        state_dir='/var/lib/eqemu-validator', socket='/run/eqemu-validator.sock')
    if current != expected: raise ValueError('Ordinary configuration differs from inspected baseline')
    units = run(['/usr/bin/systemctl', 'list-units', '--all', '--no-legend', '--plain',
        'eqemu-validator@*.service', 'eqemu-validator-asan-v1@*.service', 'eqemu-validator-asan-v2@*.service', NAME + '@*.service'])
    if units.strip(): raise ValueError('Worker connections must be absent')
    for directory in (Path(current['state_dir']), RETAINED_STATE, Path('/var/lib/eqemu-validator/asan-v2'), STATE):
        if (directory / 'active.json').exists(): raise ValueError('Worker active record requires inspection')
    return current


def protected(path):
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Expected protected root directory: ' + str(parent))


def publish(path, data, mode=0o644):
    protected(path.parent)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(mode)
        # Only complete bytes become a final target, atomically without replacing
        # anything. A failed write/fsync leaves no partial final policy to adopt.
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally: temporary.unlink(missing_ok=True)


def root_operator():
    path = Path(__file__).absolute()
    if os.geteuid() != 0: raise ValueError('Real root operator required; do not bypass NoNewPrivs')
    protected(path.parent)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Execute only an externally verified root-owned isolated operator copy')


def expected_targets(manifest):
    release = PARENT / manifest['source_commit']
    return {**{'release/' + name: release / name for name in manifest['release_files']},
        'config.json': DIAGNOSTIC_CONFIG,
        'worker.socket': Path('/etc/systemd/system') / (NAME + '.socket'),
        'worker.service': Path('/etc/systemd/system') / (NAME + '@.service'),
        'apparmor': Path('/etc/apparmor.d') / NAME}


def package(directory, expected):
    raw = load(directory / 'manifest.json')
    if sha(raw) != expected: raise ValueError('Package manifest SHA256 mismatch')
    manifest = json.loads(raw)
    if (manifest.get('profile') != PROFILE or not re.fullmatch('[a-f0-9]{40}', manifest.get('source_commit', ''))
            or manifest.get('release_files') != sorted(manifest['release_files'])
            or len(manifest['release_files']) > 64
            or any(not re.fullmatch(r'(?:scripts|validation)(?:/[a-zA-Z0-9_.-]+)+', name)
                   or '..' in name.split('/') for name in manifest['release_files'])):
        raise ValueError('Invalid finite diagnostic manifest')
    targets = expected_targets(manifest)
    if set(manifest['files']) != set(targets): raise ValueError('Package file inventory mismatch')
    data = {name: load(directory / name) for name in targets}
    if any(sha(data[name]) != digest for name, digest in manifest['files'].items()):
        raise ValueError('Diagnostic package bytes changed')
    if sha(load(Path(__file__))) != manifest['operator_sha256']:
        raise ValueError('Operator source differs from reviewed package')
    return manifest, data, targets


def operate(directory, expected, rollback=False):
    root_operator()
    manifest, data, targets = package(directory, expected)
    current = preconditions(manifest)
    lock_path = Path(current['state_dir']) / 'worker.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != current['worker_uid'] or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('Shared worker lock ownership/mode changed')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Recheck after taking the lock so an intervening connection cannot
        # leave an active record between the initial inspection and admission.
        preconditions(manifest)
        # The same lock is held through all policy/selection changes. Never
        # rerun a failed validator or start a VM during admission/rollback.
        if rollback:
            for name, target in targets.items():
                if not name.startswith('release/') and (target.exists() or target.is_symlink()) and sha(load(target)) != sha(data[name]):
                    raise ValueError('Diagnostic policy changed; refusing rollback')
            if targets['worker.socket'].exists(): run(['/usr/bin/systemctl', 'stop', NAME + '.socket'])
            if any(line.startswith(NAME + ' (') for line in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()):
                run(['/usr/sbin/apparmor_parser', '--remove', str(targets['apparmor'])])
            for name, target in targets.items():
                if not name.startswith('release/'): target.unlink(missing_ok=True)
            run(['/usr/bin/systemctl', 'daemon-reload'])
            return dict(rolled_back=True, ordinary_unchanged=True, release_and_evidence_retained=True, vm_started=False)
        release = PARENT / manifest['source_commit']
        for target in targets.values():
            if target.exists() or target.is_symlink(): raise ValueError('Diagnostic target already exists: ' + str(target))
        if STATE.exists() or STATE.is_symlink(): raise ValueError('Diagnostic state already exists; inspect it')
        # Parse policy files before installing anything. They contain no code.
        with tempfile.TemporaryDirectory(prefix='eqemu-asan-policy-') as temporary:
            temporary = Path(temporary)
            for name, filename in (('apparmor', 'apparmor'), ('worker.socket', NAME + '.socket'),
                                   ('worker.service', NAME + '@.service')):
                (temporary / filename).write_bytes(data[name])
            run(['/usr/sbin/apparmor_parser', '--skip-kernel-load', '--skip-cache', str(temporary / 'apparmor')])
            run(['/usr/bin/systemd-analyze', 'verify', '--generators=no', '--man=no',
                str(temporary / (NAME + '.socket')), str(temporary / (NAME + '@.service'))])
        if not PARENT.exists():
            protected(PARENT.parent); PARENT.mkdir(mode=0o755); PARENT.chmod(0o755)
        protected(PARENT)
        release.mkdir(mode=0o755); release.chmod(0o755)
        for name, target in targets.items():
            if name.startswith('release/'):
                for parent in reversed(target.parent.relative_to(release).parents):
                    (release / parent).mkdir(mode=0o755, exist_ok=True)
                    (release / parent).chmod(0o755)
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                target.parent.chmod(0o755)
            publish(target, data[name], 0o755 if '/scripts/' in str(target) else 0o644)
        # The state is separate; only worker.lock is shared with ordinary runs.
        STATE.mkdir(mode=0o700); STATE.chmod(0o700); os.chown(STATE, current['worker_uid'], current['worker_gid'])
        run(['/usr/sbin/apparmor_parser', '--replace', str(targets['apparmor'])])
        run(['/usr/bin/systemctl', 'daemon-reload'])
        run(['/usr/bin/systemctl', 'start', NAME + '.socket'])
        run(['/usr/bin/systemctl', 'is-active', NAME + '.socket'])
        for field in ('ordinary_sha256', 'retained_v1_sha256', 'retained_v2_sha256'):
            for name, expected_sha in manifest[field].items():
                if sha(load(Path(name))) != expected_sha: raise ValueError('Retained policy changed during admission: ' + name)
        return dict(admitted=True, configuration=str(DIAGNOSTIC_CONFIG), release=str(release),
                    ordinary_unchanged=True, vm_started=False, enabled_at_boot=False)
    finally: os.close(fd)


def prepare(output):
    if os.geteuid() == 0: raise ValueError('Prepare as ordinary submitter')
    from staging import FILES
    root = Path(__file__).resolve().parents[2]
    current = json.loads(load(CONFIG))
    if current['code_dir'] != '/srv/eqemu-validator-code' or current['state_dir'] != '/var/lib/eqemu-validator':
        raise ValueError('Diagnostic operator supports only the inspected installed baseline')
    commit = run(['/usr/bin/git', '-C', str(root), 'rev-parse', 'HEAD']).strip()
    if run(['/usr/bin/git', '-C', str(root), 'status', '--porcelain']).strip():
        raise ValueError('Commit/review the trusted Stack release first')
    if output.exists(): raise ValueError('Use a fresh package directory')
    output.mkdir(mode=0o700, parents=True)
    release = PARENT / commit
    config = dict(current, code_dir=str(release), state_dir=str(STATE),
                  socket='/run/' + NAME + '.sock', diagnostic_profile=PROFILE, diagnostic_policy=NAME)
    replacements = dict(USER=current['user'], STATE=current['state_dir'], CODE=str(release),
        BASE=current['base_image'], SOCKET=config['socket'],
        SUBMITTER_GROUP=grp.getgrgid(pwd.getpwnam(current['submitter']).pw_gid).gr_name)
    files = {'release/' + name: load(root / name) for name in FILES}
    files['config.json'] = (json.dumps(config, indent=2) + '\n').encode()
    for template, name in (('eqemu-validator.socket', 'worker.socket'),
                           ('eqemu-validator@.service', 'worker.service'), ('apparmor', 'apparmor')):
        text = (root / 'validation/worker/templates' / template).read_text()
        for key, value in replacements.items(): text = text.replace('@' + key + '@', value)
        text = text.replace('/etc/eqemu-validator/config.json', str(DIAGNOSTIC_CONFIG))
        if name == 'apparmor':
            text = text.replace('eqemu-validator flags=', NAME + ' flags=')
            text = text.replace('peer=eqemu-validator', 'peer=' + NAME).replace('eqemu-validator//&', NAME + '//&').replace('//&eqemu-validator', '//&' + NAME)
            text = text.replace(current['state_dir'] + '/** rwk,', str(STATE) + '/** rwk,\n  ' + str(STATE) + '/ rw,\n  ' + current['state_dir'] + '/worker.lock rwk,')
        else:
            text = text.replace('AppArmorProfile=eqemu-validator', 'AppArmorProfile=' + NAME)
        files[name] = text.encode()
    for name, data in files.items():
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    # Parser-only aliases have the correct systemd filenames and identical bytes.
    (output / (NAME + '.socket')).write_bytes(files['worker.socket'])
    (output / (NAME + '@.service')).write_bytes(files['worker.service'])
    operator = load(Path(__file__)); (output / 'operator.py').write_bytes(operator)
    manifest = dict(profile=PROFILE, source_commit=commit, configuration=config,
        release_files=sorted(FILES), files={name: sha(data) for name, data in files.items()},
        ordinary_sha256={str(path): sha(load(path)) for path in [*ORDINARY,
            *[Path(current['code_dir']) / name for name in FILES if name != 'validation/worker/sanitizers.py']]},
        **{'retained_v' + str(version) + '_sha256': {str(path): sha(load(path))
            for path in retained_assets(version, FILES)} for version in (1, 2)},
        operator_sha256=sha(operator))
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    (output / 'manifest.json').write_bytes(raw)
    trusted_operator = '/root/eqemu-asan-operator-' + sha(operator) + '.py'
    return dict(package=str(output), manifest_sha256=sha(raw), source_commit=commit,
        operator_sha256=sha(operator),
        install_operator=['/usr/bin/install', '-o', 'root', '-g', 'root', '-m', '0500', str(output / 'operator.py'), trusted_operator],
        verify_operator_sha256=sha(operator) + '  ' + trusted_operator,
        prerequisite='Externally verify the root-owned copy against verify_operator_sha256 before executing it; always Python -I',
        apply=['/usr/bin/python3', '-I', trusted_operator, 'apply', str(output), sha(raw)],
        rollback=['/usr/bin/python3', '-I', trusted_operator, 'rollback', str(output), sha(raw)], vm_started=False)


def prepare_main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output.absolute()), sort_keys=True)); return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('apply', 'rollback')); parser.add_argument('package', type=Path)
    parser.add_argument('manifest_sha256'); args = parser.parse_args()
    print(json.dumps(operate(args.package, args.manifest_sha256, args.operation == 'rollback'), sort_keys=True))
