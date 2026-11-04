#!/usr/bin/python3
"""One offline build/test job. Run only inside the disposable guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import time

WORK = Path('/opt/eqemu-build')
MEDIA = Path('/opt/build-inputs')
LOGS = WORK / 'runtime-logs'


def emit(value):
    print('EQEMU_RUNTIME ' + json.dumps(value, separators=(',', ':')), flush=True)

ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
       'LANG': 'C.UTF-8', 'HOME': '/root', 'DEBIAN_FRONTEND': 'noninteractive',
       'VCPKG_DISABLE_METRICS': '1', 'VCPKG_MAX_CONCURRENCY': '1',
       'VCPKG_BINARY_SOURCES': 'clear', 'X_VCPKG_ASSET_SOURCES': 'clear;x-block-origin',
       'CCACHE_DISABLE': '1', 'CMAKE_BUILD_PARALLEL_LEVEL': '1'}
STAGE = 'guest-start'
DEADLINE = 0
CHECKS = ()
PROFILE = None
SANITIZERS = None
COMPLETED = []
PROFILING = None
BUILD_METADATA = {}
INFRASTRUCTURE = re.compile(
    r'out of memory|cannot allocate memory|no space left|killed signal|command not found|'
    r'failed to download|no matching package named|attempting to make an HTTP request|'
    r'failed to get .+ as a dependency|could not execute process|'
    r'failed to select a version for the requirement|could not find (?:a |the )?(?:package|configuration file)|'
    r'could not find a configuration file for package|could NOT find', re.I)


class CandidateFailure(RuntimeError):
    pass


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(name, args, *, cwd=None, candidate=False, seconds=900):
    """Bound and stream tool output. Only candidate phases may return candidate failure."""
    global STAGE
    STAGE = name
    print('EQEMU_STAGE ' + name, flush=True)
    end = min(DEADLINE, time.monotonic() + seconds)
    tail = bytearray(); total = 0; infrastructure_failure = False
    process = subprocess.Popen(args, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or process.poll() is None:
                if time.monotonic() >= end:
                    raise RuntimeError(name + ': deadline exceeded')
                for key, _ in selector.select(.2):
                    block = os.read(key.fd, 65536)
                    if not block:
                        eof = True; selector.unregister(key.fileobj); continue
                    total += len(block)
                    if total > 32 * 1024**2:
                        raise RuntimeError(name + ': output limit exceeded')
                    tail.extend(block)
                    infrastructure_failure |= bool(INFRASTRUCTURE.search(tail.decode(errors='replace')))
                    del tail[:-8192]
                    # Console is the retained diagnostic channel. No artifact/export protocol.
                    offset = 0
                    while offset < len(block):
                        offset += os.write(1, block[offset:])
        code = process.wait(timeout=5)
        if code:
            detail = tail.decode(errors='replace')
            sanitized_signal = PROFILE and re.search(r'AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|runtime error:', detail)
            infrastructure = (code < 0 and not sanitized_signal) or code in (126, 127) or infrastructure_failure
            error = CandidateFailure if candidate and not infrastructure else RuntimeError
            failure = error(name + ': exit ' + str(code) + '\n' + detail[-3000:])
            failure.returncode = code
            failure.output = detail
            raise failure
        if name in CHECKS:
            COMPLETED.append(name)
        return tail.decode(errors='replace')
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)
        process.stdout.close()


def extract(archive, target):
    """Guest-local, bounded extraction including safe internal toolchain links."""
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as stream:
        total = 0; count = 0
        for member in stream:
            total += member.size; count += 1
            if total > 3 * 1024**3 or count > 50000 or time.monotonic() >= DEADLINE:
                raise RuntimeError('Archive budget exceeded')
            stream.extract(member, target, filter='data')


def provision():
    """Install only the packages already present in the verified public input ISO."""
    global STAGE
    STAGE = 'input-verification'
    identity = json.loads(Path('/media/eqemu-input/identity.json').read_text())
    for name, expected in identity['files'].items():
        path = Path('/media/eqemu-input') / name
        if path.stat().st_size != expected['bytes'] or sha(path) != expected['sha256']:
            raise RuntimeError('Changed input: ' + name)
    command('mount-native-inputs', ['mount', '-o', 'loop,ro,nosuid,nodev',
                                   '/media/eqemu-input/native.iso', str(MEDIA)])
    manifest = json.loads((MEDIA / 'bundle-manifest.json').read_text())
    if sha(MEDIA / 'bundle-manifest.json') != '95eb1cf160fdc3704d17d9d18be0919ed393f6951a98f6143a144b2c91b8f7e4':
        raise RuntimeError('Native input manifest mismatch')
    for entry in manifest['files']:
        path = MEDIA / entry['path']
        if path.stat().st_size != entry['bytes'] or sha(path) != entry['sha256']:
            raise RuntimeError('Native input mismatch: ' + entry['path'])
    apt = WORK / 'apt'
    for directory in ('lists/partial', 'archives/partial', 'parts', 'sources', 'log'):
        (apt / directory).mkdir(parents=True)
    for source, target in (('apt-lists', 'lists'), ('debs', 'archives')):
        for path in (MEDIA / source).iterdir():
            shutil.copyfile(path, apt / target / path.name)
    (apt / 'empty.conf').touch()
    (apt / 'sources.list').write_text('\n'.join(
        f'deb [arch=amd64 signed-by={MEDIA}/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu {suite} main universe'
        for suite in ('noble', 'noble-updates', 'noble-security')) + '\n')
    (apt / 'apt.conf').write_text(f'''Dir::Etc "{apt}";
Dir::Etc::main "{apt}/empty.conf";
Dir::Etc::parts "{apt}/parts";
Dir::Etc::sourcelist "{apt}/sources.list";
Dir::Etc::sourceparts "{apt}/sources";
Dir::State "{apt}";
Dir::State::lists "{apt}/lists";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache "{apt}";
Dir::Cache::archives "{apt}/archives";
Dir::Log "{apt}/log";
APT::Install-Recommends "false";
''')
    ENV['APT_CONFIG'] = str(apt / 'apt.conf')
    for index, path in enumerate(sorted((MEDIA / 'apt-lists').glob('*InRelease'))):
        command('package-signature-' + str(index), ['gpgv', '--keyring', str(MEDIA / 'ubuntu-archive-keyring.gpg'), str(path)])
    packages = json.loads((MEDIA / 'provenance/ubuntu-package-proof.json').read_text())['packages']
    pins = [item['package'] + '=' + item['version'] for item in packages]
    policy = Path('/usr/sbin/policy-rc.d')
    if policy.exists():
        raise RuntimeError('Unexpected service-start policy')
    policy.write_text('#!/bin/sh\nexit 101\n'); policy.chmod(0o755)
    try:
        command('offline-package-install', ['apt-get', '--no-download', '--no-remove', '-y',
                                           '-o', 'Dpkg::Options::=--force-confold', 'install', *pins])
    finally:
        policy.unlink()
    if command('package-audit', ['dpkg', '--audit']).strip():
        raise RuntimeError('Incomplete package installation')
    return identity


def prepare_source():
    source = WORK / 'source'
    extract('/media/eqemu-input/eqemu.tar', source)
    websocket = source / 'submodules/websocketpp'
    extract('/media/eqemu-input/websocketpp.tar', websocket)
    registry = source / 'submodules/vcpkg'
    if registry.exists():
        registry.rmdir()
    command('registry-clone', ['git', 'clone', str(MEDIA / 'sources/vcpkg.bundle'), str(registry)])
    command('registry-checkout', ['git', '-C', str(registry), 'checkout', '--detach', 'd1ff36c6520ee43f1a656c03cd6425c2974a449e'])
    shutil.copyfile(MEDIA / 'tools/vcpkg', registry / 'vcpkg'); (registry / 'vcpkg').chmod(0o755)
    downloads = WORK / 'downloads'; shutil.copytree(MEDIA / 'downloads', downloads)
    ENV.update(VCPKG_ROOT=str(registry), VCPKG_DOWNLOADS=str(downloads))
    return source, registry


def prepare_rust():
    rust = WORK / 'rust'; extract('/media/eqemu-input/rust-inputs.tar', rust / 'inputs')
    prefix = rust / 'toolchain'
    for component in ('rustc', 'cargo', 'rust-std', 'rustfmt-preview', 'clippy-preview'):
        unpacked = rust / component; extract(rust / 'inputs' / (component + '.tar.xz'), unpacked)
        installers = list(unpacked.glob('*/install.sh'))
        if len(installers) != 1:
            raise RuntimeError('Missing toolchain installer: ' + component)
        command('install-' + component, ['/bin/sh', str(installers[0]), '--prefix=' + str(prefix), '--disable-ldconfig'])
    vendor = rust / 'vendor'; extract(rust / 'inputs/vendor.tar', vendor)
    home = rust / 'home'; home.mkdir()
    (home / 'config.toml').write_text((rust / 'inputs/vendor-config.toml').read_text().replace('@VENDOR@', str(vendor)))
    ENV.update(PATH=str(prefix / 'bin') + ':' + ENV['PATH'], RUSTC=str(prefix / 'bin/rustc'),
               RUSTDOC=str(prefix / 'bin/rustdoc'), RUSTFMT=str(prefix / 'bin/rustfmt'),
               RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', CARGO_HOME=str(home),
               CARGO_TARGET_DIR=str(rust / 'target'), CARGO_NET_OFFLINE='true',
               CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', RUSTUP_AUTO_INSTALL='0')
    return str(prefix / 'bin/cargo')


def configure_native(source, registry, seconds=14400):
    if PROFILE is not None and PROFILING is not None:
        raise RuntimeError('Sanitizers and profiling are mutually exclusive')
    output = WORK / 'build'
    profile_flags = ['-DCMAKE_C_FLAGS=-fno-omit-frame-pointer', '-DCMAKE_CXX_FLAGS=-fno-omit-frame-pointer'] if PROFILING else []
    command('native-configure', ['cmake', '-S', str(source), '-B', str(output), '-G', 'Ninja',
            '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', *profile_flags,
            '-DCMAKE_TOOLCHAIN_FILE=' + str(registry / 'scripts/buildsystems/vcpkg.cmake'),
            '-DVCPKG_TARGET_TRIPLET=x64-linux', '-DVCPKG_HOST_TRIPLET=x64-linux',
            '-DVCPKG_INSTALL_OPTIONS=--no-downloads;--binarysource=clear',
            *['-DEQEMU_BUILD_' + name + '=ON' for name in ('SERVER', 'TESTS', 'LOGIN', 'LUA', 'PERL', 'CLIENT_FILES')],
            *(['-DEQEMU_SANITIZERS=ON'] if PROFILE else [])],
            candidate=True, seconds=seconds)
    if PROFILING:
        global BUILD_METADATA
        cache=(output/'CMakeCache.txt').read_text()
        selected={row.split('=',1)[0]:row.split('=',1)[1] for row in cache.splitlines() if '=' in row and row.startswith(('CMAKE_C_FLAGS', 'CMAKE_CXX_FLAGS', 'CMAKE_BUILD_TYPE:', 'CMAKE_C_COMPILER:', 'CMAKE_CXX_COMPILER:', 'EQEMU_'))}
        if '-fsanitize' in cache or re.search(r'^[^#\n]*SANIT[^=]*=ON$',cache,re.M|re.I):
            raise RuntimeError('Allocation/CPU profiling requires unsanitized build; use separate correctness run')
        BUILD_METADATA=dict(kind='symbolized-unsanitized-profiling', cmake_cache_sha256=sha(output/'CMakeCache.txt'), flags=selected,
            rustflags=ENV.get('RUSTFLAGS',''), compiler=command('profile-compiler',['c++','--version']),
            compiler_sha256=sha('/usr/bin/c++'))
    return output


def build():
    global SANITIZERS
    if PROFILE is not None and PROFILING is not None:
        raise RuntimeError('Sanitizers and profiling are mutually exclusive')
    source, registry = prepare_source()
    cargo = prepare_rust()
    if PROFILING: ENV['RUSTFLAGS']='-C force-frame-pointers=yes -C debuginfo=2'
    else: ENV.pop('RUSTFLAGS', None)
    workspace = source / 'rust/actors'
    command('rust-format', [cargo, 'fmt', '--all', '--check'], cwd=workspace, candidate=True)
    # Resolve the available offline closure before compiling candidate code. Missing
    # versions/packages stop as infrastructure rather than consuming candidate repairs.
    command('rust-dependencies', [cargo, 'metadata', '--format-version=1', '--locked', '--offline'], cwd=workspace)
    for stage, args in (
            ('rust-clippy', ['clippy', '--workspace', '--all-targets', '--locked', '--offline', '--', '-D', 'warnings']),
            ('rust-tests', ['test', '--workspace', '--locked', '--offline', '--lib', '--tests']),
            ('rust-doctests', ['test', '--workspace', '--locked', '--offline', '--doc'])):
        command(stage, [cargo, *args], cwd=workspace, candidate=True)
    output = configure_native(source, registry)
    if PROFILE:
        from sanitizers import controls
        SANITIZERS = controls(sys.modules[__name__], output)
    command('native-build', ['cmake', '--build', str(output), '--parallel', '1'], candidate=True, seconds=14400)
    if PROFILE:
        from sanitizers import final_binaries
        final_binaries(sys.modules[__name__], output, SANITIZERS)
    # Filter while draining the complete symbol stream; never retain the full nm table.
    command('zone-rust-symbol', ['/bin/bash', '-o', 'pipefail', '-c',
            'nm --defined-only "$1" | awk \'$2 ~ /^[Tt]$/ && $3 == "eqemu_rust_bridge_v1" {found=1} END {exit !found}\'',
            'zone-symbol', str(output / 'bin/zone')], candidate=True, seconds=120)
    if PROFILING:
        for name in ('world','zone'):
            command('profile-unsanitized-'+name,['/bin/bash','-o','pipefail','-c',
                'nm -D "$1" | awk \'/__asan_init|__ubsan_handle/ {found=1} END {exit found ? 1 : 0}\'',
                'unsanitized-check',str(output/'bin'/name)])
    try:
        tests = command('native-utilities', [str(output / 'bin/tests')], cwd=output, candidate=True, seconds=600)
    except RuntimeError as error:
        # A printed passed frame never overrides a later LSan nonzero exit.
        frames = [json.loads(line.removeprefix('EQEMU_TEST_RESULT '))
                  for line in getattr(error, 'output', '').splitlines() if line.startswith('EQEMU_TEST_RESULT ')]
        if len(frames) == 1: error.utilities = frames[0]
        raise
    frames = [json.loads(line.removeprefix('EQEMU_TEST_RESULT ')) for line in tests.splitlines() if line.startswith('EQEMU_TEST_RESULT ')]
    if len(frames) != 1:
        raise RuntimeError('Native utilities did not complete')
    result = frames[0]
    if not (result.get('passed') is True and result.get('finalized') is True and result.get('selected', 0) > 0
            and result['selected'] == result.get('started') == result.get('completed') and result.get('failed') == 0):
        raise RuntimeError('Native utility completion is incomplete or inconsistent')
    if PROFILING:
        BUILD_METADATA['compile_commands_sha256']=sha(output/'compile_commands.json')
        BUILD_METADATA['binary_notes']={name:command('profile-binary-notes-'+name,['readelf','-n',str(output/'bin'/name)]) for name in ('world','zone')}
    return {'zone_sha256': sha(output / 'bin/zone'), 'utilities': result}


def main():
    global DEADLINE, CHECKS, STAGE, PROFILE, PROFILING, WORK, LOGS
    if os.geteuid() != 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Disposable build guest only')
    nonce = Path('/opt/eqemu-worker-nonce').read_text().strip()
    if Path('/opt/eqemu-worker-profile').exists():
        from sanitizers import PROFILE as SELECTED_PROFILE, ENV as SANITIZER_ENV
        PROFILE = Path('/opt/eqemu-worker-profile').read_text().strip()
        if PROFILE != SELECTED_PROFILE: raise RuntimeError('Unknown guest profile')
        WORK = Path('/opt/eqemu-build-' + PROFILE); LOGS = WORK / 'runtime-logs'
        ENV.update(SANITIZER_ENV)
    CHECKS = tuple(json.loads(Path('/opt/eqemu-worker-checks.json').read_text()))
    COMPLETED.clear()
    result = dict(version=1, scope='worker-build', nonce=nonce, exit_code=2,
                  selected_checks=list(CHECKS), completed_checks=COMPLETED)
    DEADLINE = time.monotonic() + 17400
    try:
        WORK.mkdir(); MEDIA.mkdir()
        Path('/media/eqemu-input').mkdir(parents=True)
        command('mount-job', ['mount', '-o', 'ro,nosuid,nodev', '/dev/sr1', '/media/eqemu-input'])
        identity = provision()
        if identity.get('diagnostic_profile') != PROFILE: raise RuntimeError('Guest input profile mismatch')
        PROFILING=identity.get('profiling')
        if PROFILING is not None and PROFILE is not None: raise RuntimeError('Sanitizers and profiling are mutually exclusive')
        if PROFILING is not None:
            from profiling import MODES, TOOLS, file_identity
            if PROFILING not in MODES: raise RuntimeError('Unknown profiling mode')
            if 'profilers.tar' in identity['files']:
                from profile_inputs import install
                install(sys.modules[__name__], '/media/eqemu-input/profilers.tar', PROFILING)
            for path in TOOLS.get(PROFILING,()): file_identity(path)
        result.update(build())
        STAGE = 'normal-world'
        print('EQEMU_STAGE normal-world', flush=True)
        LOGS.mkdir()
        from normal_world import run
        result['normal_world'] = run(sys.modules[__name__], identity)
        COMPLETED.append('normal-world')
        result['exit_code'] = 0
    except Exception as error:
        if getattr(error, 'sanitizers', None): result['sanitizers'] = error.sanitizers
        if getattr(error, 'utilities', None): result['utilities'] = error.utilities
        if PROFILE and hasattr(error, 'returncode'): result['process_returncode'] = error.returncode
        if isinstance(getattr(error, 'result', None), dict):
            result['normal_world'] = error.result
        result.update(exit_code=1 if isinstance(error, CandidateFailure) else 2, error=str(error)[-3500:])
    if PROFILE:
        result['diagnostic_profile'] = PROFILE
        if SANITIZERS is not None: result['sanitizers'] = SANITIZERS
    # Bound encoded error bytes too; escaped Unicode must fit the 32 KiB frame.
    while len(json.dumps(result.get('error', ''))) > 3500:
        result['error'] = result['error'][len(result['error'])//2:]
    result['stage'] = STAGE
    print('\nEQEMU_WORKER_RESULT ' + json.dumps(result, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    main()
