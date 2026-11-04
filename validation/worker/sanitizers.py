"""Fixed native ASan/UBSan diagnostic policy, executed only in the offline guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import time

PROFILE = 'asan-ubsan-native-v1'
POLICIES = ('eqemu-validator-asan-v1', 'eqemu-validator-asan-v2', 'eqemu-validator-asan-v3')
ENV = dict(ASAN_OPTIONS='halt_on_error=1:abort_on_error=0:detect_leaks=1:symbolize=1:exitcode=1',
           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1:exitcode=1',
           ASAN_SYMBOLIZER_PATH='/usr/bin/addr2line')
FLAGS = ('-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-g', '-O1',
         '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls')
MODES = ('pass', 'use-after-free', 'out-of-bounds', 'undefined', 'leak')


def policy_name(config):
    """Select only reviewed policies; legacy diagnostic configs retain v1."""
    if config.get('diagnostic_profile') is None:
        if 'diagnostic_policy' in config:
            raise ValueError('Diagnostic policy requires a diagnostic profile')
        return 'eqemu-validator'
    policy = config.get('diagnostic_policy', POLICIES[0])
    if config['diagnostic_profile'] != PROFILE or policy not in POLICIES:
        raise ValueError('Unknown diagnostic policy')
    return policy


def checks(ordinary, profile):
    if profile is None: return ordinary
    if profile != PROFILE: raise ValueError('Unknown diagnostic profile')
    value = list(ordinary)
    value.insert(value.index('native-build'), 'sanitizer-controls')
    return tuple(value)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_commands(output):
    """Inspect real generated commands, including final links and known gaps."""
    database = output / 'compile_commands.json'
    if database.stat().st_size > 32 * 1024**2: raise RuntimeError('Compile command budget')
    entries = json.loads(database.read_text())
    counts = {}
    for entry in entries:
        argv = entry.get('arguments') or shlex.split(entry['command'])
        name = Path(entry['file']).as_posix()
        if '/CMakeFiles/' not in entry.get('output', entry.get('command', '')):
            continue
        group = next((group for group in ('common', 'tests', 'world', 'zone') if '/' + group + '/' in name), None)
        if group and '/tests/cppunit/' not in name:
            if not all(flag in argv for flag in FLAGS):
                raise RuntimeError('Missing sanitizer compile flags: ' + name)
            optimizations = [flag for flag in argv if re.fullmatch('-O[0-3sgz]', flag)]
            exception = bool(re.search(r'/common/patches/(?:sod|sof|rof|rof2|uf)\.cpp$', name))
            if not optimizations or optimizations[-1] != ('-O0' if exception else '-O1'):
                raise RuntimeError('Unexpected sanitizer optimization: ' + name)
            counts[group] = counts.get(group, 0) + 1
    if set(counts) != {'common', 'tests', 'world', 'zone'}:
        raise RuntimeError('Missing project compile coverage')
    return dict(compile_commands_sha256=digest(database), native_compile_counts=counts,
        exclusions=['Cargo-generated CXX and Rust archives', 'separate dependency builds/imported libraries', 'vendored cppunit'],
        optimization_exceptions=['common/patches/' + name + '.cpp:-O0' for name in ('sod', 'sof', 'rof', 'rof2', 'uf')])


def validate_controls(report):
    if (not isinstance(report, dict) or report.get('profile') != PROFILE or report.get('environment') != ENV
            or report.get('qualified') is not True or not isinstance(report.get('controls'), list)
            or [item.get('mode') for item in report['controls']] != list(MODES)):
        raise RuntimeError('Incomplete sanitizer qualification')
    for item in report['controls']:
        code = item.get('returncode')
        if (item.get('qualified') is not True or type(code) is not int
                or (code != 0 if item['mode'] == 'pass' else code <= 0)
                or (item['mode'] != 'pass' and (item.get('symbolized') is not True
                    or not re.search(r'sanitizer_controls\.cpp:[0-9]+', item.get('output', ''))))):
            raise RuntimeError('Missing symbolized sanitizer non-pass evidence')
    binaries = report.get('binaries')
    if (not isinstance(binaries, dict) or set(binaries) != {'tests', 'world', 'zone', 'shared_memory'}
            or any(not isinstance(item, dict) or not re.fullmatch('[a-f0-9]{64}', item.get('sha256', ''))
                   or item.get('runtimes') != ['libasan', 'libubsan'] for item in binaries.values())):
        raise RuntimeError('Missing exact sanitized native binary identities')


def final_binaries(build, output, report):
    report['binaries'] = {}
    for name in ('tests', 'world', 'zone', 'shared_memory'):
        binary = output / 'bin' / name
        linkage = build.command('sanitizer-linkage-' + name, ['readelf', '-d', str(binary)])
        if not all(library in linkage for library in ('libasan', 'libubsan')):
            raise RuntimeError('Final sanitizer runtime linkage missing: ' + name)
        report['binaries'][name] = dict(sha256=digest(binary), runtimes=['libasan', 'libubsan'])


def controls(build, output):
    """Expected failures qualify diagnostics, never count as utility passes."""
    report = dict(profile=PROFILE, environment=ENV, controls=[], qualified=False)
    try:
        path = Path(ENV['ASAN_SYMBOLIZER_PATH'])
        if not path.is_file() or not os.access(path, os.X_OK):
            raise RuntimeError('Pinned symbolizer is unavailable')
        report['symbolizer'] = dict(path=str(path), sha256=digest(path),
            version=build.command('sanitizer-symbolizer', [str(path), '--version'])[:300])
        report['compiler'] = build.command('sanitizer-compiler', ['/usr/bin/g++', '--version'])[:300]
        report['runtime_packages'] = build.command('sanitizer-packages', ['dpkg-query', '-W',
            '-f=${Package}=${Version}\n', 'libasan8', 'libubsan1', 'binutils', 'g++', 'libc6'])[:1000]
        report['runtime_libraries'] = {}
        for library in ('libasan.so', 'libubsan.so'):
            library_path = build.command('sanitizer-runtime-' + library,
                ['/usr/bin/g++', '-print-file-name=' + library]).strip()
            if not Path(library_path).is_absolute(): raise RuntimeError('Sanitizer runtime library missing')
            report['runtime_libraries'][library] = dict(path=library_path, sha256=digest(library_path))
        report.update(verify_commands(output))
        build.command('sanitizer-control-build', ['cmake', '--build', str(output), '--target',
            'tests_sanitizer_controls', '--parallel', '1'], candidate=True)
        binary = output / 'bin/tests_sanitizer_controls'
        report['binary_sha256'] = digest(binary)
        linkage = build.command('sanitizer-control-linkage', ['readelf', '-d', str(binary)])
        report['runtime_linkage'] = '\n'.join(line for line in linkage.splitlines() if 'NEEDED' in line)[:1200]
        if not all(name in report['runtime_linkage'] for name in ('libasan', 'libubsan')):
            raise RuntimeError('Control sanitizer runtime linkage missing')
        for mode in MODES:
            start = time.monotonic()
            code = 0
            try:
                text = build.command('sanitizer-control-' + mode, [str(binary), mode], candidate=True, seconds=60)
            except RuntimeError as error:
                code = getattr(error, 'returncode', None)
                text = getattr(error, 'output', str(error))
            expected = {'use-after-free': r'heap-use-after-free',
                'out-of-bounds': r'heap-buffer-overflow|runtime error:.*(?:bounds|space)',
                'undefined': r'runtime error:.*(?:overflow|undefined)', 'leak': r'LeakSanitizer|detected memory leaks'}
            symbolized = bool(re.search(r'sanitizer_controls\.cpp:[0-9]+', text))
            qualified = code == 0 if mode == 'pass' else (
                type(code) is int and code > 0 and symbolized and bool(re.search(expected[mode], text, re.I)))
            report['controls'].append(dict(mode=mode, returncode=code, expected_nonpass=mode != 'pass',
                symbolized=symbolized, qualified=qualified, seconds=round(time.monotonic()-start, 3),
                output=text[:1800], output_truncated=len(text.encode()) > 1800))
            if not qualified: raise RuntimeError('Sanitizer control did not qualify: ' + mode)
        report['qualified'] = True
        report['guest_child_maxrss_kib'] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        build.COMPLETED.append('sanitizer-controls')
        return report
    except Exception as error:
        error.sanitizers = report
        raise
