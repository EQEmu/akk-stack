"""Package committed source and verified public inputs as data. No candidate execution."""
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import inputs

NATIVE_SHA = '02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'
RUST_SHA = '2a0b4a32ad74b3bb49195d43f76ece75166b500004f5b32f868cb20a292bc52f'
PAYLOAD_LIMIT = 1024**3


def record(path, limit=PAYLOAD_LIMIT):
    return inputs.file_record(Path(path), limit)


def prepare(repo, commit, websocketpp, native, rust, output, runtime=None, world_control=None, profiling=None, profiler_input=None, profiler_sha256=None):
    """Select a complete clean commit, without freezing Cargo manifests or test counts."""
    if profiling is not None:
        from profiling import MODES
        if profiling not in MODES: raise ValueError('Unknown profiling mode')
    if profiler_input is not None:
        from profile_inputs import manifest, digest
        if profiling not in ('heaptrack','perf') or digest(profiler_input)!=profiler_sha256:
            raise ValueError('Profiler input needs selected mode and exact SHA256')
        manifest(profiler_input)
    elif profiler_sha256 is not None:
        raise ValueError('Profiler SHA256 requires an input bundle')
    profile = json.loads((Path(__file__).resolve().parents[1] / 'profile.json').read_text())
    for path, expected in ((native, NATIVE_SHA), (rust, RUST_SHA)):
        if record(path)['sha256'] != expected:
            raise ValueError('Missing or changed offline input: ' + str(path))
    fixture = json.loads((Path(__file__).resolve().parents[1] / 'runtime-fixture.json').read_text())
    if runtime is None:
        raise ValueError('Normal-world validation requires the pinned public runtime ISO')
    if record(runtime) != {key: fixture['iso'][key] for key in ('bytes', 'sha256')}:
        raise ValueError('Missing/changed public runtime ISO: ' + str(runtime))
    if world_control not in (None, 'startup', 'assertion', 'cancel'):
        raise ValueError('Unknown normal-world control')
    with tempfile.TemporaryDirectory(prefix='eqemu-build-inputs-') as tmp:
        root = Path(tmp)
        scratch = root / 'git'; scratch.mkdir()
        view = inputs.GitTree(repo, scratch)
        commit = view.location('HEAD') if commit == 'HEAD' else commit
        if not re.fullmatch('[a-f0-9]{40}', commit):
            raise ValueError('Expected HEAD or a full commit SHA')
        tree = view.git('rev-parse', commit + '^{tree}').decode().strip()
        entries, links = view.inventory(commit, tree)
        if links != profile['sources']['eqemu']['gitlinks']:
            raise ValueError('Candidate requires different native submodule inputs')
        blobs = {entry['path']: entry['blob'] for entry in entries}
        if any(blobs.get(name) != blob for name, blob in profile['dependency_blobs'].items()):
            raise ValueError('Candidate requires different native dependency inputs')
        view.clean(commit, entries, links)
        archive = root / 'eqemu.tar'; view.archive(commit, archive)
        inputs.verify_archive(archive, entries, links)
        scratch = root / 'websocket-git'; scratch.mkdir()
        dependency = inputs.GitTree(websocketpp, scratch)
        wanted = profile['sources']['websocketpp']
        dep_entries, dep_links = dependency.inventory(wanted['commit'], wanted['tree'])
        dep_archive = root / 'websocketpp.tar'; dependency.archive(wanted['commit'], dep_archive)
        inputs.verify_archive(dep_archive, dep_entries, dep_links)
        files = {'eqemu.tar': archive, 'websocketpp.tar': dep_archive,
                 'native.iso': Path(native).resolve(), 'rust-inputs.tar': Path(rust).resolve(),
                 'runtime.iso': Path(runtime).resolve()}
        if profiler_input is not None: files['profilers.tar']=Path(profiler_input).resolve()
        identity = {'version': 1, 'candidate': commit, 'tree': tree,
                    'files': {name: record(path) for name, path in files.items()}, 'world_control': world_control}
        if profiling is not None: identity['profiling']=profiling
        # Repeat after archiving: dirty index/worktree changes must not silently disappear.
        view.clean(commit, entries, links)
        (root / 'identity.json').write_text(json.dumps(identity))
        if Path(output).exists():
            raise ValueError('Payload output already exists')
        try:
            subprocess.run(['/usr/bin/genisoimage', '-quiet', '-output', str(output),
                            '-volid', 'EQEMU_INPUT', '-joliet', '-rock', '-graft-points',
                            'identity.json=' + str(root / 'identity.json'),
                            *[name + '=' + str(path) for name, path in files.items()]],
                           check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            payload = record(output)
            # Detect changes to public media while the ISO builder read it.
            if any(record(path) != identity['files'][name] for name, path in files.items()):
                raise ValueError('Offline input changed while packaging')
            return dict(version=1, operation='build', candidate=commit, tree=tree, **payload,
                        **({'profiling':profiling} if profiling is not None else {}))
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise
