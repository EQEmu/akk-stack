"""AFK reuse identity for the trusted frontend, worker, policy and offline inputs."""
import hashlib
import json
from pathlib import Path

from prepare import record

POLICY_ROOT = Path('/etc')

# Bind separate source copies, including conservative transitive local imports.
# Historical installed inventories below remain independent.
FRONTEND_FILES = ('validation/worker/actor_integration.py', 'validation/worker/integration_artifacts.py', 'validation/actor-integration-fixture.json', 'validation/worker/sanitizers.py', 'validation/worker/profile_contract.py', 'validation/worker/profiling.py', 'validation/worker/profile_artifacts.py',
                'validation/worker/profile_inputs.py', 'scripts/validate-worker-candidate', 'validation/worker/identity.py',
                'validation/worker/prepare.py', 'validation/worker/client.py',
                'validation/inputs.py', 'validation/profile.json', 'validation/runtime-fixture.json',
                'validation/worker/normal_world.py',
                'validation/worker/snapshot.py', 'validation/worker/runtime.py', 'validation/worker/guest.py',
                'validation/worker/quick_guest.py', 'validation/worker/quick_snapshot.py',
                'validation/worker/build_guest.py', 'validation/actor.py', 'validation/actor_runtime.py',
                'validation/debugger.py', 'validation/rust.py')


# Exact runtime bytes identify the retained master/v1/v2/v3 implementations.
# These select an identity inventory only, never runtime admission or execution.
LEGACY_RUNTIME_SHA256 = {
    'eqemu-validator': '56a34d3e3b7f3c384dcae1f9f769d6c772b6404a3aa3c819e9a8028579eb1185',
    'eqemu-validator-asan-v1': '661f57181335bcbaa7f16df18a0ee6fe14e6a863dd1a7b7430897f17c1553c81',
    'eqemu-validator-asan-v2': '85f6ed9df19f47f0a94c35b4b8a591b08708621b31cf50c2fb00eadd5038b996',
    'eqemu-validator-asan-v3': '85f6ed9df19f47f0a94c35b4b8a591b08708621b31cf50c2fb00eadd5038b996',
}
LEGACY_FILES = (
    'validation/worker/runtime.py', 'validation/worker/guest.py',
    'validation/worker/build_guest.py', 'validation/worker/normal_world.py',
    'validation/actor.py', 'validation/actor_runtime.py', 'validation/debugger.py',
    'validation/runtime-fixture.json', 'validation/worker/client.py',
    'scripts/check-validation-worker', 'validation/worker/format_guest.py',
    'validation/worker/snapshot.py', 'validation/worker/quick_guest.py',
    'validation/worker/quick_snapshot.py',
)
PROFILING_FILES = tuple('validation/worker/' + name for name in (
    'profile_contract.py', 'profiling.py', 'profile_artifacts.py', 'profile_inputs.py'))


def installed_files(config, policy):
    """Recognize exact historical runtimes; every new or partial release stays strict."""
    from runtime import IMPLEMENTATION_FILES
    code = Path(config['code_dir'])
    if config.get('selection') == 'profiling-v1':
        from profile_contract import SOURCE_FILES
        return SOURCE_FILES
    if any(
            (code/name).exists() or (code/name).is_symlink() for name in PROFILING_FILES):
        return IMPLEMENTATION_FILES
    if record(code/'validation/worker/runtime.py')['sha256'] != LEGACY_RUNTIME_SHA256.get(policy):
        raise ValueError('Unknown installed runtime requires the complete new helper closure')
    return LEGACY_FILES + (('validation/worker/sanitizers.py',) if config.get('diagnostic_profile') else ())


def identity(root, config_path, native, rust, runtime=None):
    # Read bytes rather than paths/mtimes: reuse must notice an in-place replacement.
    config = json.loads(config_path.read_text())
    from sanitizers import policy_name
    policy = 'eqemu-validator-profiling' if config.get('selection')=='profiling-v1' else policy_name(config)
    worker = installed_files(config, policy)
    files = [*(root / name for name in FRONTEND_FILES),
             *(Path(config['code_dir']) / name for name in worker), config_path,
             POLICY_ROOT / 'systemd/system' / (policy + '@.service'),
             POLICY_ROOT / 'systemd/system' / (policy + '.socket'),
             POLICY_ROOT / 'apparmor.d' / policy,
             Path(config['base_image']), native, rust]
    if config.get('selection')=='profiling-v1':
        files.append(Path(config['code_dir'])/'manifest.json')
    if runtime is not None:
        files.append(runtime)
    records = {str(path.resolve()): record(path) for path in files}
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema_version': 1, 'identity': 'eqemu-worker-v1:' + digest}
