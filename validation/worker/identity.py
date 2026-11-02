"""AFK reuse identity for the trusted frontend, worker, policy and offline inputs."""
import hashlib
import json
from pathlib import Path

from prepare import record


def identity(root, config_path, native, rust, runtime=None):
    # Read bytes rather than paths/mtimes: reuse must notice an in-place replacement.
    config = json.loads(config_path.read_text())
    frontend = ('validation/worker/profile_contract.py', 'validation/worker/profiling.py', 'validation/worker/profile_artifacts.py',
                'validation/worker/profile_inputs.py', 'scripts/validate-worker-candidate', 'validation/worker/identity.py',
                'validation/worker/prepare.py', 'validation/worker/client.py',
                'validation/inputs.py', 'validation/profile.json', 'validation/runtime-fixture.json',
                'validation/worker/normal_world.py')
    from runtime import IMPLEMENTATION_FILES
    worker = IMPLEMENTATION_FILES
    selection='eqemu-validator-profiling' if config.get('selection')=='profiling-v1' else 'eqemu-validator'
    files = [*(root / name for name in frontend),
             *(Path(config['code_dir']) / name for name in worker), config_path,
             Path('/etc/systemd/system/'+selection+'@.service'),
             Path('/etc/systemd/system/'+selection+'.socket'),
             Path('/etc/apparmor.d/'+selection),
             Path(config['base_image']), native, rust]
    if config.get('selection')=='profiling-v1':
        files.append(Path(config['code_dir'])/'manifest.json')
    if runtime is not None:
        files.append(runtime)
    records = {str(path.resolve()): record(path) for path in files}
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema_version': 1, 'identity': 'eqemu-worker-v1:' + digest}
