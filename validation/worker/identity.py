"""AFK reuse identity for the trusted frontend, worker, policy and offline inputs."""
import hashlib
import json
from pathlib import Path

from prepare import record


def identity(root, config_path, native, rust, runtime=None):
    # Read bytes rather than paths/mtimes: reuse must notice an in-place replacement.
    config = json.loads(config_path.read_text())
    from sanitizers import policy_name
    policy = policy_name(config)
    frontend = ('scripts/validate-worker-candidate', 'validation/worker/identity.py',
                'validation/worker/prepare.py', 'validation/worker/client.py',
                'validation/inputs.py', 'validation/profile.json', 'validation/runtime-fixture.json',
                'validation/worker/normal_world.py')
    from runtime import IMPLEMENTATION_FILES
    # The ordinary installed release predates the diagnostic-only helper. Bind
    # it when admitted/installed, without requiring an ordinary release update.
    worker = tuple(name for name in IMPLEMENTATION_FILES
        if name != 'validation/worker/sanitizers.py' or config.get('diagnostic_profile')
        or (Path(config['code_dir']) / name).exists())
    files = [*(root / name for name in frontend),
             *(Path(config['code_dir']) / name for name in worker), config_path,
             Path('/etc/systemd/system') / (policy + '@.service'),
             Path('/etc/systemd/system') / (policy + '.socket'),
             Path('/etc/apparmor.d') / policy,
             Path(config['base_image']), native, rust]
    if runtime is not None:
        files.append(runtime)
    records = {str(path.resolve()): record(path) for path in files}
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema_version': 1, 'identity': 'eqemu-worker-v1:' + digest}
