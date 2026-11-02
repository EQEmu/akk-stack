"""Exact source-only profiling selection contract. Ordinary defaults are unchanged."""
import hashlib
import json
from pathlib import Path
import re

SELECTION='profiling-v1'
CONFINEMENT='eqemu-validator-profiling'
CONFIG='/etc/eqemu-validator/profiling.json'
STATE='/var/lib/eqemu-validator-profiling'
SHARED_LOCK='/var/lib/eqemu-validator/worker.lock'
SOCKET='/run/eqemu-validator-profiling.sock'
RELEASE_ROOT='/srv/eqemu-validator-profiling'
EXTRA_FIELDS={'selection','confinement','shared_lock','source_commit','release_manifest_sha256'}
SOURCE_FILES=(
    'validation/worker/runtime.py','validation/worker/guest.py','validation/worker/build_guest.py',
    'validation/worker/normal_world.py','validation/worker/client.py','validation/worker/identity.py',
    'validation/worker/prepare.py','validation/worker/profiling.py','validation/worker/profile_artifacts.py',
    'validation/worker/profile_inputs.py','validation/worker/profile_contract.py',
    'validation/worker/snapshot.py','validation/worker/format_guest.py',
    'validation/worker/quick_snapshot.py','validation/worker/quick_guest.py',
    'validation/actor.py','validation/actor_runtime.py','validation/debugger.py',
    'validation/runtime-fixture.json','validation/inputs.py','validation/profile.json',
    'scripts/check-validation-worker','scripts/validate-worker-candidate',
)


def validate(value, path, ordinary):
    """Only a root-selected exact profiling identity can use the shared worker lock."""
    sha=value.get('source_commit')
    if (str(path)!=CONFIG or value.get('selection')!=SELECTION or value.get('confinement')!=CONFINEMENT
            or value.get('shared_lock')!=SHARED_LOCK or value.get('state_dir')!=STATE or value.get('socket')!=SOCKET
            or not isinstance(sha,str) or not re.fullmatch('[a-f0-9]{40}',sha)
            or value.get('code_dir')!=RELEASE_ROOT+'/'+sha
            or not isinstance(value.get('release_manifest_sha256'),str)
            or not re.fullmatch('[a-f0-9]{64}',value['release_manifest_sha256'])
            or ordinary.get('state_dir')!='/var/lib/eqemu-validator'
            or any(value.get(key)!=ordinary.get(key) for key in ('version','user','worker_uid','worker_gid','submitter','base_image'))):
        raise ValueError('Invalid exact profiling selection or shared lock')


def verify_release(value, regular):
    """Root-protected manifest binds the full new helper/frontend closure."""
    root=Path(value['code_dir'])
    path=regular(root/'manifest.json')
    raw=path.read_bytes()
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=value['release_manifest_sha256']:
        raise ValueError('Profiling release manifest identity mismatch')
    manifest=json.loads(raw)
    if manifest.get('source_commit')!=value['source_commit'] or set(manifest.get('files',{}))!=set(SOURCE_FILES):
        raise ValueError('Profiling release closure mismatch')
    for name,wanted in manifest['files'].items():
        path=regular(root/name)
        if path.stat().st_size!=wanted['bytes']:
            raise ValueError('Profiling release helper size mismatch')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=wanted['sha256']:
                raise ValueError('Profiling release helper identity mismatch')
