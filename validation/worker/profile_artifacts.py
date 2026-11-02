"""Bounded private profile transport. Raw bytes never enter the result summary."""
import base64
import hashlib
import json
import os
from pathlib import Path

PREFIX = b'EQEMU_PROFILE '
FILE_LIMIT = 4 * 1024**2
TOTAL_LIMIT = 16 * 1024**2
CHUNK = 3072
INTERNAL = frozenset(('collection.json','collection.tmp'))
NAMES = frozenset(('timeline.jsonl', 'stages.jsonl', 'metadata.json', 'summary.json', 'preflight.json', 'perf-preflight.analysis',
    'world.heaptrack.raw', 'zone.heaptrack.raw', 'world.heaptrack.txt', 'zone.heaptrack.txt',
    'world.heaptrack.analysis', 'zone.heaptrack.analysis',
    'world.heaptrack.interpret-log', 'zone.heaptrack.interpret-log', 'world.perf.data', 'zone.perf.data',
    'world.perf.analysis', 'zone.perf.analysis'))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def frame(name, offset, data):
    return PREFIX + canonical(dict(name=name, offset=offset, data=base64.b64encode(data).decode())) + b'\n'


class Sink:
    """Reject paths, duplicates, gaps, oversized data and symlinks before publication."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=False)
        self.offsets = {}
        self.total = 0

    def accept(self, value):
        if (not isinstance(value, dict) or set(value) != {'name', 'offset', 'data'}
                or value['name'] not in NAMES or type(value['offset']) is not int
                or not isinstance(value['data'], str) or len(value['data']) > CHUNK * 4 // 3):
            raise ValueError('Malformed profile chunk')
        name = value['name']
        data = base64.b64decode(value['data'], validate=True)
        offset = self.offsets.get(name, 0)
        if not data or value['offset'] != offset:
            raise ValueError('Profile chunk offset mismatch')
        if offset + len(data) > FILE_LIMIT or self.total + len(data) > TOTAL_LIMIT:
            raise ValueError('Profile export byte limit exceeded')
        flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_EXCL | os.O_CREAT if name not in self.offsets else os.O_APPEND)
        fd = os.open(self.directory / name, flags, 0o600)
        with os.fdopen(fd, 'ab') as stream:
            if stream.tell() != offset:
                raise ValueError('Profile output changed during export')
            stream.write(data); stream.flush()
        self.offsets[name] = offset + len(data)
        self.total += len(data)

    def inventory(self):
        return inventory(self.directory)


def inventory(directory):
    if Path(directory).is_symlink() or not Path(directory).is_dir():
        raise ValueError('Profile collection must be a regular private directory')
    result = {}
    total = 0
    for path in sorted(Path(directory).iterdir()):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Unexpected profile artifact')
        if path.name in INTERNAL:
            if path.stat().st_size>16384: raise ValueError('Profile collection identity oversized')
            continue
        if path.name not in NAMES:
            raise ValueError('Unexpected profile artifact')
        size = path.stat().st_size; total += size
        if size > FILE_LIMIT or total > TOTAL_LIMIT:
            raise ValueError('Profile artifact bound exceeded')
        with path.open('rb') as stream:
            result[path.name] = dict(bytes=size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
    return result


def send(directory, stream):
    """Finite post-execution export. A disconnected client leaves worker evidence intact."""
    inventory(directory)
    for path in sorted(Path(directory).iterdir()):
        if path.name in INTERNAL: continue
        with path.open('rb') as source:
            offset = 0
            while block := source.read(CHUNK):
                stream.write(frame(path.name, offset, block)); stream.flush()
                offset += len(block)


def validate_collection(directory, mode, candidate, tree, binaries):
    """Success requires the requested collection bound to the actual workload."""
    required={'metadata.json','summary.json','timeline.jsonl','stages.jsonl'}
    if mode=='heaptrack':
        required |= {name+suffix for name in ('world','zone') for suffix in ('.heaptrack.raw','.heaptrack.txt','.heaptrack.analysis')}
    if mode=='perf':
        required |= {name+suffix for name in ('world','zone') for suffix in ('.perf.data','.perf.analysis')}
    files=inventory(directory)
    if not required<=set(files) or any(files[name]['bytes']==0 for name in required):
        raise ValueError('Requested profile artifacts missing or empty')
    def load(name):
        path=Path(directory)/name
        if path.stat().st_size>65536: raise ValueError('Profile metadata oversized')
        return json.loads(path.read_bytes())
    metadata=load('metadata.json'); summary=load('summary.json')
    if (metadata.get('mode')!=mode or metadata.get('source',{}).get('candidate')!=candidate
            or metadata['source'].get('tree')!=tree or summary.get('mode')!=mode
            or summary.get('sampler_complete') is not True or summary.get('truncated')
            or {p.get('name') for p in summary.get('processes',[])}!={'world','zone'}
            or any(metadata.get('binaries',{}).get(name,{}).get('sha256')!=binaries.get(name) for name in ('world','zone'))):
        raise ValueError('Profile source/binary/mode/completion mismatch')
    return files
