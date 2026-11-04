"""Fixed public input admission and typed observation checks for central-cdau.

This module contains no host candidate launcher. Native observation is supplied
by the separately owned Server interface, never inferred from status polling.
"""
import hashlib
import io
import json
import math
from pathlib import Path
import re
import tarfile

from integration_artifacts import CAP, CONTRACT_SHA, FIXTURE_SHA, SELECTION, decode, encoded, fail, hex_string

FIXTURE_BYTES = 1300480
MANIFEST_SHA = 'bc266220eba8cf0685463856221ed2a71d035ec1c5607c73e2058d1376df8797'
KINDS = {5: 2304, 6: 256, 7: 20, 8: 12, 9: 16, 10: 64, 11: 384, 12: 128}
TYPES = {
    5: ('cause', 'bool', 'u32', 'u8', 'u64', 'u64', 'u16', 'sha'),
    6: ('ctx', 'direction', 'bool', 'reaction', 'denial', 'i64', 'i64'),
    7: ('u16', 'i32', 'i32', 'i32'),
    9: ('level_phase', 'u8', 'u8', 'u64', 'u64'),
    10: ('ctx', 'i32', 'i32', 'i32', 'i32', 'reaction', 'flags', 'u32'),
    12: ('fault_phase', 'case', 'u64', 'u16', 'failure', 'u64', 'u64', 'u64'),
}
RANGES = {'u8': (0, 255), 'u16': (0, 65535), 'u32': (0, 4294967295),
          'i32': (-2147483648, 2147483647), 'proc': (0, 23), 'ctx': (0, 127),
          'cause': (0, 10), 'direction': (0, 1), 'reaction': (0, 9), 'denial': (0, 3),
          'level_phase': (0, 2), 'fault_phase': (0, 4), 'case': (0, 2), 'failure': (0, 12), 'flags': (0, 255)}


def scalar(value, kind):
    if kind in RANGES:
        lo, hi = RANGES[kind]
        if type(value) is not int or not lo <= value <= hi:
            fail()
    elif kind == 'bool':
        if type(value) is not bool:
            fail()
    elif kind == 'sha':
        hex_string(value, 64)
    elif kind in ('u64', 'i64'):
        if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}' if kind == 'u64' else r'0|-?[1-9][0-9]{0,18}|-?[1-9][0-9]{19}', value):
            fail()
        lo, hi = (0, 2**64 - 1) if kind == 'u64' else (-2**63, 2**63 - 1)
        if not lo <= int(value) <= hi:
            fail()
    elif kind == 'f64':
        if (not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', value)
                or not math.isfinite(float(value))):
            fail()
    else:
        fail()


def typed(values, kinds):
    if not isinstance(values, list) or len(values) != len(kinds):
        fail()
    for value, kind in zip(values, kinds):
        scalar(value, kind)


def verify_fixture(path, target=None):
    """Verify exact tar bytes and all 27 safe regular members before any extraction."""
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != FIXTURE_BYTES:
            fail()
        raw = stream.read(FIXTURE_BYTES + 1)
    if len(raw) != FIXTURE_BYTES or hashlib.sha256(raw).hexdigest() != FIXTURE_SHA:
        fail()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != 27 or len(set(names)) != 27 or any(not m.isfile() or m.linkname or m.mode != 0o444 for m in members):
            fail()
        manifest = archive.extractfile('manifest.json').read()
        if hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA:
            fail()
        records = decode(manifest)['files']
        expected = {r['path']: r for r in records}
        if set(names) != set(expected) | {'manifest.json'}:
            fail()
        payload = {}
        for name in names:
            if name.startswith('/') or '..' in name.split('/'):
                fail()
            data = archive.extractfile(name).read()
            if name != 'manifest.json' and (len(data) != expected[name]['bytes'] or hashlib.sha256(data).hexdigest() != expected[name]['sha256']):
                fail()
            payload[name] = data
    if target is not None:
        target = Path(target)
        target.mkdir(mode=0o700)
        for name, data in payload.items():
            path = target / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o400)
    return payload


class Events:
    """Reject loss, overflow, unregistered references and typed variant mismatch."""
    def __init__(self, contexts):
        self.contexts = contexts
        self.last = {}
        self.counts = dict.fromkeys(KINDS, 0)

    def accept(self, event):
        if not isinstance(event, list) or len(event) != 7:
            fail()
        proc, sequence, micros, kind, context, revision, payload = event
        typed([proc, context, revision], ['proc', 'ctx', 'u64'])
        if (type(sequence) is not int or sequence != self.last.get(proc, 0) + 1 or sequence > 4096
                or type(micros) is not int or not 0 <= micros <= 1800000000
                or type(kind) is not int or kind not in KINDS
                or context >= len(self.contexts) or self.contexts[context][0] != proc):
            fail()
        kinds = TYPES.get(kind)
        if kind == 8:
            if not isinstance(payload, list) or len(payload) != 8 or type(payload[0]) is not int:
                fail()
            phase = payload[0]
            kinds = {0: ('u8','u16','ctx','ctx','u64','u64','u64','u64'),
                     1: ('u8','u16','ctx','u64','u64','u64','u64','u8'),
                     2: ('u8','u16','proc','u64','u64','u64','u64','u64')}.get(phase)
            if kinds is None or (phase == 0 and payload[4:] != ['0'] * 4) or (phase == 1 and (type(payload[7]) is not int or payload[7] > 5)):
                fail()
        if kind == 11:
            if not isinstance(payload, list) or len(payload) != 8 or type(payload[0]) is not int or not 0 <= payload[0] <= 8:
                fail()
            kinds = ('u8','u16','ctx','u32','flags', *(['f64'] * 3 if payload[0] == 0 else ['u64'] * 3))
        typed(payload, kinds)
        self.counts[kind] += 1
        if self.counts[kind] > KINDS[kind]:
            fail()
        self.last[proc] = sequence


def validate_contexts(contexts, process_count):
    if not isinstance(contexts, list) or len(contexts) > 128:
        fail()
    for context in contexts:
        typed(context, ['proc','u8', *(['u64'] * 7), *(['u32'] * 4), 'u8','u8'])
        if context[0] >= process_count or context[1] > 3 or len(encoded(context)) + 1 > 256:
            fail()
    if len({encoded(c) for c in contexts}) != len(contexts):
        fail()


def checksums(raw_records):
    if not isinstance(raw_records, list) or len(raw_records) != 3 or any(not isinstance(v, str) for v in raw_records):
        fail()
    if sum(len(v.encode()) for v in raw_records) > 8192:
        fail()
    return [hashlib.sha256(v.encode()).hexdigest() for v in raw_records]


def validate_snapshot(snapshot):
    fields = {'process_index','sequence','raw_record_sha256_by_actor','raw_json_by_actor'}
    if not isinstance(snapshot, dict) or set(snapshot) != fields or len(encoded(snapshot)) + 1 > 11264:
        fail()
    scalar(snapshot['process_index'], 'proc')
    scalar(snapshot['sequence'], 'u32')
    if snapshot['raw_record_sha256_by_actor'] != checksums(snapshot['raw_json_by_actor']):
        fail()
    total_items = 0
    for actor, raw in enumerate(snapshot['raw_json_by_actor']):
        record = decode(raw)
        if not isinstance(record, dict) or set(record) != {'schema','id','profile','revision','clean','saved'}:
            fail()
        if (record['schema'] != 3 or type(record['schema']) is not int or type(record['id']) is not int
                or record['id'] != actor or record['profile'] != 'west-qeynos-v1' or type(record['clean']) is not bool):
            fail()
        if type(record['revision']) is not int or not 0 <= record['revision'] < 2**64:
            fail()
        saved = record['saved']
        fields = {'desired','zone','previous_zone','owner_epoch','transfer','point','hp','max_hp','rest_ms','level','experience','reputation','inventory','completed','yielded','failed'}
        if not isinstance(saved, dict) or set(saved) != fields or not isinstance(saved['inventory'], list):
            fail()
        inventory = saved['inventory']
        if actor != 0 and inventory:
            fail()
        total_items += len(inventory)
        fields = {'parent','kind','slot','id','charges','color','custom','attuned','ornament_icon','ornament_file','ornament_model','serial','recast','scaling','scaling_exp','evolve_id','evolve_character','evolve_item','evolve_final','evolve_amount','evolve_progress','evolve_active','evolve_equipped'}
        for item in inventory:
            if not isinstance(item, dict) or set(item) != fields:
                fail()
            if not isinstance(item['custom'], str) or len(item['custom']) > 64 or not re.fullmatch(r'[A-Za-z0-9_^:.-]*', item['custom']):
                fail()
            for key in ('attuned','scaling','evolve_active','evolve_equipped'):
                if type(item[key]) is not bool:
                    fail()
            if item['scaling'] or any(item[k] != 0 for k in ('scaling_exp','evolve_id','evolve_character','evolve_item','evolve_final','evolve_amount','evolve_progress')) or item['evolve_active'] or item['evolve_equipped']:
                fail()
    if total_items > 8:
        fail()
