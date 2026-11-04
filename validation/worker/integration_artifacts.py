"""One fixed, bounded integration artifact. No paths or commands travel on the wire."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SELECTION = 'central-cdau-integration-v1'
NAME = SELECTION + '.json'
PREFIX = b'EQEMU_INTEGRATION '
CAP = 851968
CHUNK = 4096
FRAME_CAP = 6144
WIRE_CAP = 1280000
FIXTURE_SHA = 'cf71b70acf549328552b3c203d2760571cb40b4d816f8aaf0ee447629039c48c'
CONTRACT_SHA = 'fa89512eeb7071570acd6b3fdc35affa65f9d178c553869e3dce1d5a5d8bfc4a'


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('integration-schema')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: fail())


def fail():
    raise ValueError('integration-schema')


def hex_string(value, width):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(width) + '}', value):
        fail()
    return value


def binding(candidate, run_id, fixture=FIXTURE_SHA):
    return dict(version=1, name=NAME, candidate=hex_string(candidate, 40),
                run_id=hex_string(run_id, 32), fixture_sha256=hex_string(fixture, 64))


def wire(frame):
    raw = PREFIX + encoded(frame) + b'\n'
    if len(raw) > FRAME_CAP:
        fail()
    return raw


def frames(raw, candidate, run_id, *, complete, gaps, overflow):
    """Frame actual bytes, including a truthful incomplete prefix on failure."""
    if not isinstance(raw, bytes) or len(raw) > CAP or any(type(v) is not bool for v in (complete, gaps, overflow)):
        fail()
    fixed = binding(candidate, run_id)
    yield dict(fixed, kind='begin', cap=CAP)
    for sequence, offset in enumerate(range(0, len(raw), CHUNK)):
        block = raw[offset:offset + CHUNK]
        yield dict(fixed, kind='data', sequence=sequence, offset=offset,
                   sha256=hashlib.sha256(block).hexdigest(), data=base64.b64encode(block).decode('ascii'))
    yield dict(fixed, kind='end', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
               complete=complete, gaps=gaps, overflow=overflow)


class Sink:
    """Retain a verified prefix at a fixed exclusive 0600 file in a new 0700 directory.

    Original receipt is finalized once. Read-only re-export never changes it.
    Directory/file descriptors remain open through fsync and receipt publication.
    """
    def __init__(self, directory, candidate, run_id):
        self.fixed = binding(candidate, run_id)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.stream = None
        try:
            info = os.fstat(self.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                fail()
            fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            self.stream = os.fdopen(fd, 'wb')
        except BaseException:
            os.close(self.fd)
            raise
        self.digest = hashlib.sha256()
        self.total = self.sequence = self.wire_bytes = self.count = 0
        self.begun = self.ended = self.valid = self.finalized = False
        self.error = None

    def accept(self, frame):
        """Reject every unexpected field, binding, duplicate, gap and capacity violation."""
        try:
            self._accept(frame)
        except Exception:
            self.error = 'integration-transfer-invalid'
            self.valid = False
            raise ValueError(self.error) from None

    def _accept(self, frame):
        size = len(wire(frame))
        self.wire_bytes += size
        self.count += 1
        if self.error or self.ended or self.count > 210 or self.wire_bytes > WIRE_CAP:
            fail()
        if not isinstance(frame, dict) or any(frame.get(k) != v or type(frame.get(k)) is not type(v) for k, v in self.fixed.items()):
            fail()
        common = set(self.fixed) | {'kind'}
        kind = frame.get('kind')
        if kind == 'begin':
            if self.begun or set(frame) != common | {'cap'} or type(frame['cap']) is not int or frame['cap'] != CAP or size > 1024:
                fail()
            self.begun = True
        elif kind == 'data':
            if not self.begun or set(frame) != common | {'sequence', 'offset', 'sha256', 'data'}:
                fail()
            if (type(frame['sequence']) is not int or frame['sequence'] != self.sequence or self.sequence >= 208
                    or type(frame['offset']) is not int or frame['offset'] != self.total
                    or not isinstance(frame['data'], str) or len(frame['data']) > 5464):
                fail()
            block = base64.b64decode(frame['data'], validate=True)
            if (not 0 < len(block) <= CHUNK or self.total + len(block) > CAP
                    or base64.b64encode(block).decode() != frame['data']
                    or hashlib.sha256(block).hexdigest() != hex_string(frame['sha256'], 64)):
                fail()
            self.stream.write(block)
            self.digest.update(block)
            self.total += len(block)
            self.sequence += 1
        elif kind == 'end':
            if (not self.begun or set(frame) != common | {'bytes', 'sha256', 'complete', 'gaps', 'overflow'}
                    or type(frame['bytes']) is not int or frame['bytes'] != self.total
                    or hex_string(frame['sha256'], 64) != self.digest.hexdigest() or size > 1024
                    or any(type(frame[k]) is not bool for k in ('complete', 'gaps', 'overflow'))):
                fail()
            self.stream.flush()
            os.fsync(self.stream.fileno())
            os.fsync(self.fd)
            self.ended = True
            self.valid = frame['complete'] and not frame['gaps'] and not frame['overflow']
        else:
            fail()

    def ack(self):
        if not self.ended or self.error:
            fail()
        result = dict(version=1, run_id=self.fixed['run_id'], sha256=self.digest.hexdigest(), bytes=self.total, durable=True)
        if len(encoded(result)) + 1 > 256:
            fail()
        return result

    def finish(self, ack=None):
        """Persist original export uncertainty before returning any terminal outcome."""
        if self.finalized:
            fail()
        durable = ack == self.ack() if self.ended and not self.error else False
        # bools must not compare equal to integer protocol fields.
        durable = durable and all(type(ack[k]) is type(v) for k, v in self.ack().items())
        receipt = dict(version=1, **{k: self.fixed[k] for k in ('name', 'candidate', 'run_id', 'fixture_sha256')},
                       bytes=self.total, sha256=self.digest.hexdigest(), terminal=self.ended,
                       complete=self.valid and durable, client_durable=bool(durable),
                       original_transfer='durable' if durable else 'uncertain',
                       error=self.error or ('none' if self.valid and durable else 'integration-incomplete'))
        self.stream.flush()
        os.fsync(self.stream.fileno())
        fd = os.open('receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(receipt) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)
        self.finalized = True
        return receipt

    def abandon(self):
        try:
            if not self.finalized:
                self.finish()
        finally:
            self.close()

    def close(self):
        if self.fd is None:
            return
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            os.close(self.fd)
            self.fd = None
