#!/usr/bin/python3
"""Build a finite additive offline package from verified retained archives. Data only."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tomllib

HERE = Path(__file__).resolve().parent
BUNDLE_LIMIT = 220 * 1024**2
VENDOR_LIMIT = 128 * 1024**2
CRATE_LIMIT = 8 * 1024**2
FILE_LIMIT = 10000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def read(path, limit):
    """Reject links/devices and bound reads even if a file changes while open."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('Input type/size budget')
        data = stream.read(limit + 1)
        if len(data) != info.st_size:
            raise ValueError('Input changed/size budget')
        return data


def unpack(data, limit, compressed=False):
    """Inspect bounded archive bytes in memory; never extract to the filesystem."""
    if compressed:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Archive byte budget')
    entries = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/') if member.isdir() else member.name
            path = PurePosixPath(name)
            total += member.size
            if (not name or name == '.' or str(path) != name or path.is_absolute() or '..' in path.parts
                    or '\\' in name or any(ord(c) < 32 or ord(c) == 127 for c in name)
                    or len(name) > 240 or name in entries or len(entries) >= FILE_LIMIT
                    or not (member.isfile() or member.isdir()) or member.mode & 0o7000
                    or total > limit or member.size < 0 or member.isdir() and member.size):
                raise ValueError('Unsafe archive inventory/budget')
            body = archive.extractfile(member).read() if member.isfile() else None
            entries[name] = (member.mode & 0o777, body)
    for name, (_, body) in entries.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) in entries and entries[str(parent)][1] is not None:
                raise ValueError('File is archive parent')
    return entries


def pack(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for name, (mode, data) in sorted(entries.items()):
            member = tarfile.TarInfo(name)
            member.mode = mode
            if data is None:
                member.type = tarfile.DIRTYPE
            else:
                member.size = len(data)
            archive.addfile(member, None if data is None else io.BytesIO(data))
    return stream.getvalue()


def checksum_inventory(entries, registry):
    """Check every registry package and every file against Cargo checksum data."""
    for item in registry:
        prefix = item['name'] + '-' + item['version'] + '/'
        checksum = json.loads(entries[prefix + '.cargo-checksum.json'][1])
        files = {n[len(prefix):]: sha(body) for n, (_, body) in entries.items()
                 if n.startswith(prefix) and body is not None and n != prefix + '.cargo-checksum.json'}
        if checksum['package'] != item['sha256'] or checksum['files'] != files:
            raise ValueError('Vendor checksum mismatch: ' + prefix)


def build(base, cache, lock, output, evidence=()):
    recipe_bytes = read(HERE / 'offline-additions.json', 32768)
    recipe = json.loads(recipe_bytes)
    lock_bytes = read(lock, 1024**2)
    if sha(lock_bytes) != recipe['lock_sha256']:
        raise ValueError('Source lock identity')
    actual = sorted((p['name'], p['version'], p['checksum']) for p in tomllib.loads(lock_bytes.decode())['package']
                    if p.get('source', '').startswith('registry+'))
    expected = sorted((p['name'], p['version'], p['sha256']) for p in recipe['registry'])
    if actual != expected or len(actual) != 37:
        raise ValueError('Registry lock inventory')
    original = read(base, BUNDLE_LIMIT)
    if dict(bytes=len(original), sha256=sha(original)) != recipe['base_bundle']:
        raise ValueError('Base bundle identity')
    outer = unpack(original, BUNDLE_LIMIT)
    components = {'rustc', 'cargo', 'rust-std', 'rustfmt-preview', 'clippy-preview'}
    if set(outer) != {'vendor.tar', 'vendor-config.toml', *(n + '.tar.xz' for n in components)}:
        raise ValueError('Outer component inventory')
    vendor = unpack(outer['vendor.tar'][1], VENDOR_LIMIT)
    old = dict(vendor); archives = {}; provenance = {}
    additions = [p for p in recipe['registry'] if p['add']]
    if len(additions) != 4:
        raise ValueError('Finite additions inventory')
    for item in additions:
        prefix = item['name'] + '-' + item['version']
        name = prefix + '.crate'
        raw = read(cache / name, CRATE_LIMIT)
        if sha(raw) != item['sha256']:
            raise ValueError('Crate lock checksum: ' + name)
        files = unpack(raw, CRATE_LIMIT, compressed=True)
        if not files or any(n != prefix and not n.startswith(prefix + '/') for n in files):
            raise ValueError('Crate root')
        if prefix + '/Cargo.toml' not in files or prefix + '/.cargo-checksum.json' in files:
            raise ValueError('Crate manifest/checksum collision')
        if any(n == prefix or n.startswith(prefix + '/') for n in vendor):
            raise ValueError('Addition overlaps original vendor')
        checksums = {n[len(prefix)+1:]: sha(body) for n, (_, body) in files.items() if body is not None}
        files[prefix + '/.cargo-checksum.json'] = (0o644, canonical(dict(package=item['sha256'], files=checksums)))
        vendor.update(files); archives['crates/' + name] = (0o600, raw)
        provenance[name] = dict(path=str((cache / name).absolute()), bytes=len(raw), sha256=sha(raw))
    checksum_inventory(vendor, recipe['registry'])
    assert all(vendor[n] == value for n, value in old.items())
    outer['vendor.tar'] = (outer['vendor.tar'][0], pack(vendor))
    bundle = pack(outer)
    if len(bundle) > BUNDLE_LIMIT:
        raise ValueError('Bundle budget')
    # Only the nested vendor archive may change; all other component bytes stay exact.
    unchanged = {n: dict(bytes=len(body), sha256=sha(body)) for n, (_, body) in outer.items() if n != 'vendor.tar'}
    manifest = dict(version=1, source_commit=recipe['source_commit'], source_tree=recipe['source_tree'],
        lock_sha256=sha(lock_bytes), recipe_sha256=sha(recipe_bytes), tool_sha256=sha(read(Path(__file__), 1024**2)),
        base=recipe['base_bundle'], bundle=dict(bytes=len(bundle), sha256=sha(bundle)), unchanged=unchanged,
        crates=provenance, original_vendor_entries=len(old), vendor_entries=len(vendor), registry_packages=37,
        vendor_files={n: dict(mode=mode, sha256=sha(body)) for n, (mode, body) in vendor.items() if body is not None},
        executed_candidate=False, installed=False)
    package = {**archives, 'rust-inputs.tar': (0o600, bundle), 'Cargo.lock': (0o600, lock_bytes),
               'offline-additions.json': (0o600, recipe_bytes), 'extend_offline.py': (0o600, read(Path(__file__), 1024**2))}
    for path in evidence:
        name = 'evidence/' + path.name
        if name in package:
            raise ValueError('Duplicate evidence')
        package[name] = (0o600, read(path, 4*1024**2))
    manifest['package_files'] = {n: dict(bytes=len(body), sha256=sha(body)) for n, (_, body) in package.items()}
    manifest_bytes = canonical(manifest)
    package['manifest.json'] = (0o600, manifest_bytes)
    package['SHA256SUMS'] = (0o600, ''.join(f'{sha(body)}  {n}\n' for n, (_, body) in sorted(package.items())).encode())
    target = output / sha(bundle)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.mkdir(mode=0o700)  # Exclusive: existing packages are never replaced.
    for name, (_, body) in package.items():
        path = target / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(body)
        path.chmod(0o400)
    return dict(path=str(target), bundle=manifest['bundle'], manifest_sha256=sha(manifest_bytes))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'cache', 'lock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--evidence', type=Path, action='append', default=[])
    args = parser.parse_args()
    print(json.dumps(build(args.base, args.cache, args.lock, args.output, args.evidence), sort_keys=True))
