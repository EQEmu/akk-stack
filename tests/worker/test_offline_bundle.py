"""Host-only archive construction and finite selection regressions."""
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import prepare
import jobs
spec = importlib.util.spec_from_file_location('extend_offline', ROOT / 'validation/rust/extend_offline.py')
extend = importlib.util.module_from_spec(spec); spec.loader.exec_module(extend)


class OfflineBundle(unittest.TestCase):
    def test_deterministic_tar(self):
        entries = {'a': (0o755, None), 'a/source': (0o644, b'never executed')}
        self.assertEqual(extend.pack(entries), extend.pack(dict(reversed(list(entries.items())))))
        self.assertEqual(extend.unpack(extend.pack(entries), 32768), entries)

    def test_reject_unsafe_archives(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('a/../b', tarfile.REGTYPE), ('./a', tarfile.REGTYPE),
                           ('.', tarfile.DIRTYPE), ('a', tarfile.SYMTYPE),
                           ('a', tarfile.LNKTYPE), ('a', tarfile.FIFOTYPE)]:
            with self.subTest(name=name, kind=kind):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:') as archive:
                    member = tarfile.TarInfo(name); member.type = kind; archive.addfile(member)
                with self.assertRaises(ValueError): extend.unpack(stream.getvalue(), 32768)
        for entries in [[('a', b'1'), ('a', b'2')], [('a', b'file'), ('a/b', b'child')]]:
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:') as archive:
                for name, data in entries:
                    member = tarfile.TarInfo(name); member.size = len(data); archive.addfile(member, io.BytesIO(data))
            with self.assertRaises(ValueError): extend.unpack(stream.getvalue(), 32768)

    def test_bombs_and_file_bounds(self):
        with self.assertRaises(ValueError): extend.unpack(gzip.compress(b'0'*100000), 1000, compressed=True)
        with patch.object(extend, 'FILE_LIMIT', 1):
            with self.assertRaises(ValueError): extend.unpack(extend.pack({'a': (0o644,b'a'), 'b':(0o644,b'b')}), 32768)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'file'; p.write_bytes(b'oversize')
            with self.assertRaises(ValueError): extend.read(p, 2)
            link = Path(tmp)/'link'; link.symlink_to(p)
            with self.assertRaises(OSError): extend.read(link, 20)

    def test_finite_selection(self):
        pin, size = next(iter(prepare.ADDITIONAL_RUST.items()))
        for digest, count, accepted in [(prepare.RUST_SHA, 10, True), (pin,size,True),
                                        (pin,size+1,False), ('0'*64,size,False)]:
            with patch.object(prepare,'record',return_value=dict(bytes=count,sha256=digest)):
                if accepted: prepare.verify_rust('fixture')
                else:
                    with self.assertRaises(ValueError): prepare.verify_rust('fixture')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'tampered.tar'; path.write_bytes(b'tampered package')
            with self.assertRaises(ValueError): prepare.verify_rust(path)

    def test_vendor_checksum_tamper(self):
        entries = {'crate-1/source': (0o644,b'original'), 'crate-1/.cargo-checksum.json':
                   (0o644,extend.canonical(dict(package='a'*64,files={'source': extend.sha(b'original')})))}
        registry = [dict(name='crate',version='1',sha256='a'*64)]
        extend.checksum_inventory(entries,registry)
        entries['crate-1/source'] = (0o644,b'changed')
        with self.assertRaises(ValueError): extend.checksum_inventory(entries,registry)

    def test_job_operand_and_snapshot(self):
        # No process, socket, callback, or VM is launched by this CLI test.
        with tempfile.TemporaryDirectory() as tmp, patch.object(jobs, 'start', return_value={}) as start:
            args = ['start','full','--repo',str(ROOT),'--commit','25fe3746d4f101ac26d9dca4e003d3529e488169',
                    '--websocketpp',str(ROOT),'--thread','test-thread','--t3-base-dir',tmp]
            self.assertEqual(jobs.main(args),0)
            self.assertNotIn('--rust-input', start.call_args.args[1]['command'])
            self.assertEqual(jobs.main(args + ['--rust-input',tmp+'/bundle.tar']),0)
            command = start.call_args.args[1]['command']
            self.assertEqual(command[command.index('--rust-input')+1],tmp+'/bundle.tar')
            self.assertTrue(start.call_args.kwargs['snapshot'])

    @unittest.skipUnless(os.environ.get('OFFLINE_TEST_BASE') and os.environ.get('OFFLINE_TEST_CACHE'), 'retained data paths not supplied')
    def test_real_package_independent_rebuild(self):
        base = Path(os.environ['OFFLINE_TEST_BASE']); cache = Path(os.environ['OFFLINE_TEST_CACHE'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = extend.build(base, cache, ROOT/'validation/rust/offline-additions.lock',root/'one')
            second = extend.build(base, cache, ROOT/'validation/rust/offline-additions.lock',root/'two')
            self.assertEqual(first['bundle'],second['bundle'])
            self.assertEqual(first['manifest_sha256'],second['manifest_sha256'])
            a,b = Path(first['path']),Path(second['path'])
            for path in a.rglob('*'):
                if path.is_file(): self.assertEqual(path.read_bytes(), (b/path.relative_to(a)).read_bytes())
            prepare.verify_rust(a/'rust-inputs.tar')
            old = extend.unpack(extend.read(base,extend.BUNDLE_LIMIT),extend.BUNDLE_LIMIT)
            new = extend.unpack(extend.read(a/'rust-inputs.tar',extend.BUNDLE_LIMIT),extend.BUNDLE_LIMIT)
            for name in old:
                if name != 'vendor.tar': self.assertEqual(old[name],new[name])
            old_vendor=extend.unpack(old['vendor.tar'][1],extend.VENDOR_LIMIT)
            new_vendor=extend.unpack(new['vendor.tar'][1],extend.VENDOR_LIMIT)
            self.assertTrue(all(new_vendor[n]==v for n,v in old_vendor.items()))
            with self.assertRaises(FileExistsError): extend.build(base,cache,ROOT/'validation/rust/offline-additions.lock',root/'one')
            # Wrong lock and tampered crate fail before output publication.
            bad = root/'bad.lock'; bad.write_bytes(b'wrong lock')
            with self.assertRaisesRegex(ValueError,'Source lock'): extend.build(base,cache,bad,root/'bad')
            copies=root/'cache';copies.mkdir()
            for path in (a/'crates').iterdir(): (copies/path.name).write_bytes(path.read_bytes()+b'tampered')
            with self.assertRaisesRegex(ValueError,'Crate lock checksum'):
                extend.build(base,copies,ROOT/'validation/rust/offline-additions.lock',root/'bad')
            self.assertFalse((root/'bad').exists())


if __name__ == '__main__': unittest.main()
