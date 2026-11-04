"""Harmless host tests: synthetic bytes only, no candidate execution or socket VM."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'validation/worker'))
import integration_artifacts as a
from actor_integration import Events, scalar, validate_contexts

CANDIDATE = 'a' * 40
RUN = 'b' * 32


class Transport(unittest.TestCase):
    def sink(self, root):
        sink = a.Sink(Path(root)/'output', CANDIDATE, RUN)
        self.addCleanup(sink.close)
        return sink

    def frames(self, raw=b'public fixture', **kw):
        return list(a.frames(raw, CANDIDATE, RUN, complete=kw.get('complete', True), gaps=kw.get('gaps', False), overflow=kw.get('overflow', False)))

    def test_maximum_wire_and_durable_receipt(self):
        raw = b'x' * a.CAP
        frames = self.frames(raw)
        self.assertEqual(len(frames), 210)
        self.assertLessEqual(max(map(lambda f:len(a.wire(f)), frames)), a.FRAME_CAP)
        self.assertLessEqual(sum(len(a.wire(f)) for f in frames), a.WIRE_CAP)
        with tempfile.TemporaryDirectory() as root:
            sink = self.sink(root)
            for frame in frames:
                sink.accept(frame)
            ack = sink.ack()
            self.assertLessEqual(len(a.encoded(ack)) + 1, 256)
            receipt = sink.finish(ack)
            self.assertTrue(receipt['complete'])
            self.assertEqual((sink.directory/a.NAME).read_bytes(), raw)
            self.assertEqual(os.stat(sink.directory/a.NAME).st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError): sink.finish(ack)

    def test_reject_mutated_frame_without_losing_verified_prefix(self):
        raw = b'x' * 5000
        for mutation in ('sequence','offset','sha256','run_id','fixture_sha256','candidate','name','version','extra','data'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                sink = self.sink(root)
                frames = self.frames(raw)
                sink.accept(frames[0]); sink.accept(frames[1])
                bad = dict(frames[2])
                bad[mutation] = {'sequence':0,'offset':0,'sha256':'f'*64,'run_id':'f'*32,'fixture_sha256':'f'*64,'candidate':'f'*40,'name':'elsewhere','version':True,'extra':0,'data':'@@' }[mutation]
                with self.assertRaises(ValueError): sink.accept(bad)
                receipt = sink.finish()
                self.assertFalse(receipt['complete'])
                self.assertEqual((sink.directory/a.NAME).read_bytes(), raw[:4096])

    def test_partial_gaps_overflow_and_ack_uncertainty_never_pass(self):
        for mode in ('partial','gaps','overflow','missing-end','bad-ack','missing-ack'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                sink = self.sink(root)
                frames = self.frames(complete=mode!='partial', gaps=mode=='gaps', overflow=mode=='overflow')
                for frame in frames[:-1] if mode=='missing-end' else frames: sink.accept(frame)
                ack = sink.ack() if mode not in ('missing-end','missing-ack') else None
                if mode=='bad-ack': ack['run_id']='f'*32
                self.assertFalse(sink.finish(ack)['complete'])

    def test_duplicate_begin_replay_after_end_and_unknown_fields(self):
        for index in (0,1,2):
            with tempfile.TemporaryDirectory() as root:
                sink = self.sink(root)
                frames = self.frames()
                for frame in frames[:index+1]: sink.accept(frame)
                with self.assertRaises(ValueError): sink.accept(frames[index])
                self.assertFalse(sink.finish()['complete'])

    def test_existing_directory_symlink_and_file_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'output'; path.mkdir()
            with self.assertRaises(FileExistsError): a.Sink(path,CANDIDATE,RUN)
            path.rmdir(); path.symlink_to(root)
            with self.assertRaises(FileExistsError): a.Sink(path,CANDIDATE,RUN)

    def test_empty_prefix_retained_on_cancellation(self):
        with tempfile.TemporaryDirectory() as root:
            sink=self.sink(root)
            receipt=sink.finish()
            self.assertFalse(receipt['terminal'])
            self.assertEqual(receipt['original_transfer'],'uncertain')
            self.assertEqual(receipt['sha256'],hashlib.sha256(b'').hexdigest())

    def test_duplicate_json_keys_and_nan_rejected(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}'):
            with self.assertRaises(ValueError): a.decode(raw)


class TypedEvents(unittest.TestCase):
    def context(self):
        return [0,0,*(['0']*7),1,1,140,2,0,1]

    def test_width_and_lossless_u64(self):
        scalar(str(2**64-1),'u64')
        scalar(str(-2**63),'i64')
        for v in (str(2**64),'-0','01',2**64-1):
            with self.assertRaises(ValueError): scalar(v,'u64')
        validate_contexts([self.context()],1)

    def test_sequence_gap_and_overflow(self):
        events=Events([self.context()])
        event=[0,1,0,9,0,'0',[2,1,2,'1000','1000']]
        events.accept(event)
        with self.assertRaises(ValueError): events.accept(event)
        for seq in range(2,17): events.accept([0,seq,0,9,0,'0',[2,1,2,'1000','1000']])
        with self.assertRaises(ValueError): events.accept([0,17,0,9,0,'0',[2,1,2,'1000','1000']])

    def test_exact_variants_and_boolean_integer_confusion(self):
        for payload in ([0,0,0,0,'0','0','0','1'],[1,0,0,'500','500','500','1000',6],[2,0,24,'1','0','500','0','1']):
            with self.assertRaises(ValueError): Events([self.context()]).accept([0,1,0,8,0,'0',payload])
        with self.assertRaises(ValueError): scalar(True,'u8')


if __name__=='__main__': unittest.main()
