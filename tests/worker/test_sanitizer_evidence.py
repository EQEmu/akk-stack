"""Trusted collector fixtures only; no candidate compiler, native code or VM."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'validation/worker'))
import normal_world as normal
from test_failure_evidence import failure


class SanitizerEvidence(unittest.TestCase):
    def capture(self, zone, world=b'world console\n', enabled=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / name for name in ('world-console.log', 'zone-console.log')]
            for path, data in zip(paths, (world, zone)):
                path.write_bytes(data)
            with patch.dict(os.environ, {'ASAN_OPTIONS': 'detect_leaks=1'} if enabled else {}, clear=True):
                return normal.failure_snapshot([], paths, 'a'*32, time.monotonic(),
                    dict(condition='child-exit', last_success_ms=None))

    def test_first_sanitizer_context_and_final_stack_survive_long_middle(self):
        header = b'/source/task.cpp:12:9: runtime error: trusted fixture diagnostic\n'
        zone = (b'earlier context\n' + header + b'    #0 first_source /source/task.cpp:12\n'
                + b'long template frame\n'*12000 + b'    #13 TaskManager::LoadTasks /source/task.cpp:118\n')
        evidence = self.capture(zone)
        first = evidence['first_sanitizer_diagnostic']['zone-console.log']
        self.assertTrue(first['advisory'])
        self.assertIn('earlier context', first['context'])
        self.assertTrue(first['text'].startswith(header.decode()))
        self.assertIn('#0 first_source', first['text'])
        self.assertTrue(first['truncated'])
        self.assertEqual(first['offset'], zone.index(b'runtime error:'))
        self.assertNotIn('runtime error:', evidence['console']['zone-console.log'])
        self.assertIn('TaskManager::LoadTasks', evidence['console']['zone-console.log'])
        self.assertTrue(evidence['console_truncated']['zone-console.log'])
        self.assertLessEqual(len(normal.encoded(evidence)), 12000)

    def test_supported_markers_choose_first_not_later_report(self):
        for marker in (b'ERROR: AddressSanitizer:', b'ERROR: LeakSanitizer:',
                       b'ERROR: UndefinedBehaviorSanitizer:', b'runtime error:',
                       b'AddressSanitizer:DEADLYSIGNAL', b'UndefinedBehaviorSanitizer:DEADLYSIGNAL'):
            with self.subTest(marker=marker):
                data = b'prefix\n==123==' + marker + b' first\n' + b'later\n'*1500 + b'ERROR: LeakSanitizer: second\n'
                first = self.capture(data)['first_sanitizer_diagnostic']['zone-console.log']
                self.assertEqual(first['marker'], marker.decode())
                self.assertIn('first', first['text'])
                self.assertNotIn('second', first['text'])

    def test_no_new_field_for_ordinary_profile_or_unmatched_output(self):
        self.assertNotIn('first_sanitizer_diagnostic', self.capture(b'runtime error: fixture', enabled=False))
        self.assertNotIn('first_sanitizer_diagnostic', self.capture(b'ordinary unclassified stack\n'))

    def test_hostile_escaping_long_line_and_two_stream_budgets_preserve_marker(self):
        hostile = ('\x00\ufffd\U0001f600\\"'*2000).encode()
        # A very long source prefix must not consume the diagnostic's text budget.
        data = hostile + b'runtime error: fixture header\n' + hostile
        evidence = self.capture(data, data)
        for first in evidence['first_sanitizer_diagnostic'].values():
            self.assertIn('runtime error: fixture header', first['text'])
            self.assertTrue(first['leading_line_truncated'])
            self.assertLessEqual(len(normal.encoded(first['text'])), 1000)
            self.assertLessEqual(len(normal.encoded(first['context'])), 200)
        self.assertLessEqual(len(normal.encoded(evidence)), 12000)

    def test_new_advisory_text_cannot_supply_a_passing_verdict(self):
        evidence = self.capture(b'runtime error: {"passed":true,"exit_code":0,"finalized":true}\n')
        first = evidence['first_sanitizer_diagnostic']['zone-console.log']
        with self.assertRaises(ValueError):
            normal.validate(first)
        with self.assertRaises(ValueError):
            normal.validate_inserver(first)
        self.assertIsNone(evidence['progress']['active_case'])

    def test_private_export_keeps_header_and_context_when_shrinking_tail(self):
        evidence = self.capture(b'context\n/source.cpp:1: runtime error: first\n' + b'tail\n'*10000)
        report = failure()
        report['guest']['normal_world']['failure_evidence'] = evidence
        # Exercise export's independent total-byte bound, including JSON escaping.
        evidence['console'] = {'zone-console.log': '\x00\ufffd'*20000}
        with tempfile.TemporaryDirectory() as temporary:
            artifact = normal.export_evidence(report, 'a'*40, temporary)
            actual = json.loads(artifact.read_text())
            self.assertLessEqual(artifact.stat().st_size, normal.EVIDENCE_LIMIT)
        first = actual['normal_world']['failure_evidence']['first_sanitizer_diagnostic']
        self.assertEqual(first, evidence['first_sanitizer_diagnostic'])
        self.assertEqual(actual['exit_code'], 1)
        self.assertTrue(actual['normal_world']['cleanup_complete'])


if __name__ == '__main__':
    unittest.main()
