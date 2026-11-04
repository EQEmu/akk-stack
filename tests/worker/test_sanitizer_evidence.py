"""Trusted collector fixtures only; no candidate compiler, native code or VM."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'validation/worker'))
import normal_world as normal
from test_failure_evidence import failure


class SanitizerEvidence(unittest.TestCase):
    def capture(self, zone, world=b'world console\n', enabled=True, secrets=()):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / name for name in ('world-console.log', 'zone-console.log')]
            for path, data in zip(paths, (world, zone)):
                path.write_bytes(data)
            with patch.dict(os.environ, {'ASAN_OPTIONS': 'detect_leaks=1'} if enabled else {}, clear=True):
                return normal.failure_snapshot([], paths, 'a'*32, time.monotonic(),
                    dict(condition='child-exit', last_success_ms=None), secrets)

    def test_failure_metadata_reservation_preserves_headers_and_whole_frame_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            capture=normal.FailureCapture(time.monotonic(),proc=root/'missing')
            children=[Mock(pid=123,poll=Mock(return_value=None)),Mock(pid=124,poll=Mock(return_value=-9))]
            for name,child in zip(('world','zone'),children):capture.watch(name,child)
            capture.latch(children,'child-exit',[None,-9])
            resources=capture.finish()
            for item in resources['processes']:
                for key in ('start_ticks','samples','last_ms','max_gap_ms','rss_kib','hwm_kib'):item[key]=2**64-1
            for key in ('baseline','failure','final'):
                for field in (*normal.MEM_FIELDS.values(),'oom_kill'):resources['guest'][key][field]=2**64-1
            resources['kernel'].update(state='ok',records=[dict(pid=123,**{key:2**64-1 for key in ('sequence','time_us','total_vm_kib','anon_rss_kib','file_rss_kib','shmem_rss_kib')})]*2)
            resources=normal.fit_resources(resources, min(1536,2048-len(normal.encoded(capture.pre))-60))
            # Pair identities still bind even if optional sampling counters are large.
            for a,b in zip(capture.pre['processes'],resources['processes']):a['start_ticks']=b['start_ticks']
            metadata=dict(pre_cleanup_observation=capture.pre,failure_resources=resources)
            normal.validate_capture(metadata)
            self.assertTrue(resources['truncated'])
            self.assertLessEqual(len(normal.encoded(metadata)),2048)
            paths=[root/name for name in ('world-console.log','zone-console.log')]
            for path in paths:path.write_bytes(b'context\n/source.cpp:1: runtime error: first\n'+('\x00\ufffd\U0001f600'*18000).encode())
            with patch.dict(os.environ,{'ASAN_OPTIONS':'detect_leaks=1'}):
                evidence=normal.failure_snapshot([],paths,'a'*32,time.monotonic(),dict(condition='child-exit'),reserved=2048)
            self.assertLessEqual(len(normal.encoded(evidence))+len(normal.encoded(metadata)),12000)
            self.assertEqual(len(evidence['first_sanitizer_diagnostic']),2)
            report=failure();report['diagnostic_profile']='asan-ubsan-native-v1'
            report['guest']['normal_world'].update(metadata,failure_evidence=evidence)
            report['guest']['sanitizers']=dict(profile='asan-ubsan-native-v1',environment=dict(ASAN_OPTIONS='detect_leaks=1'),
                controls=[dict(mode=mode,returncode=1,output='x'*1800) for mode in ('pass','use-after-free','out-of-bounds','undefined','leak')],
                binaries={name:dict(sha256='b'*64,runtimes=['libasan','libubsan']) for name in ('tests','world','zone','shared_memory')})
            self.assertLessEqual(len(normal.encoded(report['guest'])),32768)
            artifact=normal.export_evidence(report,'a'*40,root/'evidence')
            actual=json.loads(artifact.read_text())['normal_world']
            self.assertEqual(actual['pre_cleanup_observation'],metadata['pre_cleanup_observation'])
            self.assertEqual(actual['failure_resources'],metadata['failure_resources'])
            self.assertLessEqual(artifact.stat().st_size,16384)

    def test_escaped_progress_and_stack_fit_reserved_budget_without_losing_headers(self):
        run='a'*32;name='\U0001f600'*64;diagnostic='\U0001f600'*256
        events=[dict(version=1,run_id=run,event='case-start',name=name,elapsed_ms=1),
                dict(version=1,run_id=run,event='case-end',name=name,elapsed_ms=2,passed=False,diagnostic=diagnostic),
                dict(version=1,run_id=run,event='case-start',name='\U0001f601'*64,elapsed_ms=3)]
        data=b'context\n/source.cpp:1: runtime error: fixture\n'+b'x'*1200+b'\n'
        data+=b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT '+('\U0001f600'*200).encode()+b'\n'
        data+=b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n'+('\U0001f600'*1000).encode()+b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
        data+=b''.join(b'EQEMU_INSERVER_PROGRESS '+normal.encoded(event)+b'\n' for event in events)
        with tempfile.TemporaryDirectory() as tmp:
            paths=[Path(tmp)/name for name in ('world-console.log','zone-console.log')]
            for path in paths:path.write_bytes(data)
            with patch.dict(os.environ,{'ASAN_OPTIONS':'detect_leaks=1'}):
                evidence=normal.failure_snapshot([],paths,run,time.monotonic(),dict(condition='deadline'),reserved=2176)
        self.assertLessEqual(len(normal.encoded(evidence)),12000-2176)
        self.assertEqual(len(evidence['first_sanitizer_diagnostic']),2)
        self.assertTrue(evidence['progress_truncated'])
        self.assertFalse(evidence['progress']['last_completed_case']['passed'])

    def test_encoded_progress_credentials_are_masked_after_json_decode_before_metadata_clipping(self):
        secret='0123456789abcdef'*3;run='a'*32;name='\U0001f600'*16+secret
        events=[dict(version=1,run_id=run,event='case-start',name=name,elapsed_ms=1),
                dict(version=1,run_id=run,event='case-end',name=name,elapsed_ms=2,passed=False,diagnostic='\U0001f600'*256),
                dict(version=1,run_id=run,event='case-start',name=name,elapsed_ms=3)]
        escaped=''.join('\\u%04x'%ord(c) for c in secret)
        data=b'\x00'*128+b'\nruntime error: first\n'+b'x'*1200+b'\nEQEMU_NATIVE_DIAGNOSTIC_CONTEXT '+b'c'*498+b'\n'
        data+=b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n'+b's'*2996+b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
        data+=b''.join(b'EQEMU_INSERVER_PROGRESS '+json.dumps(event).replace(secret,escaped).encode()+b'\n' for event in events)
        with tempfile.TemporaryDirectory() as tmp:
            paths=[Path(tmp)/name for name in ('world-console.log','zone-console.log')]
            for path in paths:path.write_bytes(data)
            with patch.dict(os.environ,{'ASAN_OPTIONS':'detect_leaks=1'}):
                evidence=normal.failure_snapshot([],paths,run,time.monotonic(),dict(condition='deadline'),(secret,),2176)
        self.assertTrue(evidence['progress_truncated'])
        self.assertNotIn(secret[-16:],json.dumps(evidence))
        self.assertIn('*',evidence['progress']['last_completed_case']['name'])

    def test_complete_artifact_budgets_optional_text_after_adding_suite_and_capture(self):
        from test_normal_world import suite
        run='a'*32;name='\U0001f600'*64
        events=[dict(version=1,run_id=run,event='case-start',name=name,elapsed_ms=1),
                dict(version=1,run_id=run,event='case-end',name=name,elapsed_ms=2,passed=False,diagnostic='\U0001f600'*256),
                dict(version=1,run_id=run,event='case-start',name=name,elapsed_ms=3)]
        data=b'\x00'*128+b'\nruntime error: first\n'+b'x'*1200+b'\nEQEMU_NATIVE_DIAGNOSTIC_CONTEXT '+b'c'*498+b'\n'
        data+=b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n'+b's'*2996+b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
        data+=b''.join(b'EQEMU_INSERVER_PROGRESS '+normal.encoded(event)+b'\n' for event in events)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=[root/name for name in ('world-console.log','zone-console.log')]
            for path in paths:path.write_bytes(data)
            with patch.dict(os.environ,{'ASAN_OPTIONS':'detect_leaks=1'}):
                evidence=normal.failure_snapshot([],paths,run,time.monotonic(),dict(condition='child-exit'),reserved=2176)
            self.assertLessEqual(len(normal.encoded(evidence)),9824)
            capture=normal.FailureCapture(time.monotonic(),proc=root/'missing')
            children=[Mock(pid=123,poll=Mock(return_value=None)),Mock(pid=124,poll=Mock(return_value=1))]
            for name,child in zip(('world','zone'),children):capture.watch(name,child)
            capture.latch(children,'child-exit',[None,1])
            metadata=dict(pre_cleanup_observation=capture.pre,failure_resources=capture.finish())
            report=failure();report['diagnostic_profile']='asan-ubsan-native-v1'
            completed=suite();completed.update(selected=10,started=10,completed=10,failed=10,passed=False,
                tests=[dict(name=str(i)+'n'*63,passed=False,diagnostic='d'*256) for i in range(10)])
            normal.validate_inserver(completed)
            self.assertGreater(len(normal.encoded(completed)),3500)
            report['guest']['normal_world'].update(metadata,failure_evidence=evidence,inserver_tests=completed,
                error='e'*498,control=None,ready_seconds=1,baseline_seconds=5,responsive_samples=50,cpu_ticks=[1,1],
                clock_ticks_per_second=100,fixture_manifest_sha256='a'*64,database_cleanup=True,
                binaries={name:'b'*64 for name in ('world','zone','shared_memory')},
                native_exit_codes=[dict(name='world',returncode=0),dict(name='zone',returncode=1)])
            report['guest']['sanitizers']=dict(environment=dict(ASAN_OPTIONS='a'*100,UBSAN_OPTIONS='u'*100,ASAN_SYMBOLIZER_PATH='/usr/bin/addr2line'),
                symbolizer=dict(path='/usr/bin/addr2line',sha256='b'*64,version='v'*300),
                runtime_libraries={name:dict(path='/usr/lib/'+name,sha256='c'*64) for name in ('libasan.so','libubsan.so')},
                binaries={name:dict(sha256='d'*64,runtimes=['libasan','libubsan']) for name in ('tests','world','zone','shared_memory')},
                compile_commands_sha256='e'*64,exclusions=['e'*80]*3,optimization_exceptions=['e'*80]*5)
            artifact=normal.export_evidence(report,'a'*40,root/'evidence')
            actual=json.loads(artifact.read_text());actual_normal=actual['normal_world']
            self.assertTrue(actual['truncated']);self.assertLessEqual(artifact.stat().st_size,16384)
            self.assertEqual(actual_normal['inserver_tests'],completed)
            for key in metadata:self.assertEqual(actual_normal[key],metadata[key])
            self.assertEqual(actual_normal['failure_evidence']['first_sanitizer_diagnostic'],evidence['first_sanitizer_diagnostic'])
            self.assertTrue(actual_normal['cleanup_complete']);self.assertEqual(actual['exit_code'],1)
            # Exhaust every optional string. Mandatory supported fields still fit
            # both boundaries, and the reducer has a finite stopping condition.
            mandatory=json.loads(json.dumps(evidence));steps=0
            while normal.shrink_failure_evidence(mandatory):
                steps+=1;self.assertLess(steps,128)
            self.assertFalse(normal.shrink_failure_evidence(mandatory))
            self.assertLessEqual(len(normal.encoded(mandatory)),9824)
            report['guest']['normal_world']['failure_evidence']=mandatory
            compact=normal.export_evidence(report,'a'*40,root/'mandatory')
            compact_normal=json.loads(compact.read_text())['normal_world']
            self.assertLessEqual(compact.stat().st_size,16384)
            self.assertEqual(compact_normal['inserver_tests'],completed)
            for key in metadata:self.assertEqual(compact_normal[key],metadata[key])
            # Unknown oversized mandatory data is malformed, not a supported
            # production maximum. No authoritative bytes are silently removed.
            report['guest']['normal_world']['malformed_oversize']='x'*20000
            before=json.loads(json.dumps(report))
            with self.assertRaisesRegex(normal.EvidenceBudgetError,'^irreducible-artifact-budget$'):
                normal.export_evidence(report,'a'*40,root/'malformed')
            self.assertEqual(report,before)
            self.assertFalse((root/'malformed').exists())

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

    def test_known_credentials_crossing_each_new_excerpt_boundary_are_redacted(self):
        secret = '0123456789abcdef'*3
        header = b'runtime error: fixture header\n'
        cases = [
            (header[:-1] + b'x'*960 + secret.encode() + b'later\n'*1000, 'text', 'end'),
            (b'x'*200 + secret.encode() + b'x'*177 + header + b'later\n'*1000, 'text', 'start'),
            (secret.encode() + b'x'*110 + b'\n' + header + b'later\n'*1000, 'context', 'start'),
            (b'x'*100 + secret.encode() + b'\x00'*25 + b'\n' + header + b'later\n'*1000, 'context', 'start'),
        ]
        for data, field, edge in cases:
            with self.subTest(field=field, edge=edge, data=data[:20]):
                evidence = self.capture(data)
                first = evidence['first_sanitizer_diagnostic']['zone-console.log']
                text = first[field]
                fragments = [secret[:n] if edge == 'end' else secret[-n:]
                    for n in range(1, len(secret))]
                matches = [part for part in fragments if (text.endswith(part) if edge == 'end' else text.startswith(part))]
                self.assertTrue(matches, 'Fixture must reproduce a partial credential at the boundary')
                scrubbed = self.capture(data, secrets=[secret])
                first = scrubbed['first_sanitizer_diagnostic']['zone-console.log']
                self.assertEqual(first['offset'], evidence['first_sanitizer_diagnostic']['zone-console.log']['offset'])
                self.assertIn('*', first[field])
                self.assertNotIn(max(matches, key=len), first[field])
                self.assertLessEqual(len(normal.encoded(first['text'])), 1000)
                self.assertLessEqual(len(normal.encoded(first['context'])), 200)

    def test_observer_credentials_require_bounded_pipe_with_exact_guest_pair(self):
        for value in ([], ['one'], ['one', 'two', 'three'], ['', 'two'], [1, 'two'], ['x'*129, 'two']):
            with self.subTest(value=value), normal.observer_credential_pipe(normal.encoded(value)) as stream:
                with patch.object(normal.sys, 'stdin', types.SimpleNamespace(buffer=stream)):
                    with self.assertRaises(ValueError):
                        normal.read_observer_secrets()
        with tempfile.TemporaryFile() as stream:
            stream.write(normal.encoded(['one', 'two'])); stream.seek(0)
            with patch.object(normal.sys, 'stdin', types.SimpleNamespace(buffer=stream)):
                with self.assertRaisesRegex(ValueError, 'credential pipe'):
                    normal.read_observer_secrets()
        with self.assertRaisesRegex(ValueError, 'credential budget'):
            with normal.observer_credential_pipe(b'x'*1025):
                self.fail('Oversized credential input accepted')

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
