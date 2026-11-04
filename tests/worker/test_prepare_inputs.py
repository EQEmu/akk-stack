"""Pinned input capture with real bytes and harmless Git/ISO seams, never a VM."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import prepare


class PinnedInputs(unittest.TestCase):
    def exercise(self, changed=None, timing='archive', actual_bundle=False, restore=False, same_size=False):
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root=Path(tmp)
            paths={name:root/name for name in ('native.iso','runtime.iso','rust-inputs.tar')}
            if changed=='profilers.tar': paths['profilers.tar']=root/'profilers.tar'
            bodies={name:('approved '+name).encode() for name in paths}
            if actual_bundle:
                bodies['rust-inputs.tar']=(Path(os.environ['OFFLINE_TEST_PACKAGE'])/'rust-inputs.tar').read_bytes()
            for name,path in paths.items(): path.write_bytes(bodies[name])
            approved={name:prepare.record(path) for name,path in paths.items()}
            replacement = b'x'*len(bodies[changed]) if same_size else b'unapproved replacement'
            options = {}
            if 'profilers.tar' in paths:
                import profile_inputs
                stack.enter_context(patch.object(profile_inputs,'manifest'))
                options = dict(profiling='heaptrack',profiler_input=paths['profilers.tar'],
                               profiler_sha256=approved['profilers.tar']['sha256'])
            stack.enter_context(patch.object(prepare,'NATIVE_SHA',approved['native.iso']['sha256']))
            if not actual_bundle:
                stack.enter_context(patch.object(prepare,'RUST_SHA',approved['rust-inputs.tar']['sha256']))
            original_loads=json.loads
            profile=original_loads((ROOT/'validation/profile.json').read_text())
            def loads(raw):
                value=original_loads(raw)
                if 'iso' in value and 'manifest_sha256' in value:
                    value=dict(value,iso=approved['runtime.iso'])
                return value
            stack.enter_context(patch.object(prepare.json,'loads',side_effect=loads))
            archives=0
            class Git:
                def __init__(self,*args): pass
                def location(self,*args): return 'a'*40
                def git(self,*args): return ('b'*40).encode()
                def inventory(self,*args):
                    return ([dict(path=name,blob=blob) for name,blob in profile['dependency_blobs'].items()],
                            profile['sources']['eqemu']['gitlinks'])
                def clean(self,*args): pass
                def archive(self,commit,target):
                    nonlocal archives
                    target.write_bytes(b'opaque Git fixture'); archives+=1
                    if changed and timing=='archive' and archives==2:
                        paths[changed].write_bytes(replacement)
            stack.enter_context(patch.object(prepare.inputs,'GitTree',Git))
            stack.enter_context(patch.object(prepare.inputs,'verify_archive'))
            observed={}
            def iso(argv,**kwargs):
                output=Path(argv[argv.index('-output')+1])
                grafts=dict(arg.split('=',1) for arg in argv if '=' in arg)
                identity=original_loads(Path(grafts['identity.json']).read_text())
                if changed and timing=='iso': paths[changed].write_bytes(replacement)
                for name in paths:
                    observed[name]=Path(grafts[name]).read_bytes()
                if restore: paths[changed].write_bytes(bodies[changed])
                output.write_bytes(b'harmless ISO fixture')
                observed['identity']=identity
            stack.enter_context(patch.object(prepare.subprocess,'run',side_effect=iso))
            output=root/'payload.iso'
            if changed and not restore:
                with self.assertRaisesRegex(ValueError,'input changed|input identity|bounded regular file'):
                    prepare.prepare(root,'a'*40,root,paths['native.iso'],paths['rust-inputs.tar'],output,paths['runtime.iso'],**options)
                self.assertFalse(output.exists())
                return
            request=prepare.prepare(root,'a'*40,root,paths['native.iso'],paths['rust-inputs.tar'],output,paths['runtime.iso'],**options)
            self.assertEqual(request['sha256'],prepare.record(output)['sha256'])
            for name in paths:
                self.assertEqual(observed[name],bodies[name])
                self.assertEqual(observed['identity']['files'][name],approved[name])

    def test_pinned_replacement_before_capture_fails_for_every_public_input(self):
        for name in ('native.iso','rust-inputs.tar','runtime.iso','profilers.tar'):
            for same_size in (False,True):
                with self.subTest(input=name,same_size=same_size): self.exercise(name,same_size=same_size)

    def test_changes_during_iso_read_fail_closed_and_remove_payload(self):
        for name in ('native.iso','rust-inputs.tar','runtime.iso','profilers.tar'):
            with self.subTest(input=name): self.exercise(name,timing='iso')

    def test_restored_original_cannot_put_replacement_bytes_in_iso(self):
        for name in ('native.iso','rust-inputs.tar','runtime.iso','profilers.tar'):
            with self.subTest(input=name): self.exercise(name,timing='iso',restore=True)

    def test_unchanged_inputs_carry_approved_records(self):
        self.exercise()

    @unittest.skipUnless(os.environ.get('OFFLINE_TEST_PACKAGE'),'sealed package path not supplied')
    def test_actual_approved_bundle_replaced_with_22_bytes_rejected(self):
        self.exercise('rust-inputs.tar',actual_bundle=True)


if __name__=='__main__': unittest.main()
