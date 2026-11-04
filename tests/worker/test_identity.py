"""Real-file identities for separate frontend, retained and new installed closures."""
import ast
import contextlib
import functools
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import identity
import profile_contract
import runtime

PINS = {
    'ordinary': 'b9996308a027ef5a3432dc451039f9fa2974b072',
    'v1': '6bcd71010acfc1ebe8ac1264f5b9b90537ab2d69',
    'v2': '22f4ea6bf6070014e29bc4eb156b9c8a65dcb197',
    'v3': '29c1e8457196c73ee19d8922d0ee913d3375098f',
}


@functools.cache
def historical_bytes(pin, name):
    return subprocess.check_output(['git', '-C', str(ROOT), 'show', pin+':'+name])


@contextlib.contextmanager
def identity_fixture(slot='new', profiling=False):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp); frontend = root/'frontend'; installed = root/'installed'
        shutil.copytree(ROOT/'validation', frontend/'validation')
        shutil.copytree(ROOT/'scripts', frontend/'scripts')
        helpers = (identity.LEGACY_FILES + (() if slot=='ordinary' else ('validation/worker/sanitizers.py',))
                   if slot in PINS else profile_contract.SOURCE_FILES)
        for name in helpers:
            path = installed/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(historical_bytes(PINS[slot],name) if slot in PINS else (ROOT/name).read_bytes())
        policy = 'eqemu-validator' if slot in ('ordinary','new') else 'eqemu-validator-asan-'+slot
        fields = {} if slot in ('ordinary','new') else dict(diagnostic_profile='asan-ubsan-native-v1')
        if slot in ('v2','v3'): fields['diagnostic_policy'] = policy
        if profiling:
            fields = dict(selection='profiling-v1'); policy = 'eqemu-validator-profiling'
            manifest = dict(source_commit='a'*40, files={name:dict(bytes=(installed/name).stat().st_size,
                sha256=hashlib.sha256((installed/name).read_bytes()).hexdigest()) for name in helpers})
            (installed/'manifest.json').write_text(json.dumps(manifest))
        policies = root/'etc'; policy_paths = []
        for name in ('systemd/system/'+policy+'@.service', 'systemd/system/'+policy+'.socket', 'apparmor.d/'+policy):
            path = policies/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('policy '+name).encode()); policy_paths.append(path)
        for name in ('base', 'native', 'rust', 'runtime'): (root/name).write_bytes(name.encode())
        config = root/'config.json'
        config.write_text(json.dumps(dict(code_dir=str(installed), base_image=str(root/'base'), **fields)))
        with patch.object(identity, 'POLICY_ROOT', policies):
            yield SimpleNamespace(root=root, frontend=frontend, installed=installed, config=config,
                helpers=helpers, policies=policy_paths,
                calculate=lambda: identity.identity(frontend,config,root/'native',root/'rust',root/'runtime'))


class Identity(unittest.TestCase):
    def test_stability_and_each_bound_file_change(self):
        with identity_fixture() as fixture:
            original = fixture.calculate()
            self.assertEqual(original, fixture.calculate())
            self.assertEqual(set(original), {'schema_version','identity'})
            self.assertEqual(original['schema_version'],1)
            self.assertLessEqual(len(original['identity'].encode()),256)
            bound = [fixture.installed/name for name in runtime.IMPLEMENTATION_FILES]
            bound += [fixture.config, *fixture.policies, *(fixture.root/name for name in ('base','native','rust','runtime'))]
            for path in bound:
                with self.subTest(path=path):
                    raw = path.read_bytes()
                    # Configuration mutation must remain parseable and select the same closure.
                    path.write_bytes(raw+b' ')
                    self.assertNotEqual(original, fixture.calculate())
                    path.write_bytes(raw)
            (fixture.root/'candidate').write_bytes(b'unrelated candidate')
            self.assertEqual(original, fixture.calculate())

    def test_every_frontend_import_copy_binds_mutation_and_missing_file(self):
        for slot in (*PINS, 'new'):
            with self.subTest(slot=slot), identity_fixture(slot) as fixture:
                original = fixture.calculate()
                installed = {name:(fixture.installed/name).read_bytes() for name in fixture.helpers}
                for name in identity.FRONTEND_FILES:
                    path = fixture.frontend/name; raw = path.read_bytes()
                    with self.subTest(frontend=name):
                        path.write_bytes(raw+b'\n')
                        self.assertNotEqual(original, fixture.calculate())
                        path.unlink()
                        with self.assertRaises(FileNotFoundError): fixture.calculate()
                        path.write_bytes(raw)
                self.assertEqual(installed,{name:(fixture.installed/name).read_bytes() for name in fixture.helpers})
                self.assertEqual(original,fixture.calculate())

    def test_frontend_list_covers_transitive_local_imports(self):
        # Conservative: include imports in every function, even worker-only branches.
        pending = [ROOT/'scripts/validate-worker-candidate']; visited = set()
        while pending:
            path = pending.pop()
            if path in visited: continue
            visited.add(path)
            for node in ast.walk(ast.parse(path.read_text())):
                names = ([node.module] if isinstance(node,ast.ImportFrom) else
                         [item.name for item in node.names] if isinstance(node,ast.Import) else [])
                for module in names:
                    if not module: continue
                    for directory in (ROOT/'validation/worker', ROOT/'validation'):
                        imported = directory/(module.replace('.', '/')+'.py')
                        if imported.is_file():
                            pending.append(imported); break
        self.assertLessEqual({str(path.relative_to(ROOT)) for path in visited},set(identity.FRONTEND_FILES))

    def test_policy_files_bind_exact_ordinary_legacy_v1_and_explicit_slots(self):
        for slot in PINS:
            with self.subTest(slot=slot), identity_fixture(slot) as fixture:
                original = fixture.calculate()
                self.assertEqual(original,fixture.calculate())
                for path in fixture.policies:
                    raw=path.read_bytes(); path.write_bytes(raw+b'change')
                    self.assertNotEqual(original,fixture.calculate()); path.write_bytes(raw)
                config=json.loads(fixture.config.read_text())
                for fields in ({'diagnostic_policy':'eqemu-validator-asan-v4'}, {'diagnostic_profile':'other'}):
                    fixture.config.write_text(json.dumps(dict(config,**fields)))
                    with self.assertRaises(ValueError): fixture.calculate()
                fixture.config.write_text(json.dumps(config))

    def test_frontend_sanitizer_bytes_bind_with_installed_copy_unchanged(self):
        for slot in (*PINS, 'new'):
            with self.subTest(slot=slot), identity_fixture(slot) as fixture:
                installed = {name:(fixture.installed/name).read_bytes() for name in fixture.helpers}
                original=fixture.calculate()
                path=fixture.frontend/'validation/worker/sanitizers.py'
                path.write_bytes(path.read_bytes()+b'\n# frontend-only mutation\n')
                self.assertNotEqual(original,fixture.calculate())
                self.assertEqual(installed,{name:(fixture.installed/name).read_bytes() for name in fixture.helpers})

    def test_retained_closures_require_every_old_helper_and_bind_mutations(self):
        for slot in PINS:
            with self.subTest(slot=slot), identity_fixture(slot) as fixture:
                self.assertFalse(any((fixture.installed/name).exists() for name in identity.PROFILING_FILES))
                original=fixture.calculate()
                for name in fixture.helpers:
                    path=fixture.installed/name; raw=path.read_bytes()
                    path.unlink()
                    with self.subTest(missing=name), self.assertRaises(FileNotFoundError): fixture.calculate()
                    path.write_bytes(raw+b'\n# mutation\n')
                    if name=='validation/worker/runtime.py':
                        with self.assertRaisesRegex(ValueError,'complete new helper closure'): fixture.calculate()
                    else: self.assertNotEqual(original,fixture.calculate())
                    path.write_bytes(raw)
                self.assertEqual(original,fixture.calculate())

    def test_new_packages_never_fall_back_for_missing_or_partial_helpers(self):
        for profiling in (False,True):
            with self.subTest(profiling=profiling), identity_fixture(profiling=profiling) as fixture:
                original=fixture.calculate()
                for name in (profile_contract.SOURCE_FILES if profiling else runtime.IMPLEMENTATION_FILES):
                    path=fixture.installed/name; raw=path.read_bytes(); path.unlink()
                    with self.subTest(missing=name), self.assertRaises(FileNotFoundError): fixture.calculate()
                    path.write_bytes(raw)
                saved={name:(fixture.installed/name).read_bytes() for name in identity.PROFILING_FILES}
                for name in saved: (fixture.installed/name).unlink()
                with self.assertRaises((ValueError,FileNotFoundError)): fixture.calculate()
                for name,raw in saved.items(): (fixture.installed/name).write_bytes(raw)
                self.assertEqual(original,fixture.calculate())
                if profiling:
                    path=fixture.installed/'manifest.json'; raw=path.read_bytes()
                    path.write_bytes(raw+b' '); self.assertNotEqual(original,fixture.calculate())
                    path.unlink()
                    with self.assertRaises(FileNotFoundError): fixture.calculate()

    def test_profiling_selection_never_accepts_historical_or_partially_extended_release(self):
        for slot in PINS:
            with self.subTest(slot=slot), identity_fixture(slot) as fixture:
                config=json.loads(fixture.config.read_text())
                # A single new helper turns an otherwise historical release into an incomplete new release.
                for name in identity.PROFILING_FILES:
                    path=fixture.installed/name; path.write_bytes((ROOT/name).read_bytes())
                    with self.assertRaises(FileNotFoundError): fixture.calculate()
                    path.unlink()
                config.pop('diagnostic_profile',None); config.pop('diagnostic_policy',None)
                config['selection']='profiling-v1';fixture.config.write_text(json.dumps(config))
                with self.assertRaises(FileNotFoundError): fixture.calculate()

    def test_cli_identity_does_not_contact_worker_or_prepare_candidate(self):
        loader = importlib.machinery.SourceFileLoader('candidate_cli', str(ROOT / 'scripts/validate-worker-candidate'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        expected = {'schema_version': 1, 'identity': 'test'}
        with patch.object(sys, 'argv', ['validate-worker-candidate', '--identity']), \
                patch.object(cli, 'identity', return_value=expected), \
                patch.object(cli, 'exchange') as exchange, patch.object(cli, 'prepare') as prepare, \
                patch('builtins.print') as output:
            self.assertEqual(cli.main(), 0)
            self.assertEqual(json.loads(output.call_args.args[0]), expected)
            exchange.assert_not_called()
            prepare.assert_not_called()
        with patch.object(sys, 'argv', ['validate-worker-candidate', '--identity']), \
                patch.object(cli, 'identity', side_effect=OSError('unreadable input')), patch('builtins.print') as output:
            self.assertEqual(cli.main(), 2)
            self.assertNotIn('identity', json.loads(output.call_args.args[0]))


if __name__ == '__main__':
    unittest.main()
