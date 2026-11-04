"""Full bounded working-source snapshots for fixed advisory checks. No execution."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

from snapshot import canonical, sha, read_file

# Reviewed immutable package identities, shared by frontend, runtime and guest.
RUST_PACKAGES = {
    'original': dict(bytes=171847680, sha256='2a0b4a32ad74b3bb49195d43f76ece75166b500004f5b32f868cb20a292bc52f'),
    'additive-v1': dict(bytes=171284480, sha256='7bc2a72f9b8a3ebcea3dfcb879ab2d5bb0a23d5ab4913e85f9acd728a5ce932e'),
}


def approved_rust(item):
    return item in RUST_PACKAGES.values()


SOURCE_LIMIT = 256 * 1024**2
FILE_LIMIT = 16 * 1024**2
FILE_COUNT = 10000
PATH_CHARACTERS = 240
# A regular PAX member has its file header, optional PAX header/path payload,
# and at most one block of content padding. Other TarInfo fields remain zero.
PAX_PATH_BLOCKS = (PATH_CHARACTERS * 4 + 32 + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
ARCHIVE_MEMBER_OVERHEAD = (2 + PAX_PATH_BLOCKS) * tarfile.BLOCKSIZE + tarfile.BLOCKSIZE - 1
ARCHIVE_LIMIT = SOURCE_LIMIT + FILE_COUNT * ARCHIVE_MEMBER_OVERHEAD + 2 * tarfile.BLOCKSIZE + tarfile.RECORDSIZE - 1
MANIFEST_LIMIT = 4 * 1024**2
RESULT_LIMIT = 65536
CHECKS = ('rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'native-configure', 'native-objects')
UNTRACKED_EXCLUDED = {'target','vendor','generated','CMakeFiles','__pycache__','.cache'}


def safe_path(name):
    if not isinstance(name, str) or not name or len(name) > PATH_CHARACTERS:
        return False
    try:name.encode('utf-8')
    except UnicodeEncodeError:return False
    path = PurePosixPath(name)
    return (not path.is_absolute() and str(path) == name and
            not any(part in ('.', '..', '.git') for part in path.parts) and
            not any(ord(char) < 32 for char in name))


def capture(repo, base, recipe):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from inputs import GitTree, regular
    if not isinstance(base, str) or not re.fullmatch('[a-f0-9]{40}', base):
        raise ValueError('Quick snapshot base must be a full commit SHA')
    root = Path(repo).absolute()
    if root.resolve() != root:
        raise ValueError('Quick snapshot path traverses symlinks')
    with tempfile.TemporaryDirectory(prefix='eqemu-quick-index-') as tmp:
        view = GitTree(root, Path(tmp))
        tree = view.git('rev-parse', base + '^{tree}').decode().strip()
        baseline, gitlinks = view.inventory(base, tree)
        index = Path(view.location('--git-path', 'index'))
        with regular(index, 16 * 1024**2) as (stream, _):
            data = stream.read(16 * 1024**2 + 1)
        if len(data) > 16 * 1024**2:
            raise ValueError('Quick index budget exceeded')
        copied = Path(tmp) / 'index'; copied.write_bytes(data)
        view.env['GIT_INDEX_FILE'] = str(copied)
        tracked=set();indexed_links={}
        for row in view.git('ls-files', '--stage', '-z').split(b'\0'):
            if not row:
                continue
            meta, name = row.split(b'\t', 1); mode, blob, stage = meta.decode().split()
            tracked.add(name.decode())
            if mode=='160000':indexed_links[name.decode()]=blob
            if stage != '0' or (mode == '160000' and gitlinks.get(name.decode()) != blob):
                raise ValueError('Unmerged or changed submodule index')
        if indexed_links!=gitlinks:raise ValueError('Deleted/changed native submodule input')
        listing = view.git('--work-tree=' + str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
        names = sorted({name.decode() for name in listing.split(b'\0') if name})
        for prefix in ('','rust/','rust/actors/'):
            for leaf in ('rustfmt.toml','.rustfmt.toml','.cargo/config','.cargo/config.toml'):
                name=prefix+leaf
                if os.path.lexists(root/name) and name not in names:names.append(name)
        names.sort()
        original = {e['path']: e for e in baseline}
        files = []; changed = set(); total = 0
        for name in names:
            if name in gitlinks or any(name.startswith(link + '/') for link in gitlinks):
                continue
            if name not in tracked and (any(part in UNTRACKED_EXCLUDED for part in PurePosixPath(name).parts)
                    or PurePosixPath(name).name in ('.env','eqemu_config.json','login.json')
                    or PurePosixPath(name).name.startswith('.env.')):
                continue
            if not safe_path(name):
                raise ValueError('Unsafe quick snapshot path')
            try:
                data, mode = read_file(root, name, FILE_LIMIT)
            except FileNotFoundError:
                continue
            total += len(data)
            if total > SOURCE_LIMIT or len(files) >= FILE_COUNT:
                raise ValueError('Quick snapshot budget exceeded')
            blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if name not in original or (blob, mode) != (original[name]['blob'], original[name]['mode']):
                changed.add(name)
            files.append(dict(path=name, mode=mode, bytes=len(data), sha256=sha(data)))
        present = {e['path'] for e in files}
        deleted = sorted(set(original) - present); changed.update(deleted)
        result = dict(version=1, scope='working-snapshot-quick-input', base=base, head=view.location('HEAD'),
                      recipe_sha256=recipe, files=files, changed=sorted(changed), deleted=deleted, gitlinks=gitlinks)
        validate_snapshot(result)
        return result


def validate_snapshot(value):
    if (not isinstance(value, dict) or set(value) != {'version','scope','base','head','recipe_sha256','files','changed','deleted','gitlinks'}
            or type(value['version']) is not int or value['version'] != 1 or value['scope'] != 'working-snapshot-quick-input'
            or any(not isinstance(value[k], str) or not re.fullmatch('[a-f0-9]{40}', value[k]) for k in ('base','head'))
            or not isinstance(value['recipe_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['recipe_sha256'])
            or not isinstance(value['files'], list) or not 0 < len(value['files']) <= FILE_COUNT
            or len(canonical(value)) > MANIFEST_LIMIT or not isinstance(value['gitlinks'], dict)
            or any(not safe_path(k) or not isinstance(v,str) or not re.fullmatch('[a-f0-9]{40}',v) for k,v in value['gitlinks'].items())):
        raise ValueError('Malformed quick snapshot')
    names=set();total=0
    for entry in value['files']:
        if (not isinstance(entry, dict) or set(entry) != {'path','mode','bytes','sha256'} or not safe_path(entry['path'])
                or entry['path'] in names or entry['mode'] not in ('100644','100755') or type(entry['bytes']) is not int
                or not 0 <= entry['bytes'] <= FILE_LIMIT or not isinstance(entry['sha256'],str)
                or not re.fullmatch('[a-f0-9]{64}',entry['sha256'])
                or any(entry['path']==link or entry['path'].startswith(link+'/') for link in value['gitlinks'])):
            raise ValueError('Malformed quick snapshot file')
        total+=entry['bytes'];names.add(entry['path'])
    if total>SOURCE_LIMIT or 'rust/actors/Cargo.toml' not in names:
        raise ValueError('Quick snapshot source budget/workspace missing')
    for key in ('changed','deleted'):
        if (not isinstance(value[key],list) or len(value[key])>FILE_COUNT or not all(safe_path(name) for name in value[key])
                or value[key] != sorted(set(value[key]))):
            raise ValueError('Malformed quick changed/deleted paths')
    if (not set(value['deleted']) <= set(value['changed']) or set(value['deleted']) & names
            or not set(value['changed'])<=names|set(value['deleted'])):
        raise ValueError('Contradictory quick deletions')
    return value


def identity(value):
    return dict(version=1,scope=value['scope'],base=value['base'],head=value['head'],recipe_sha256=value['recipe_sha256'],
                input_snapshot_sha256=sha(canonical(value)),files=len(value['files']),bytes=sum(e['bytes'] for e in value['files']),
                changed=value['changed'],deleted=value['deleted'])


def archive(repo, value, output):
    """Write raw regular source bytes, never Git filters or checkout commands."""
    with tarfile.open(output,'x',format=tarfile.PAX_FORMAT) as stream:
        for entry in value['files']:
            data,mode=read_file(repo,entry['path'],FILE_LIMIT)
            if len(data)!=entry['bytes'] or sha(data)!=entry['sha256'] or mode!=entry['mode']:
                raise ValueError('Source changed while packaging quick snapshot')
            info=tarfile.TarInfo(entry['path']);info.size=len(data);info.mode=0o755 if mode=='100755' else 0o644
            stream.addfile(info,io.BytesIO(data))
    if Path(output).stat().st_size>ARCHIVE_LIMIT:
        raise ValueError('Quick source archive exceeds its derived overhead bound')


def native_scope(value):
    """Cold builds have no reliable header dependency map. State that limit."""
    translation=[];limitations=[]
    for name in value['changed']:
        path=PurePosixPath(name);suffix=path.suffix.lower()
        if name.startswith('rust/actors/bridge/') or name in ('rust/actors/Cargo.toml','rust/actors/Cargo.lock') or '/.cargo/' in '/'+name:
            limitations.append('Rust bridge/build input changed: '+name)
        elif name.startswith('rust/actors/core/') and suffix=='.rs' and path.name!='build.rs':
            continue
        elif suffix in ('.md','.rst') or name in ('LICENSE','COPYING','NOTICE'):
            continue
        elif name in [prefix+leaf for prefix in ('','rust/','rust/actors/') for leaf in ('rustfmt.toml','.rustfmt.toml')]:
            continue
        elif suffix in ('.cpp','.cc','.cxx'):
            if name in value['deleted']:limitations.append('Deleted/renamed translation unit: '+name)
            else:translation.append(name)
        else:
            limitations.append('Unknown native input/header/build scope requires full validation: '+name)
    if len(translation)>8:limitations.append('More than eight changed translation units require full validation')
    def bounded(items):
        kept=[]
        for item in items:
            if len(kept)>=32 or len(canonical(kept+[item]))>4096:break
            kept.append(item)
        return kept
    shown=bounded(translation)
    if len(shown)<len(translation):limitations.insert(0,'Native source scope exceeded the private path budget; requires full validation')
    reasons=bounded(limitations)
    return dict(changed_translation_units=shown,selected_objects=[],limitations=reasons,
                omitted_translation_units=len(translation)-len(shown),omitted_limitations=len(limitations)-len(reasons))


def diagnostic(text,limit=3000):
    """Keep a useful tail within JSON-encoded bytes, including Unicode escaping."""
    text=str(text)
    if len(canonical(text))<=limit:return text
    marker='[earlier diagnostic omitted]\n';low=0;high=len(text)
    while low<high:
        middle=(low+high+1)//2
        if len(canonical(marker+text[-middle:]))<=limit:low=middle
        else:high=middle-1
    return marker+text[-low:] if low else marker


def validate_detail(value):
    """Stage evidence is a fixed partition, never an arbitrary job recipe."""
    if not isinstance(value,dict) or len(canonical(value))>RESULT_LIMIT or value.get('selected_checks')!=list(CHECKS):
        raise ValueError('Malformed/oversized quick evidence')
    records=value.get('checks')
    if not isinstance(records,list) or len(records)!=len(CHECKS):raise ValueError('Missing quick stages')
    for name,entry in zip(CHECKS,records):
        if (not isinstance(entry,dict) or set(entry)!={'name','status','reason','seconds','diagnostic'} or entry['name']!=name
                or entry['status'] not in ('completed','failed','unavailable','skipped')
                or not isinstance(entry['reason'],str) or len(entry['reason'])>160
                or not isinstance(entry['diagnostic'],str) or len(canonical(entry['diagnostic']))>3000
                or type(entry['seconds']) not in (int,float) or not 0<=entry['seconds']<=3600):
            raise ValueError('Malformed quick stage')
    for status,key in [('completed','completed_checks'),('failed','failed_checks'),('unavailable','unavailable_checks'),('skipped','skipped_checks')]:
        if value.get(key)!=[entry['name'] for entry in records if entry['status']==status]:raise ValueError('Contradictory quick stage partition')
    expected=2 if value['unavailable_checks'] else 1 if value['failed_checks'] else 0
    if type(value.get('exit_code')) is not int or value['exit_code']!=expected:raise ValueError('Quick exit/evidence mismatch')
    if expected==0 and any(entry['status']=='skipped' and entry['reason']!='no-native-translation-unit-changes' for entry in records):
        raise ValueError('Quick success omitted prerequisite coverage')
    native=value.get('native_scope')
    if not isinstance(native,dict) or set(native)!={'changed_translation_units','selected_objects','limitations','omitted_translation_units','omitted_limitations'}:
        raise ValueError('Malformed native quick scope')
    if any(type(native[key]) is not int or not 0<=native[key]<=FILE_COUNT for key in ('omitted_translation_units','omitted_limitations')):
        raise ValueError('Malformed omitted native scope counts')
    for key,limit in [('changed_translation_units',32),('selected_objects',8),('limitations',32)]:
        if (not isinstance(native[key],list) or len(native[key])>limit
                or not all(isinstance(item,str) and len(item)<=320 for item in native[key])):raise ValueError('Oversized native quick scope')
    if not all(safe_path(path) for path in native['changed_translation_units']+native['selected_objects']):raise ValueError('Escaped native quick scope')
    return value


def validate_result(result,value,tool):
    validate_snapshot(value);validate_detail(result)
    expected=identity(value)
    if (type(result.get('version')) is not int or result['version']!=1 or result.get('scope')!='working-snapshot-quickcheck'
            or result.get('operation')!='quick' or result.get('advisory') is not True
            or any(result.get(key)!=expected[key] for key in ('base','head','input_snapshot_sha256','recipe_sha256'))
            or result.get('output_snapshot_sha256')!=expected['input_snapshot_sha256']
            or any(result.get(key)!=tool[key] for key in ('implementation_sha256','rust_input_sha256','native_input_sha256'))
            or result.get('cleanup_complete') is not True or result.get('vm_started') is not True):
        raise ValueError('Incomplete or mismatched quick result')
    scope=native_scope(value)
    if any(result['native_scope'][key]!=scope[key] for key in scope if key!='selected_objects'):
        raise ValueError('Quick native scope differs from submitted source')
    native_record={entry['name']:entry for entry in result['checks']}
    if scope['limitations'] and native_record['native-objects']['status']!='unavailable':
        raise ValueError('Unsupported native scope cannot claim compilation')
    if (native_record['native-objects']['status']=='completed' and not result['native_scope']['selected_objects']):
        raise ValueError('Native compilation completed without selected objects')
    timing=result.get('timings')
    if (not isinstance(timing,dict) or not all(key in timing for key in ('preparation_seconds','boot_seconds','total_seconds'))
            or any(type(number) not in (int,float) or not 0<=number<=4000 for number in timing.values())):
        raise ValueError('Malformed quick timing evidence')
    return result
