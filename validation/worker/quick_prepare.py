"""Verified public inputs plus a dirty source archive for fixed quick checks."""
import json
from pathlib import Path
import subprocess
import tempfile

from format_prepare import implementation
from prepare import record, NATIVE_SHA
import quick_snapshot as snapshot


def tool_identity(root, rust_package='original'):
    rust = snapshot.RUST_PACKAGES[rust_package]
    names=('scripts/quick-worker-snapshot','validation/worker/quick_snapshot.py','validation/worker/quick_prepare.py',
           'validation/worker/quick_guest.py','validation/worker/build_guest.py','validation/profile.json',
           'validation/rust-toolchain.json','validation/inputs.py','validation/worker/snapshot.py',
           'validation/worker/snapshot_apply.py','validation/worker/prepare.py','validation/worker/format_prepare.py',
           'validation/worker/client.py')
    recipe=snapshot.sha(snapshot.canonical(dict(version=1,files={name:record(root/name)['sha256'] for name in names},
        native_input_sha256=NATIVE_SHA,rust_input_sha256=rust['sha256'],checks=list(snapshot.CHECKS))))
    return dict(version=1,scope='working-snapshot-quick-tool',recipe_sha256=recipe,implementation_sha256=implementation(root),
        rust_input_sha256=rust['sha256'],native_input_sha256=NATIVE_SHA,checks=list(snapshot.CHECKS),
        limits=dict(snapshot_bytes=snapshot.SOURCE_LIMIT,snapshot_files=snapshot.FILE_COUNT,file_bytes=snapshot.FILE_LIMIT,
                    manifest_bytes=snapshot.MANIFEST_LIMIT,result_bytes=snapshot.RESULT_LIMIT,worker_seconds=3600,
                    client_seconds=3630,cleanup_grace_seconds=30))


def prepare(repo,value,websocketpp,native,rust,output,rust_package='original'):
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
    from inputs import GitTree, verify_archive
    profile=json.loads((Path(__file__).resolve().parents[1]/'profile.json').read_text())
    if value['gitlinks']!=profile['sources']['eqemu']['gitlinks']:
        raise ValueError('Quick snapshot requires unsupported native submodule inputs')
    if record(rust) != snapshot.RUST_PACKAGES[rust_package]:raise ValueError('Missing/changed pinned quick Rust input')
    for path,wanted in ((native,NATIVE_SHA),):
        if record(path)['sha256']!=wanted:raise ValueError('Missing/changed pinned quick input: '+str(path))
    with tempfile.TemporaryDirectory(prefix='eqemu-quick-payload-') as tmp:
        root=Path(tmp);archive=root/'eqemu.tar';snapshot.archive(repo,value,archive)
        if archive.stat().st_size>snapshot.ARCHIVE_LIMIT:raise ValueError('Quick source archive exceeds derived bound')
        scratch=root/'git';scratch.mkdir();dependency=GitTree(websocketpp,scratch)
        wanted=profile['sources']['websocketpp']
        entries,links=dependency.inventory(wanted['commit'],wanted['tree'])
        dependency.archive(wanted['commit'],root/'websocketpp.tar')
        verify_archive(root/'websocketpp.tar',entries,links)
        (root/'snapshot.json').write_bytes(snapshot.canonical(value))
        files={'snapshot.json':root/'snapshot.json','eqemu.tar':archive,'websocketpp.tar':root/'websocketpp.tar',
               'native.iso':Path(native),'rust-inputs.tar':Path(rust)}
        ident={key:snapshot.identity(value)[key] for key in ('base','head','recipe_sha256','input_snapshot_sha256')}
        ident['files']={name:record(path) for name,path in files.items()}
        (root/'identity.json').write_bytes(snapshot.canonical(ident))
        if output.exists() or output.is_symlink():raise ValueError('Quick payload already exists')
        try:
            subprocess.run(['/usr/bin/genisoimage','-quiet','-output',str(output),'-volid','EQEMU_INPUT','-joliet','-rock','-graft-points',
                'identity.json='+str(root/'identity.json'),*[name+'='+str(path) for name,path in files.items()]],
                check=True,timeout=120,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            if any(record(path)!=ident['files'][name] for name,path in files.items()):raise ValueError('Quick input changed during packaging')
            if snapshot.capture(repo,value['base'],value['recipe_sha256'])!=value:raise ValueError('Quick source changed during packaging')
            return dict(version=1,operation='quick',**ident,**record(output))
        except BaseException:
            output.unlink(missing_ok=True);raise
