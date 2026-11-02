#!/usr/bin/python3 -I
"""Prepare or operate one finite additive profiling selection. Never starts a VM.

Run prepare as the submitter. Root verify/apply/activate/rollback require the exact
package SHA256. Apply only publishes files. Activate starts the new socket once,
without enabling it at boot. Ordinary and diagnostic selections are retained.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

SOURCE_FILES=(
    'validation/worker/runtime.py','validation/worker/guest.py','validation/worker/build_guest.py',
    'validation/worker/normal_world.py','validation/worker/client.py','validation/worker/identity.py',
    'validation/worker/prepare.py','validation/worker/profiling.py','validation/worker/profile_artifacts.py',
    'validation/worker/profile_inputs.py','validation/worker/profile_contract.py',
    'validation/worker/snapshot.py','validation/worker/format_guest.py',
    'validation/worker/quick_snapshot.py','validation/worker/quick_guest.py',
    'validation/actor.py','validation/actor_runtime.py','validation/debugger.py',
    'validation/runtime-fixture.json','validation/inputs.py','validation/profile.json',
    'scripts/check-validation-worker','scripts/validate-worker-candidate',
)
CONFIG='/etc/eqemu-validator/profiling.json'
ORDINARY='/etc/eqemu-validator/config.json'
JOURNAL='/etc/eqemu-validator/profiling-publication.json'
STATE='/var/lib/eqemu-validator-profiling'
SHARED_LOCK='/var/lib/eqemu-validator/worker.lock'
RELEASE_ROOT='/srv/eqemu-validator-profiling'
SOCKET='eqemu-validator-profiling.socket'
SERVICE='eqemu-validator-profiling@.service'
POLICY='/etc/apparmor.d/eqemu-validator-profiling'
MAX_BYTES=8*1024**2


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
def sha(data): return hashlib.sha256(data).hexdigest()


def read(path,limit=1024**2):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit: raise ValueError('Not a finite regular package file')
        data=stream.read(limit+1)
        if len(data)!=info.st_size: raise ValueError('Package changed while reading')
        return data


def read_virtual(path,limit=1024**2):
    with Path(path).open('rb') as stream: data=stream.read(limit+1)
    if len(data)>limit: raise ValueError('Virtual file budget exceeded')
    return data


def prepare(output,source,ordinary,commit,base):
    """Pure packaging from a clean source commit; no installation or setup commands."""
    if not all(re.fullmatch('[a-f0-9]{40}',value) for value in (commit,base)): raise ValueError('Full source pins required')
    if ordinary.get('state_dir')!='/var/lib/eqemu-validator': raise ValueError('Default ordinary shared lock required')
    release=RELEASE_ROOT+'/'+commit
    files={'code/'+name:read(source/name) for name in SOURCE_FILES}
    code_manifest=dict(version=1,source_commit=commit,base_commit=base,
        files={name:dict(bytes=len(files['code/'+name]),sha256=sha(files['code/'+name])) for name in SOURCE_FILES})
    files['code/manifest.json']=canonical(code_manifest)
    config=dict(ordinary,selection='profiling-v1',confinement='eqemu-validator-profiling',shared_lock=SHARED_LOCK,
        source_commit=commit,release_manifest_sha256=sha(files['code/manifest.json']),code_dir=release,
        state_dir=STATE,socket='/run/eqemu-validator-profiling.sock')
    files['config.json']=canonical(config)
    template=source/'validation/worker/templates'
    replacements={'@CODE@':release,'@STATE@':STATE,'@BASE@':ordinary['base_image'],'@USER@':ordinary['user'],
        '@SOCKET@':config['socket'],'@SUBMITTER_GROUP@':str(pwd.getpwnam(ordinary['submitter']).pw_gid)}
    for name,filename in (('service','eqemu-validator@.service'),('socket','eqemu-validator.socket'),('apparmor','apparmor')):
        text=read(template/filename).decode()
        for key,value in replacements.items(): text=text.replace(key,value)
        text=text.replace('/etc/eqemu-validator/config.json',CONFIG)
        text=text.replace('AppArmorProfile=eqemu-validator','AppArmorProfile=eqemu-validator-profiling')
        if name=='service':
            text=text.replace('ReadWritePaths='+STATE,'ReadWritePaths='+STATE+' '+SHARED_LOCK)
        if name=='apparmor':
            text=text.replace('profile eqemu-validator ', 'profile eqemu-validator-profiling ')
            text=text.replace('peer=eqemu-validator,','peer=eqemu-validator-profiling,')
            text=text.replace('peer="eqemu-validator//','peer="eqemu-validator-profiling//')
            text=text.replace('//&eqemu-validator"','//&eqemu-validator-profiling"')
            # The ordinary config is read only to bind account/base/lock identity.
            text=text.replace(CONFIG+' r,',CONFIG+' r,\n  '+ORDINARY+' r,')
            text=text.replace('  /tmp/ rw,','  /var/lib/eqemu-validator/ r,\n  '+SHARED_LOCK+' rwk,\n  /tmp/ rw,')
        if '@' in text.replace('validator@.service',''): raise ValueError('Unexpanded profiling template token')
        files[name]=text.encode()
    files['operator.py']=read(Path(__file__))
    output.mkdir(mode=0o700)
    for name,data in files.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream: stream.write(data)
    package=dict(version=1,source_commit=commit,base_commit=base,
        files={name:dict(bytes=len(data),sha256=sha(data)) for name,data in files.items()})
    (output/'package.json').write_bytes(canonical(package))
    return dict(package_sha256=sha(canonical(package)),operator_sha256=sha(files['operator.py']),source_commit=commit,
        release=release,executed=False,installed=False)


def load_package(directory,expected):
    raw=read(directory/'package.json',65536)
    if sha(raw)!=expected: raise ValueError('Package SHA256 mismatch')
    value=json.loads(raw)
    wanted={'code/'+name for name in SOURCE_FILES}|{'code/manifest.json','config.json','service','socket','apparmor','operator.py'}
    if (value.get('version')!=1 or set(value.get('files',{}))!=wanted
            or not re.fullmatch('[a-f0-9]{40}',value.get('source_commit',''))): raise ValueError('Package closure mismatch')
    found=set()
    allowed_dirs={parent for name in wanted|{'package.json'} for parent in (directory/name).parents if parent.is_relative_to(directory)}
    for path in directory.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()) or path.is_dir() and path not in allowed_dirs: raise ValueError('Symlink in profiling package')
        if path.is_file(): found.add(str(path.relative_to(directory)))
    if found!=wanted|{'package.json'}: raise ValueError('Unknown or omitted profiling package file')
    files={name:read(directory/name) for name in wanted}
    if sum(map(len,files.values()))>MAX_BYTES: raise ValueError('Profiling package budget')
    for name,data in files.items():
        if value['files'][name]!={'bytes':len(data),'sha256':sha(data)}: raise ValueError('Package file identity mismatch: '+name)
    config=json.loads(files['config.json'])
    release=RELEASE_ROOT+'/'+value['source_commit']
    if (config.get('code_dir')!=release or config.get('state_dir')!=STATE or config.get('shared_lock')!=SHARED_LOCK
            or config.get('confinement')!='eqemu-validator-profiling' or config.get('selection')!='profiling-v1'
            or config.get('socket')!='/run/eqemu-validator-profiling.sock'
            or config.get('source_commit')!=value['source_commit']
            or config.get('release_manifest_sha256')!=sha(files['code/manifest.json'])):
        raise ValueError('Package selection identity mismatch')
    code=json.loads(files['code/manifest.json'])
    if (code.get('source_commit')!=value['source_commit'] or set(code.get('files',{}))!=set(SOURCE_FILES)
            or any(code['files'][name]!={'bytes':len(files['code/'+name]),'sha256':sha(files['code/'+name])} for name in SOURCE_FILES)):
        raise ValueError('New release closure is not self-consistent')
    return value,files,config


class Host:
    """Filesystem and system tools kept at a seam for unprivileged synthetic tests."""
    def __init__(self,root=Path('/')): self.root=root
    def path(self,name): return self.root/str(name).lstrip('/')
    def info(self,path): return path.lstat()
    def chown(self,path,uid,gid): os.chown(path,uid,gid)
    def run(self,args): return subprocess.check_output(args,stderr=subprocess.STDOUT,timeout=30,text=True)
    def account(self,name): return pwd.getpwnam(name)
    def processes(self):
        for path in Path('/proc').glob('[0-9]*/comm'):
            try:
                if path.read_text().strip() in ('qemu-system-x86','qemu-system-x86_64','qemu-kvm','afk'):
                    raise ValueError('Shared worker or AFK process exists')
            except FileNotFoundError: pass


def protected(host,path,*,uid=0,mode=None,regular=True):
    for parent in (path,*path.parents):
        info=host.info(parent)
        target=parent==path
        if stat.S_ISLNK(info.st_mode) or (target and regular and not stat.S_ISREG(info.st_mode)):
            raise ValueError('Symlink or nonregular protected asset')
        if (info.st_uid!=(uid if target else 0) or (info.st_mode&0o022 and not (target and uid!=0))
                or target and mode is not None and stat.S_IMODE(info.st_mode)!=mode):
            raise ValueError('Protected asset owner/mode mismatch: '+str(parent))
        if parent==host.root: break


def quiescent(host):
    output=host.run(['/usr/bin/systemctl','list-units','--all','--no-legend','--plain','--type=service','eqemu-validator*','afk*'])
    for row in output.splitlines():
        fields=row.split()
        if len(fields)<4 or fields[2] not in ('inactive','failed') or fields[3] not in ('dead','failed'):
            raise ValueError('Shared selections are active or uncertain')
    host.processes()


def retained(host):
    """Record actual retained metadata, including submitter-owned ordinary helpers."""
    result={}
    for name in ('config.json','asan-v1.json','asan-v2.json','asan-v3.json'):
        path=host.path('/etc/eqemu-validator/'+name)
        if not path.exists(): raise ValueError('Expected retained selection configuration missing')
        protected(host,path)
        config=json.loads(read(path))
        state=host.path(config['state_dir'])
        if (state/'active.json').exists() or (state/'active.json').is_symlink():
            raise ValueError('Retained worker has active or unconfirmed cleanup state')
        code=host.path(config['code_dir'])
        entries=list(code.rglob('*'))
        if len(entries)>256 or any(item.is_symlink() for item in entries): raise ValueError('Retained code tree is unknown or oversized')
        paths=[path,*[item for item in entries if item.is_file()]]
        stem='eqemu-validator' if name=='config.json' else 'eqemu-validator-'+name.removesuffix('.json')
        paths += [host.path('/etc/systemd/system/'+stem+suffix) for suffix in ('@.service','.socket')]
        paths.append(host.path('/etc/apparmor.d/'+stem))
        for asset in paths:
            raw=read(asset);info=host.info(asset)
            result[str(asset.relative_to(host.root))]=dict(sha256=sha(raw),bytes=len(raw),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
    return result


@contextlib.contextmanager
def shared_lock(host,config):
    path=host.path(SHARED_LOCK)
    # The parent belongs to the ordinary worker. Never create an alternate lock.
    protected(host,path.parent,uid=config['worker_uid'],mode=0o700,regular=False)
    info=host.info(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=config['worker_uid'] or info.st_gid!=config['worker_gid'] or stat.S_IMODE(info.st_mode)!=0o600:
        raise ValueError('Ordinary shared lock must be regular owned mode 0600')
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
    try:
        actual=os.fstat(fd)
        if (actual.st_dev,actual.st_ino)!=(info.st_dev,info.st_ino): raise ValueError('Shared lock changed')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def plan(files,config):
    targets={config['code_dir']+'/'+name.removeprefix('code/'):data for name,data in files.items() if name.startswith('code/')}
    targets.update({CONFIG:files['config.json'],'/etc/systemd/system/'+SERVICE:files['service'],
        '/etc/systemd/system/'+SOCKET:files['socket'],POLICY:files['apparmor']})
    return targets


def temporary(path):
    return path.with_name(path.name+'.profiling-tmp')


def check_temporary(host,path,data,mode):
    if path.exists() or path.is_symlink():
        protected(host,path)
        if stat.S_IMODE(host.info(path).st_mode) not in (0o600,mode) or not data.startswith(read(path)):
            raise ValueError('Unrecognized partial publication file')


def publish(host,path,data,mode):
    """Publish complete bytes with no replacement; partial temporary files are owned."""
    pending=temporary(path)
    check_temporary(host,pending,data,mode)
    if pending.exists(): pending.unlink()
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    pending.chmod(mode);host.chown(pending,0,0)
    os.link(pending,path,follow_symlinks=False)
    # The link inherits ownership. Record it too in synthetic filesystem tests.
    host.chown(path,0,0)
    pending.unlink()


def operate(host,directory,expected,operation):
    protected(host,directory,regular=False)
    package,files,config=load_package(directory,expected)
    if read(Path(__file__))!=files['operator.py']: raise ValueError('Use the exact reviewed packaged operator')
    ordinary_path=host.path(ORDINARY);protected(host,ordinary_path)
    ordinary=json.loads(read(ordinary_path))
    if (ordinary.get('state_dir')!='/var/lib/eqemu-validator'
            or any(config.get(key)!=ordinary.get(key) for key in ('user','worker_uid','worker_gid','submitter','base_image','version'))):
        raise ValueError('Ordinary identity changed after packaging')
    account=host.account(config['user']);submitter=host.account(config['submitter'])
    if account.pw_uid==0 or account.pw_uid!=config['worker_uid'] or account.pw_gid!=config['worker_gid'] or submitter.pw_uid in (0,account.pw_uid):
        raise ValueError('Configured worker/submitter account identity mismatch')
    targets=plan(files,config)
    marker=host.path(JOURNAL)
    with shared_lock(host,config):
        quiescent(host)
        before=retained(host)
        proposed_journal=dict(version=1,package_sha256=expected,retained=before)
        check_temporary(host,temporary(marker),canonical(proposed_journal),0o600)
        journal=json.loads(read(marker)) if marker.exists() else None
        if journal is not None:
            protected(host,marker,mode=0o600)
            if journal.get('package_sha256')!=expected or journal.get('retained')!=before:
                raise ValueError('Publication journal or retained assets changed')
        release=host.path(config['code_dir'])
        if release.exists():
            expected_paths={host.path(path) for path in targets if path.startswith(config['code_dir']+'/')}
            expected_paths |= {temporary(path) for path in expected_paths}
            expected_dirs={parent for path in expected_paths for parent in path.parents if parent.is_relative_to(release)}
            entries=list(release.rglob('*'))
            if len(entries)>128 or any(p.is_symlink() or not (p.is_file() or p.is_dir()) or p.is_file() and p not in expected_paths or p.is_dir() and p not in expected_dirs for p in entries):
                raise ValueError('Unknown asset in profiling release')
        for path,data in targets.items():
            check_temporary(host,temporary(host.path(path)),data,0o755 if '/scripts/' in path else 0o644)
        if operation=='apply':
            if journal is None:
                # Refuse collisions before acquiring ownership of any publication.
                if any(host.path(path).exists() or host.path(path).is_symlink() or temporary(host.path(path)).exists() for path in targets) or host.path(STATE).exists() or host.path(config['code_dir']).exists():
                    raise ValueError('Additive publication collision; no replacement allowed')
                journal=proposed_journal
                protected(host,marker.parent,regular=False)
                publish(host,marker,canonical(journal),0o600)
            for path,data in targets.items():
                dest=host.path(path)
                missing=[parent for parent in dest.parents if not parent.exists()]
                for parent in reversed(missing):
                    protected(host,parent.parent,regular=False)
                    parent.mkdir(mode=0o755);host.chown(parent,0,0)
                protected(host,dest.parent,mode=0o755,regular=False)
                mode=0o755 if '/scripts/' in path else 0o644
                check_temporary(host,temporary(dest),data,mode)
                if dest.exists() or dest.is_symlink():
                    protected(host,dest,mode=mode)
                    if read(dest)!=data: raise ValueError('Partial publication drift; refusing replacement')
                    if temporary(dest).exists(): temporary(dest).unlink()
                else:
                    publish(host,dest,data,mode)
            state=host.path(STATE)
            if not state.exists():
                state.mkdir(mode=0o700);host.chown(state,config['worker_uid'],config['worker_gid'])
            protected(host,state,uid=config['worker_uid'],mode=0o700,regular=False)
        elif operation in ('verify','activate'):
            if journal is None: raise ValueError('No owned profiling publication')
            for path,data in targets.items():
                dest=host.path(path);protected(host,dest,mode=0o755 if '/scripts/' in path else 0o644)
                if read(dest)!=data: raise ValueError('Published profiling asset changed')
            protected(host,host.path(STATE),uid=config['worker_uid'],mode=0o700,regular=False)
            host.run(['/usr/bin/systemd-analyze','verify',str(host.path('/etc/systemd/system/'+SERVICE)),str(host.path('/etc/systemd/system/'+SOCKET))])
            host.run(['/usr/sbin/apparmor_parser','--skip-kernel-load','--skip-cache',str(host.path(POLICY))])
            if operation=='activate':
                host.run(['/usr/bin/systemctl','daemon-reload'])
                host.run(['/usr/sbin/apparmor_parser','-r',str(host.path(POLICY))])
                host.run(['/usr/bin/systemctl','start',SOCKET])
        elif operation=='rollback':
            if journal is None:
                if any(host.path(path).exists() for path in targets): raise ValueError('Unowned profiling assets exist')
                if temporary(marker).exists(): temporary(marker).unlink()
                return dict(operation=operation,removed=False,vm_started=False)
            # Only this selection is stopped. The shared lock and quiescence guard
            # prevent removing code used by a connection or any other selection.
            host.run(['/usr/bin/systemctl','stop',SOCKET])
            # Policy may never have been loaded during a partial publication.
            profiles=host.path('/sys/kernel/security/apparmor/profiles')
            if profiles.exists() and 'eqemu-validator-profiling (enforce)' in read_virtual(profiles).decode().splitlines():
                host.run(['/usr/sbin/apparmor_parser','-R',str(host.path(POLICY))])
            for path,data in targets.items():
                dest=host.path(path)
                check_temporary(host,temporary(dest),data,0o755 if '/scripts/' in path else 0o644)
                if dest.exists() or dest.is_symlink():
                    protected(host,dest,mode=0o755 if '/scripts/' in path else 0o644)
                    if read(dest)!=data: raise ValueError('Rollback refuses changed profiling asset')
            for path in targets:
                temporary(host.path(path)).unlink(missing_ok=True)
                host.path(path).unlink(missing_ok=True)
            directories={parent for path in targets for parent in host.path(path).parents if parent.is_relative_to(host.path(config['code_dir']))}
            for directory in sorted(directories,key=lambda p:len(p.parts),reverse=True):
                if directory.exists(): directory.rmdir()
            state=host.path(STATE)
            if state.exists() and not any(state.iterdir()): state.rmdir()
            temporary(marker).unlink(missing_ok=True)
            marker.unlink()
            host.run(['/usr/bin/systemctl','daemon-reload'])
        else: raise ValueError('Unknown profiling publication operation')
        if retained(host)!=before: raise ValueError('Retained assets changed during operation')
        return dict(operation=operation,private_state_retained=host.path(STATE).exists(),package_sha256=expected,source_commit=package['source_commit'],
            ordinary_preserved=True,retained=before,enabled_at_boot=False,vm_started=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('prepare','verify','apply','activate','rollback'))
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--package-sha256')
    parser.add_argument('--base',default='b9996308a027ef5a3432dc451039f9fa2974b072')
    args=parser.parse_args()
    if args.operation=='prepare':
        if os.geteuid()==0: raise ValueError('Prepare the package as the submitter')
        source=Path(__file__).resolve().parents[2]
        def git(*argv): return subprocess.check_output(['git','-C',str(source),*argv],text=True).strip()
        if git('status','--porcelain','--untracked-files=all'): raise ValueError('Prepare from a clean committed source tree')
        result=prepare(args.package,source,json.loads(read(Path(ORDINARY))),git('rev-parse','HEAD'),git('rev-parse',args.base))
    else:
        if os.geteuid()!=0: raise ValueError('Publication operation requires root')
        if not args.package_sha256 or not re.fullmatch('[a-f0-9]{64}',args.package_sha256): raise ValueError('Exact reviewed package SHA256 required')
        result=operate(Host(),args.package,args.package_sha256,args.operation)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__': main()
