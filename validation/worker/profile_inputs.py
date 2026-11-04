"""Optional, explicitly pinned offline profiler packages, installed only in a guest.

Bundle schema is a finite tar of manifest.json and debs/*.deb. The entire tar
SHA256 is selected explicitly by the caller and bound into candidate identity.
"""
import hashlib
import json
from pathlib import Path
import re
import tarfile

LIMIT = 256*1024**2


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def manifest(path):
    """Validate opaque package bytes without extracting or executing them on the host."""
    if Path(path).stat().st_size > LIMIT: raise ValueError('Profiler input exceeds 256 MiB')
    with tarfile.open(path) as stream:
        members=stream.getmembers()
        if len(members)>128 or sum(item.size for item in members)>LIMIT or any(not item.isfile() or item.size>64*1024**2 for item in members):
            raise ValueError('Profiler input requires bounded regular files')
        names=[item.name for item in members]
        if len(names)!=len(set(names)) or 'manifest.json' not in names:
            raise ValueError('Profiler manifest missing/duplicate')
        entry=stream.getmember('manifest.json')
        if entry.size>65536: raise ValueError('Profiler manifest oversized')
        value=json.load(stream.extractfile(entry))
        if (not isinstance(value,dict) or set(value)!={'version','packages','tools'} or value['version']!=1
                or not isinstance(value['packages'],list) or not 1<=len(value['packages'])<=64
                or not isinstance(value['tools'],dict)):
            raise ValueError('Malformed profiler manifest')
        expected={'manifest.json'}
        for package in value['packages']:
            if (set(package)!={'path','package','version','sha256','bytes'}
                    or not re.fullmatch(r'debs/[a-zA-Z0-9_.+%:~-]+\.deb',package['path'])
                    or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]+',package['package'])
                    or not re.fullmatch(r'[a-zA-Z0-9.+:~_-]+',package['version'])
                    or not re.fullmatch('[a-f0-9]{64}',package['sha256'])
                    or type(package['bytes']) is not int or not 0<package['bytes']<=64*1024**2
                    or package['path'] in expected):
                raise ValueError('Malformed profiler package pin')
            expected.add(package['path'])
            item=stream.getmember(package['path'])
            if item.size!=package['bytes'] or hashlib.file_digest(stream.extractfile(item),'sha256').hexdigest()!=package['sha256']:
                raise ValueError('Profiler package identity mismatch')
        from profiling import TOOLS
        allowed={path for paths in TOOLS.values() for path in paths}
        if (not set(value['tools'])<=allowed or any(not re.fullmatch('[a-f0-9]{64}',sha) for sha in value['tools'].values())):
            raise ValueError('Unknown profiler tool pin')
        if set(names)!=expected: raise ValueError('Unexpected profiler bundle file')
    return value


def install(build, path, mode):
    """No network, upgrade, removal, persistent selection, or service-policy change."""
    value=manifest(path)
    from profiling import TOOLS
    if not set(TOOLS.get(mode,()))<=set(value['tools']):
        raise ValueError('Requested profiler tools are not pinned')
    target=build.WORK/'profiler-packages'; target.mkdir()
    with tarfile.open(path) as stream:
        for package in value['packages']:
            dest=target/Path(package['path']).name
            with stream.extractfile(package['path']) as src, dest.open('xb') as dst:
                while block:=src.read(1024**2): dst.write(block)
    current=build.command('profiler-installed-packages',['dpkg-query','-W','-f=${Package}\t${Version}\n'])
    installed=dict(row.split('\t') for row in current.splitlines())
    for package in value['packages']:
        old=installed.get(package['package'])
        if old is not None and old!=package['version']:
            raise ValueError('Profiler bundle would upgrade an installed guest package')
    build.command('profiler-offline-install',['apt-get','--no-download','--no-remove','--no-upgrade','-y',
        '--no-install-recommends','install',*[str(target/Path(p['path']).name) for p in value['packages']]])
    for tool,expected in value['tools'].items():
        if digest(tool)!=expected: raise ValueError('Installed profiler tool identity mismatch')
    return value


def package(debs,output,mode):
    """Package explicitly chosen trusted public debs as data, without installing them."""
    import subprocess
    import tempfile
    from profiling import TOOLS
    if mode not in ('heaptrack','perf') or not 1<=len(debs)<=64: raise ValueError('Select one profiler and finite explicit deb files')
    if Path(output).exists(): raise ValueError('Profiler output already exists')
    with tempfile.TemporaryDirectory(prefix='eqemu-profile-debs-') as tmp:
        root=Path(tmp)
        packages=[]
        for index,path in enumerate(map(Path,debs)):
            if not path.is_file() or path.is_symlink() or not 0<path.stat().st_size<=64*1024**2: raise ValueError('Not a bounded public deb')
            fields=subprocess.check_output(['/usr/bin/dpkg-deb','-f',str(path),'Package','Version'],timeout=30,text=True).splitlines()
            values=dict(row.split(': ',1) for row in fields)
            entry=dict(path='debs/'+str(index)+'.deb',package=values['Package'],version=values['Version'],
                       bytes=path.stat().st_size,sha256=digest(path))
            packages.append(entry)
            subprocess.run(['/usr/bin/dpkg-deb','-x',str(path),str(root)],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        value=dict(version=1,packages=packages,tools={path:digest(root/path.lstrip('/')) for path in TOOLS[mode]})
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        try:
            with tarfile.open(output,'x') as stream:
                import io
                item=tarfile.TarInfo('manifest.json');item.size=len(raw);stream.addfile(item,io.BytesIO(raw))
                for path,entry in zip(debs,packages):
                    stream.add(path,arcname=entry['path'],recursive=False)
            manifest(output)
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise
    return dict(sha256=digest(output),bytes=Path(output).stat().st_size,manifest=value,installed=False)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deb',type=Path,action='append',required=True)
    parser.add_argument('--mode',choices=('heaptrack','perf'),required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(package(args.deb,args.output,args.mode),sort_keys=True))
