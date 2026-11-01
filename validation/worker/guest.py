"""Tiny cloud-init workload for worker qualification, not EQEmu acceptance."""
import json
import shlex

BUILD_CHECKS = (
    'rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'rust-doctests',
    'native-configure', 'native-build', 'zone-rust-symbol', 'native-utilities', 'normal-world',
)


def user_data(nonce, control):
    result = json.dumps({'version': 1, 'nonce': nonce, 'scope': 'worker-smoke',
                         'exit_code': 1 if control == 'assertion' else 0}, separators=(',', ':'))
    script = '#!/bin/sh\nset -eu\n'
    if control in ('deadline', 'controller-death'):
        script += 'sleep 600\n'
    elif control != 'missing-result':
        script += "printf '%s\\n' 'EQEMU_WORKER_RESULT " + result + "' >/dev/ttyS0\n"
    script += '/usr/sbin/poweroff\n'
    return '#cloud-config\n' + json.dumps({
        'hostname': 'eqemu-worker-smoke',
        'ssh_pwauth': False,
        'disable_root': True,
        'write_files': [{'path': '/opt/eqemu-worker-smoke', 'permissions': '0700', 'content': script}],
        'runcmd': [['/opt/eqemu-worker-smoke']],
    }) + '\n'


def build_user_data(nonce, profile=None):
    """The reviewed guest command travels in seed data, never executes on the host."""
    from pathlib import Path
    from sanitizers import checks
    selected = checks(BUILD_CHECKS, profile)
    failure = dict(version=1, nonce=nonce, scope='worker-build', exit_code=2,
                   stage='guest-launcher', selected_checks=list(selected), completed_checks=[],
                   error='Guest command exited with status %s before normal completion')
    # Keep a shell parent alive if Python dies before it can report a result.
    # The shell owns shutdown for both normal completion and abrupt process death.
    # A getty hangup invalidates already-open ttyS0 writers with EIO. Remove
    # that competing owner before opening the validation console.
    launcher = ('/usr/bin/systemctl mask --runtime --now serial-getty@ttyS0.service || exit 2\n'
                'exec >/dev/ttyS0 2>&1\n'
                '/usr/bin/python3 -u /opt/eqemu-worker-build-guest\n'
                'status=$?\n'
                'if [ "$status" -ne 0 ]; then\n'
                '    printf ' + shlex.quote('\\nEQEMU_WORKER_RESULT ' + json.dumps(failure) + '\\n') + ' "$status"\n'
                'fi\n'
                '/usr/sbin/poweroff\n')
    helpers = [('normal_world.py', Path(__file__).with_name('normal_world.py')),
               *[(name, Path(__file__).parents[1] / name) for name in
                 ('actor.py', 'actor_runtime.py', 'debugger.py', 'runtime-fixture.json')]]
    if profile: helpers.append(('sanitizers.py', Path(__file__).with_name('sanitizers.py')))
    return '#cloud-config\n' + json.dumps({
        'hostname': 'eqemu-worker-build', 'ssh_pwauth': False, 'disable_root': True,
        'write_files': [
            {'path': '/opt/eqemu-worker-build-guest', 'permissions': '0600',
             'content': Path(__file__).with_name('build_guest.py').read_text()},
            {'path': '/opt/eqemu-worker-nonce', 'permissions': '0600', 'content': nonce},
            {'path': '/opt/eqemu-worker-checks.json', 'permissions': '0600', 'content': json.dumps(selected)},
            *([{'path': '/opt/eqemu-worker-profile', 'permissions': '0600', 'content': profile}] if profile else []),
            *[{'path': '/opt/' + name, 'permissions': '0644', 'content': path.read_text()} for name, path in helpers],
        ],
        'runcmd': [['/bin/sh', '-c', launcher]],
    }) + '\n'


def format_user_data(nonce, request):
    """Only the reviewed formatter workload is copied into this disposable guest."""
    from pathlib import Path
    launcher = ('/usr/bin/systemctl mask --runtime --now serial-getty@ttyS0.service || exit 2\n'
                'exec >/dev/ttyS0 2>&1\n'
                '/usr/bin/python3 -u /opt/eqemu-worker-format-guest\n'
                '/usr/sbin/poweroff\n')
    files = [('format_guest.py', '/opt/eqemu-worker-format-guest'),
             ('build_guest.py', '/opt/build_guest.py'), ('snapshot.py', '/opt/snapshot.py')]
    return '#cloud-config\n' + json.dumps({
        'hostname': 'eqemu-worker-format', 'ssh_pwauth': False, 'disable_root': True,
        'write_files': [
            {'path': target, 'permissions': '0600', 'content': Path(__file__).with_name(name).read_text()}
            for name, target in files
        ] + [{'path': '/opt/eqemu-worker-nonce', 'permissions': '0600', 'content': nonce},
             {'path': '/opt/eqemu-format-request.json', 'permissions': '0600', 'content': json.dumps(request)}],
        'runcmd': [['/bin/sh', '-c', launcher]],
    }) + '\n'


def quick_user_data(nonce,request):
    """Fixed quick checks reuse the reviewed full-build provisioning helpers."""
    from pathlib import Path
    launcher=('/usr/bin/systemctl mask --runtime --now serial-getty@ttyS0.service || exit 2\n'
              'exec >/dev/ttyS0 2>&1\n/usr/bin/python3 -u /opt/eqemu-worker-quick-guest\n/usr/sbin/poweroff\n')
    files=[('quick_guest.py','/opt/eqemu-worker-quick-guest'),('quick_snapshot.py','/opt/quick_snapshot.py'),
           ('snapshot.py','/opt/snapshot.py'),('build_guest.py','/opt/build_guest.py')]
    return '#cloud-config\n'+json.dumps(dict(hostname='eqemu-worker-quick',ssh_pwauth=False,disable_root=True,
        write_files=[dict(path=target,permissions='0600',content=Path(__file__).with_name(name).read_text()) for name,target in files]+
            [dict(path='/opt/eqemu-worker-nonce',permissions='0600',content=nonce),
             dict(path='/opt/eqemu-quick-request.json',permissions='0600',content=json.dumps(request))],
        runcmd=[['/bin/sh','-c',launcher]]))+'\n'
