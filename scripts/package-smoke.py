#!/usr/bin/env python3
"""Verify release package metadata and launch an installed, isolated native app.

Runs only on disposable native CI runners. Does not contact a test update feed,
install an SSH service, or use the runner's normal Simple Connect profile.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time


def run(args, log, *, cwd=None, env=None, timeout=120):
    print('Running:', ' '.join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    with log.open('ab') as output:
        output.write(result.stdout)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}; see {log}')
    return result.stdout.decode(errors='replace')


def one(bundle, pattern):
    matches = list(bundle.rglob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f'Expected one {pattern}, found {len(matches)} in {bundle}')
    return matches[0].resolve()


def launch(command, profile, logs, *, extra_env=None):
    env = os.environ.copy()
    # Native KnownFolder/Keychain APIs do not consistently honour HOME/APPDATA.
    env['SIMPLE_CONNECT_HOME'] = str(profile)
    env['HOME'] = str(profile)
    env['XDG_CONFIG_HOME'] = str(profile / 'config')
    env['XDG_DATA_HOME'] = str(profile / 'data')
    env['XDG_STATE_HOME'] = str(profile / 'state')
    env['XDG_RUNTIME_DIR'] = str(profile / 'runtime')
    env.update(extra_env or {})
    profile.mkdir(mode=0o700)
    (profile / 'runtime').mkdir(mode=0o700)
    log = logs / 'application.log'
    with log.open('wb') as output:
        proc = subprocess.Popen(list(map(str, command)), env=env, stdout=output, stderr=subprocess.STDOUT,
                                start_new_session=os.name != 'nt')
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f'Application exited early ({proc.returncode}); see {log}')
                time.sleep(0.2)
            print('Installed application stayed running for 10 seconds', flush=True)
        finally:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], stdout=output, stderr=output)
            else:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                if os.name != 'nt':
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
                proc.wait(timeout=10)
            # Preserve native diagnostics even if startup failed.
            if (profile / 'state').exists():
                shutil.copytree(profile / 'state', logs / 'profile-state', dirs_exist_ok=True)
    for diagnostic in (logs / 'profile-state').rglob('*'):
        if diagnostic.is_file() and 'SSH engine unavailable' in diagnostic.read_text(errors='replace'):
            raise RuntimeError(f'Application launched without a working SSH engine; see {diagnostic}')


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open('rb') as source:
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


@contextmanager
def update_fixture(artifact, target):
    signature = Path(f'{artifact}.sig').read_text().strip()
    version = json.loads(Path('package.json').read_text())['version']
    state = {'tamper': True}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == '/latest.json':
                manifest = {'version': version, 'platforms': {target: {
                    'url': f'http://127.0.0.1:{self.server.server_port}/package',
                    'signature': signature,
                }}}
                body = json.dumps(manifest).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == '/package':
                self.send_response(200)
                self.send_header('Content-Length', str(artifact.stat().st_size))
                self.end_headers()
                with artifact.open('rb') as source:
                    first = True
                    while chunk := source.read(1024 * 1024):
                        if first and state['tamper']:
                            chunk = bytes([chunk[0] ^ 1]) + chunk[1:]
                        first = False
                        self.wfile.write(chunk)
            else:
                self.send_error(404)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/latest.json', state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def rehearse_update(harness, installed, artifact, target, profile, logs, *, installed_app=None):
    """Exercise the real updater against both corrupt and genuine local bytes."""
    profile.mkdir(parents=True, exist_ok=True)
    sentinel = profile / 'data' / 'update-rehearsal-sentinel'
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    sentinel.write_text('isolated application data survives 0.0.9 -> candidate')
    sentinel_hash = digest(sentinel)
    expected_hash = digest(installed)
    if sys.platform == 'linux':
        # A distinct installed old AppImage, never the distributable candidate.
        # Its old app version is provided by the native example context below.
        with installed.open('ab') as old_image:
            old_image.write(b'\ninstalled-0.0.9-rehearsal\n')
        command = ['xvfb-run', '-a', 'dbus-run-session', '--', harness]
    else:
        shutil.copy2(harness, installed)
        if installed_app:
            run(['codesign', '--force', '--deep', '--sign', '-', installed_app], logs / 'update-rehearsal.log')
        command = [installed]
    old_hash = digest(installed)
    if old_hash == expected_hash:
        raise RuntimeError('Installed older rehearsal binary must differ from candidate')
    env = os.environ.copy()
    env.update({'SIMPLE_CONNECT_HOME': str(profile), 'HOME': str(profile), 'WEBKIT_DISABLE_DMABUF_RENDERER': '1'})
    if sys.platform == 'linux':
        env['APPIMAGE'] = str(installed)
    with update_fixture(artifact, target) as (feed, state):
        result = run([*command, 'reject-tamper', feed, installed, target], logs / 'update-rehearsal.log', env=env, timeout=240)
        if 'Tampered download rejected by native minisign verification' not in result:
            raise RuntimeError('Native updater did not confirm signature rejection')
        if digest(installed) != old_hash or digest(sentinel) != sentinel_hash:
            raise RuntimeError('Tampered update changed the installation or application data')
        state['tamper'] = False
        run([*command, 'install', feed, installed, target], logs / 'update-rehearsal.log', env=env, timeout=240)
        # Windows' native updater exits before its NSIS installer finishes.
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if digest(installed) == expected_hash:
                    break
            except (FileNotFoundError, PermissionError):
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError('Native updater did not restore the signed candidate executable/image')
    if digest(sentinel) != sentinel_hash:
        raise RuntimeError('Application data changed during native update')
    if installed_app:
        run(['codesign', '--verify', '--deep', '--strict', installed_app], logs / 'update-rehearsal.log')
    print(f'Native {target} updater rejected tampering, installed candidate, and preserved data', flush=True)


def windows(bundle, arch, work, logs, harness):
    installer = one(bundle, '*-setup.exe')
    destination = work / 'installed'
    # NSIS /D is the final argument and is intentionally unquoted. CI temp roots
    # are space-free; an unexpected runner path must fail rather than install elsewhere.
    if ' ' in str(destination):
        raise RuntimeError('NSIS smoke install requires a space-free temporary root')
    run([installer, '/S', f'/D={destination}'], logs / 'installer.log', timeout=180)
    executable = destination / 'simple-connect.exe'
    if not executable.is_file():
        raise RuntimeError('NSIS did not install the application at the requested location')
    with executable.open('rb') as binary:
        binary.seek(0x3C)
        pe_offset = struct.unpack('<I', binary.read(4))[0]
        binary.seek(pe_offset)
        if binary.read(4) != b'PE\0\0':
            raise RuntimeError('Installed Windows binary is not PE')
        machine = struct.unpack('<H', binary.read(2))[0]
    if machine != (0xAA64 if arch == 'aarch64' else 0x8664):
        raise RuntimeError('Installed Windows binary architecture mismatch')
    ssh = destination / 'openssh' / 'ssh.exe'
    keygen = destination / 'openssh' / 'ssh-keygen.exe'
    for client in (ssh, keygen):
        if not client.is_file():
            raise RuntimeError(f'Bundled client missing: {client}')
    run([ssh, '-V'], logs / 'openssh.log')
    # Exercise DLL loading and key generation without touching ~/.ssh.
    key = work / 'smoke-key'
    run([keygen, '-q', '-t', 'ed25519', '-N', '', '-f', key], logs / 'openssh.log')
    run([keygen, '-lf', f'{key}.pub'], logs / 'openssh.log')
    launch([executable], work / 'profile', logs)
    rehearse_update(harness, executable, installer, f'windows-{arch}-nsis', work / 'profile', logs)
    uninstaller = destination / 'uninstall.exe'
    if uninstaller.exists():
        run([uninstaller, '/S'], logs / 'uninstall.log', timeout=120)


def macos(bundle, arch, work, logs, harness):
    image = one(bundle, '*.dmg')
    mount = work / 'mount'
    mount.mkdir()
    attached = False
    try:
        run(['hdiutil', 'attach', image, '-readonly', '-nobrowse', '-mountpoint', mount], logs / 'installer.log')
        attached = True
        application = one(mount, '*.app')
        installed = work / application.name
        run(['ditto', application, installed], logs / 'installer.log')
    finally:
        if attached:
            run(['hdiutil', 'detach', mount], logs / 'installer.log')
    run(['codesign', '--verify', '--deep', '--strict', installed], logs / 'codesign.log')
    binary = installed / 'Contents' / 'MacOS' / 'simple-connect'
    description = run(['file', binary], logs / 'architecture.log')
    expected = 'arm64' if arch == 'aarch64' else 'x86_64'
    if expected not in description:
        raise RuntimeError(f'Mach-O architecture mismatch: {description}')
    launch([binary], work / 'profile', logs)
    rehearse_update(harness, binary, one(bundle, '*.app.tar.gz'), f'darwin-{arch}-app', work / 'profile', logs, installed_app=installed)


def linux(bundle, arch, work, logs, harness):
    deb = one(bundle, '*.deb')
    rpm = one(bundle, '*.rpm')
    expected_deb = 'arm64' if arch == 'aarch64' else 'amd64'
    if run(['dpkg-deb', '-f', deb, 'Architecture'], logs / 'metadata.log').strip() != expected_deb:
        raise RuntimeError('DEB architecture mismatch')
    if 'openssh-client' not in run(['dpkg-deb', '-f', deb, 'Depends'], logs / 'metadata.log'):
        raise RuntimeError('DEB does not declare openssh-client')
    if run(['rpm', '-qp', '--qf', '%{ARCH}', rpm], logs / 'metadata.log').strip() != arch:
        raise RuntimeError('RPM architecture mismatch')
    if 'openssh-clients' not in run(['rpm', '-qp', '--requires', rpm], logs / 'metadata.log'):
        raise RuntimeError('RPM does not declare openssh-clients')
    image = one(bundle, '*.AppImage')
    image.chmod(0o755)
    run([image, '--appimage-extract'], logs / 'extract.log', cwd=work)
    apprun = work / 'squashfs-root' / 'AppRun'
    if not apprun.exists():
        raise RuntimeError('AppImage extraction did not produce AppRun')
    launch(['xvfb-run', '-a', '-s', '-screen 0 1280x800x24', 'dbus-run-session', '--', apprun],
           work / 'profile', logs, extra_env={'APPIMAGE': str(image), 'WEBKIT_DISABLE_DMABUF_RENDERER': '1'})
    old_image = work / 'installed-old.AppImage'
    shutil.copy2(image, old_image)
    rehearse_update(harness, old_image, image, f'linux-{arch}-appimage', work / 'profile', logs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--arch', choices=['x86_64', 'aarch64'], required=True)
    parser.add_argument('--logs', type=Path, required=True)
    parser.add_argument('--harness-dir', type=Path, required=True)
    args = parser.parse_args()
    args.logs.mkdir(parents=True, exist_ok=True)
    args.logs = args.logs.resolve()
    # macOS's default temporary path is too long for Unix domain sockets.
    with tempfile.TemporaryDirectory(prefix='sc-smoke-', dir='/tmp' if sys.platform == 'darwin' else None) as temporary:
        work = Path(temporary)
        handler = windows if sys.platform == 'win32' else macos if sys.platform == 'darwin' else linux
        harness = args.harness_dir.resolve() / ('update_rehearsal.exe' if os.name == 'nt' else 'update_rehearsal')
        if not harness.is_file():
            raise RuntimeError(f'Native updater rehearsal example missing: {harness}')
        handler(args.bundle.resolve(), args.arch, work, args.logs, harness)
    print('Package smoke check passed', flush=True)


if __name__ == '__main__':
    main()
