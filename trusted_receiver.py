"""Verify a sealed bundle before executing any code from it.

Obtain this bootstrap and the operator public keyring through a trusted channel.
Usage: python3 trusted_receiver.py BUNDLE_DIRECTORY OPERATOR_KEYRING [--install]
"""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def _secure_temp_base():
    for candidate in (Path('/var/tmp'), Path('/tmp')):
        try:
            info = candidate.lstat()
        except OSError:
            continue
        if (stat.S_ISDIR(info.st_mode) and not candidate.is_symlink()
                and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                and os.access(candidate, os.W_OK | os.X_OK)):
            return candidate
    raise RuntimeError(
        'No root-owned sticky temporary directory is available for protected receiver staging')


def _copy_bundle_tree(source, destination):
    source = Path(source).absolute()
    destination = Path(destination)
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    file_flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        source_fd = os.open(source, directory_flags)
    except OSError as exc:
        raise RuntimeError(f'Cannot open bundle directory without following links: {source}: {exc}') from exc
    destination.mkdir(mode=0o700)

    def copy_directory(source_directory_fd, target_directory):
        try:
            entries = list(os.scandir(source_directory_fd))
        except OSError as exc:
            raise RuntimeError(f'Cannot enumerate bundle while staging: {exc}') from exc
        for entry in entries:
            target = target_directory / entry.name
            try:
                before = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f'Bundle changed while staging: {entry.name}: {exc}') from exc
            if stat.S_ISLNK(before.st_mode):
                raise RuntimeError(f'Bundle contains a symbolic link and cannot be staged safely: {entry.name}')
            if stat.S_ISDIR(before.st_mode):
                try:
                    child_fd = os.open(entry.name, directory_flags, dir_fd=source_directory_fd)
                except OSError as exc:
                    raise RuntimeError(f'Bundle directory changed while staging: {entry.name}: {exc}') from exc
                try:
                    opened = os.fstat(child_fd)
                    if (not stat.S_ISDIR(opened.st_mode)
                            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                        raise RuntimeError(f'Bundle directory changed while staging: {entry.name}')
                    target.mkdir(mode=0o700)
                    copy_directory(child_fd, target)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError(f'Bundle contains a non-regular filesystem object: {entry.name}')
            try:
                input_fd = os.open(entry.name, file_flags, dir_fd=source_directory_fd)
            except OSError as exc:
                raise RuntimeError(f'Bundle file changed while staging: {entry.name}: {exc}') from exc
            try:
                opened = os.fstat(input_fd)
                if (not stat.S_ISREG(opened.st_mode)
                        or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
                    raise RuntimeError(f'Bundle file changed while staging: {entry.name}')
                with os.fdopen(input_fd, 'rb', closefd=False) as input_handle, target.open('xb') as output_handle:
                    shutil.copyfileobj(input_handle, output_handle, length=4 * 1024 * 1024)
            finally:
                os.close(input_fd)

    try:
        copy_directory(source_fd, destination)
    finally:
        os.close(source_fd)


def _normalize_read_only(root):
    root = Path(root)
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f'Protected receiver staging contains an unsafe file: {path}')
            path.chmod(0o444)
        for name in directories:
            path = current_path / name
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError(f'Protected receiver staging contains an unsafe directory: {path}')
            path.chmod(0o555)
    root.chmod(0o555)


def _lock_stage_as_root(staging_root):
    staging_root = Path(staging_root)
    _normalize_read_only(staging_root)
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        for current, directories, files in os.walk(staging_root, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                os.chown(current_path / name, 0, 0, follow_symlinks=False)
            for name in directories:
                os.chown(current_path / name, 0, 0, follow_symlinks=False)
        os.chown(staging_root, 0, 0, follow_symlinks=False)
    else:
        subprocess.run(['sudo', 'chown', '-R', '0:0', str(staging_root)], check=True)

    for current, directories, files in os.walk(staging_root, topdown=True, followlinks=False):
        current_path = Path(current)
        for path in [current_path] + [current_path / name for name in directories + files]:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222:
                raise RuntimeError(f'Protected receiver staging could not be locked read-only: {path}')


def _verify_bundle(directory, keyring):
    directory = Path(directory)
    for filename in ['bundle-index.json', 'verify-bundle.py']:
        subprocess.run(['gpgv', '--keyring', str(keyring), str(directory / (filename + '.asc')),
                        str(directory / filename)], check=True, cwd=directory)
    subprocess.run([sys.executable, str(directory / 'verify-bundle.py')], check=True, cwd=directory)


def _cleanup_staging(staging_root, locked):
    staging_root = Path(staging_root)
    if locked:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            shutil.rmtree(staging_root, ignore_errors=True)
        else:
            subprocess.run(['sudo', 'rm', '-rf', '--', str(staging_root)], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    try:
        for current, directories, files in os.walk(staging_root, topdown=False, followlinks=False):
            current_path = Path(current)
            for name in files:
                try:
                    (current_path / name).chmod(0o600)
                except OSError:
                    pass
            for name in directories:
                try:
                    (current_path / name).chmod(0o700)
                except OSError:
                    pass
        staging_root.chmod(0o700)
    except OSError:
        pass
    shutil.rmtree(staging_root, ignore_errors=True)


def verify(directory, keyring, install=False):
    source = Path(directory).absolute()
    keyring = Path(keyring).resolve(strict=True)
    if not source.is_dir() or source.is_symlink():
        raise RuntimeError('Bundle directory must be a real directory, not a symbolic link')

    base = _secure_temp_base() if install else None
    staging_root = Path(tempfile.mkdtemp(prefix='feathered-receiver-', dir=base))
    staged_bundle = staging_root / 'bundle'
    locked = False
    try:
        _copy_bundle_tree(source, staged_bundle)
        if install:
            _lock_stage_as_root(staging_root)
            locked = True
        _verify_bundle(staged_bundle, keyring)
        if install:
            env = dict(os.environ, FEATHERED_OPERATOR_KEYRING=str(keyring))
            subprocess.run(['bash', str(staged_bundle / 'install-offline.sh')], check=True,
                           cwd=staged_bundle, env=env)
    finally:
        _cleanup_staging(staging_root, locked)


if __name__ == '__main__':
    if len(sys.argv) not in {3, 4} or (len(sys.argv) == 4 and sys.argv[3] != '--install'):
        raise SystemExit(__doc__)
    verify(sys.argv[1], sys.argv[2], '--install' in sys.argv[3:])
