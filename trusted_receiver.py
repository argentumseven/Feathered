"""Verify a sealed bundle before executing any code from it.

Obtain this bootstrap and the operator public keyring through a trusted channel.
Usage: python3 trusted_receiver.py BUNDLE_DIRECTORY OPERATOR_KEYRING [--install]
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile


_BOOTSTRAP_LIMITS = {
    "bundle-index.json": 64 * 1024 * 1024,
    "bundle-index.json.asc": 1024 * 1024,
    "verify-bundle.py": 4 * 1024 * 1024,
    "verify-bundle.py.asc": 1024 * 1024,
}
_MAX_INDEX_PATH_DEPTH = 64
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _trusted_gpgv():
    """Return an absolute, locally trusted gpgv executable path.

    The receiver is itself part of the trusted bootstrap, so resolving gpgv
    through PATH would unnecessarily add the caller's executable search path to
    the TCB.  Deployments may override ``FEATHERED_GPGV`` with another absolute
    path, but on POSIX the resolved executable and every parent directory must
    be root-owned and not group/world writable.
    """
    configured = os.environ.get('FEATHERED_GPGV', '/usr/bin/gpgv')
    path = Path(configured)
    if not path.is_absolute():
        raise RuntimeError('FEATHERED_GPGV must name an absolute gpgv path')
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise RuntimeError(f'Trusted gpgv executable is unavailable: {path}: {exc}') from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise RuntimeError(f'Trusted gpgv path is not an executable regular file: {resolved}')
    if os.name != 'nt' and hasattr(info, 'st_uid'):
        for candidate in (resolved, *resolved.parents):
            candidate_info = candidate.stat()
            if candidate_info.st_uid != 0 or candidate_info.st_mode & 0o022:
                raise RuntimeError(
                    f'Trusted gpgv path is not protected by root-owned, non-writable filesystem objects: {candidate}')
            if candidate == Path('/'):
                break
    return str(resolved)


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


def _copy_open_file(input_fd, target, *, max_bytes=None, expected_size=None, expected_sha256=None):
    opened = os.fstat(input_fd)
    if not stat.S_ISREG(opened.st_mode):
        raise RuntimeError(f'Bundle entry is not a regular file: {target.name}')
    if max_bytes is not None and opened.st_size > max_bytes:
        raise RuntimeError(
            f'Bundle bootstrap file exceeds the pre-authentication size limit: {target.name}')
    if expected_size is not None and opened.st_size != expected_size:
        raise RuntimeError(
            f'Bundle file size does not match the signed index: {target.name}')

    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest = hashlib.sha256()
    copied = 0
    try:
        with os.fdopen(input_fd, 'rb', closefd=False) as input_handle, target.open('xb') as output_handle:
            while True:
                block = input_handle.read(4 * 1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if max_bytes is not None and copied > max_bytes:
                    raise RuntimeError(
                        f'Bundle bootstrap file exceeds the pre-authentication size limit: {target.name}')
                if expected_size is not None and copied > expected_size:
                    raise RuntimeError(
                        f'Bundle file grew beyond the size recorded in the signed index: {target.name}')
                digest.update(block)
                output_handle.write(block)
        after = os.fstat(input_fd)
        if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino) or after.st_size != copied:
            raise RuntimeError(f'Bundle file changed while staging: {target.name}')
        if expected_size is not None and copied != expected_size:
            raise RuntimeError(
                f'Bundle file size does not match the signed index: {target.name}')
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise RuntimeError(
                f'Bundle file digest does not match the signed index: {target.name}')
        return copied, actual_sha256
    except Exception:
        target.unlink(missing_ok=True)
        raise


def _open_regular_at(directory_fd, name, *, before=None):
    file_flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    if before is None:
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(f'Cannot stat bundle file while staging: {name}: {exc}') from exc
    if not stat.S_ISREG(before.st_mode):
        kind = 'symbolic link' if stat.S_ISLNK(before.st_mode) else 'non-regular filesystem object'
        raise RuntimeError(f'Bundle contains a {kind} and cannot be staged safely: {name}')
    try:
        input_fd = os.open(name, file_flags, dir_fd=directory_fd)
    except OSError as exc:
        raise RuntimeError(f'Cannot open bundle file without following links: {name}: {exc}') from exc
    opened = os.fstat(input_fd)
    if (not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
        os.close(input_fd)
        raise RuntimeError(f'Bundle file changed while staging: {name}')
    return input_fd


def _use_windows_handle_staging():
    return os.name == 'nt'


def _windows_reparse_hint(path, display_name):
    try:
        info = os.lstat(path)
    except OSError:
        return
    attributes = getattr(info, 'st_file_attributes', 0)
    reparse_flag = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
    if stat.S_ISLNK(info.st_mode) or attributes & reparse_flag:
        raise RuntimeError(
            f'Bundle contains a symbolic link or reparse point and cannot be staged safely: {display_name}')


def _windows_open_checked_handle(path, *, directory, display_name):
    import ctypes
    from ctypes import wintypes

    _windows_reparse_hint(path, display_name)

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ('dwFileAttributes', wintypes.DWORD),
            ('ftCreationTime', wintypes.FILETIME),
            ('ftLastAccessTime', wintypes.FILETIME),
            ('ftLastWriteTime', wintypes.FILETIME),
            ('dwVolumeSerialNumber', wintypes.DWORD),
            ('nFileSizeHigh', wintypes.DWORD),
            ('nFileSizeLow', wintypes.DWORD),
            ('nNumberOfLinks', wintypes.DWORD),
            ('nFileIndexHigh', wintypes.DWORD),
            ('nFileIndexLow', wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_info = kernel32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    get_info.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    generic_read = 0x80000000
    file_read_attributes = 0x0080
    share_read = 0x00000001
    share_write = 0x00000002
    open_existing = 3
    backup_semantics = 0x02000000
    open_reparse_point = 0x00200000
    sequential_scan = 0x08000000
    attribute_directory = 0x00000010
    attribute_reparse = 0x00000400
    invalid_handle = ctypes.c_void_p(-1).value

    desired_access = file_read_attributes if directory else generic_read
    flags = open_reparse_point | (backup_semantics if directory else sequential_scan)
    handle = create_file(
        str(path), desired_access, share_read | share_write, None, open_existing, flags, None)
    if handle == invalid_handle:
        error = ctypes.WinError(ctypes.get_last_error())
        kind = 'directory' if directory else 'file'
        raise RuntimeError(
            f'Cannot open bundle {kind} without following links: {display_name}: {error}') from error

    info = FileInformation()
    if not get_info(handle, ctypes.byref(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        close_handle(handle)
        raise RuntimeError(f'Cannot inspect bundle filesystem object: {display_name}: {error}') from error
    if info.dwFileAttributes & attribute_reparse:
        close_handle(handle)
        raise RuntimeError(
            f'Bundle contains a symbolic link or reparse point and cannot be staged safely: {display_name}')
    is_directory = bool(info.dwFileAttributes & attribute_directory)
    if is_directory != directory:
        close_handle(handle)
        kind = 'directory' if directory else 'regular file'
        raise RuntimeError(f'Bundle entry is not a {kind}: {display_name}')
    return handle


def _windows_close_handle(handle):
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    close_handle(handle)


def _windows_open_regular_under(source, parts, display_name):
    import msvcrt

    directory_handles = []
    try:
        current = Path(source)
        directory_handles.append(
            _windows_open_checked_handle(current, directory=True, display_name=str(current)))
        for part in parts[:-1]:
            current = current / part
            directory_handles.append(
                _windows_open_checked_handle(current, directory=True, display_name=display_name))
        file_path = current / parts[-1]
        handle = _windows_open_checked_handle(
            file_path, directory=False, display_name=display_name)
        try:
            flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
            return msvcrt.open_osfhandle(int(handle), flags)
        except Exception:
            _windows_close_handle(handle)
            raise
    finally:
        for handle in reversed(directory_handles):
            _windows_close_handle(handle)


def _stage_bootstrap(source, destination):
    source = Path(source).absolute()
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    if _use_windows_handle_staging():
        for name, limit in _BOOTSTRAP_LIMITS.items():
            input_fd = _windows_open_regular_under(source, (name,), name)
            try:
                _copy_open_file(input_fd, destination / name, max_bytes=limit)
            finally:
                os.close(input_fd)
        return

    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        source_fd = os.open(source, directory_flags)
    except OSError as exc:
        raise RuntimeError(f'Cannot open bundle directory without following links: {source}: {exc}') from exc
    try:
        for name, limit in _BOOTSTRAP_LIMITS.items():
            input_fd = _open_regular_at(source_fd, name)
            try:
                _copy_open_file(input_fd, destination / name, max_bytes=limit)
            finally:
                os.close(input_fd)
    finally:
        os.close(source_fd)


def _authenticate_bootstrap(directory, keyring):
    directory = Path(directory)
    gpgv = _trusted_gpgv()
    for filename in ['bundle-index.json', 'verify-bundle.py']:
        subprocess.run([gpgv, '--keyring', str(keyring), str(directory / (filename + '.asc')),
                        str(directory / filename)], check=True, cwd=directory)


def _indexed_path(text):
    if not isinstance(text, str) or not text or '\\' in text:
        raise RuntimeError('Signed bundle index contains an unsafe file path')
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if (posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {'', '.', '..'} for part in posix.parts)
            or posix.as_posix() != text):
        raise RuntimeError(f'Signed bundle index contains an unsafe file path: {text}')
    if len(posix.parts) > _MAX_INDEX_PATH_DEPTH:
        raise RuntimeError(f'Signed bundle index path is nested too deeply: {text}')
    if text in {'bundle-index.json', 'bundle-index.json.asc'}:
        raise RuntimeError(f'Signed bundle index must not list its own bootstrap file: {text}')
    return posix.parts


def _load_authenticated_index(directory):
    path = Path(directory) / 'bundle-index.json'
    try:
        index = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f'Authenticated bundle index is unreadable: {exc}') from exc
    if not isinstance(index, dict) or index.get('format') != 'feathered-bundle-index/1':
        raise RuntimeError('Authenticated bundle index has an unsupported format')
    files = index.get('files')
    if not isinstance(files, list) or not files:
        raise RuntimeError('Authenticated bundle index contains no file list')
    file_count = index.get('file_count')
    total_bytes = index.get('total_bytes')
    if isinstance(file_count, bool) or not isinstance(file_count, int) or file_count != len(files):
        raise RuntimeError('Authenticated bundle index file count is inconsistent')
    if isinstance(total_bytes, bool) or not isinstance(total_bytes, int) or total_bytes < 0:
        raise RuntimeError('Authenticated bundle index total byte count is invalid')

    normalized = []
    seen = set()
    computed_total = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise RuntimeError('Authenticated bundle index contains a malformed file entry')
        relative = entry.get('path')
        parts = _indexed_path(relative)
        if relative in seen:
            raise RuntimeError(f'Authenticated bundle index contains a duplicate file entry: {relative}')
        seen.add(relative)
        digest = entry.get('sha256')
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise RuntimeError(f'Authenticated bundle index contains an invalid SHA-256: {relative}')
        raw_size = entry.get('size')
        if isinstance(raw_size, bool):
            raise RuntimeError(f'Authenticated bundle index contains an invalid size: {relative}')
        try:
            size = int(raw_size)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f'Authenticated bundle index contains an invalid size: {relative}') from exc
        if size < 0 or str(size) != str(raw_size):
            raise RuntimeError(f'Authenticated bundle index contains an invalid size: {relative}')
        computed_total += size
        if computed_total > total_bytes:
            raise RuntimeError('Authenticated bundle index total byte count is inconsistent')
        normalized.append((relative, parts, size, digest))
    if computed_total != total_bytes:
        raise RuntimeError('Authenticated bundle index total byte count is inconsistent')
    return normalized, total_bytes


def _digest_file(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b''):
            digest.update(block)
            size += len(block)
    return size, digest.hexdigest()


def _stage_indexed_files(source, destination, entries, total_bytes):
    source = Path(source).absolute()
    destination = Path(destination)
    copied_total = 0

    if _use_windows_handle_staging():
        for relative, parts, expected_size, expected_sha256 in entries:
            target = destination.joinpath(*parts)
            if target.exists():
                if relative not in {'verify-bundle.py', 'verify-bundle.py.asc'}:
                    raise RuntimeError(f'Authenticated bundle index collides with a bootstrap file: {relative}')
                size, digest = _digest_file(target)
                if size != expected_size or digest != expected_sha256:
                    raise RuntimeError(f'Authenticated bootstrap file does not match the signed index: {relative}')
                copied_total += size
                continue

            input_fd = _windows_open_regular_under(source, parts, relative)
            try:
                copied, _ = _copy_open_file(
                    input_fd, target, expected_size=expected_size,
                    expected_sha256=expected_sha256)
            finally:
                os.close(input_fd)
            copied_total += copied
            if copied_total > total_bytes:
                raise RuntimeError('Staged bundle exceeded the byte count in the authenticated index')
        if copied_total != total_bytes:
            raise RuntimeError('Staged bundle byte count does not match the authenticated index')
        return

    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        source_fd = os.open(source, directory_flags)
    except OSError as exc:
        raise RuntimeError(f'Cannot open bundle directory without following links: {source}: {exc}') from exc

    try:
        for relative, parts, expected_size, expected_sha256 in entries:
            target = destination.joinpath(*parts)
            if target.exists():
                if relative not in {'verify-bundle.py', 'verify-bundle.py.asc'}:
                    raise RuntimeError(f'Authenticated bundle index collides with a bootstrap file: {relative}')
                size, digest = _digest_file(target)
                if size != expected_size or digest != expected_sha256:
                    raise RuntimeError(f'Authenticated bootstrap file does not match the signed index: {relative}')
                copied_total += size
                continue

            current_fd = os.dup(source_fd)
            try:
                for part in parts[:-1]:
                    try:
                        child_fd = os.open(part, directory_flags, dir_fd=current_fd)
                    except OSError as exc:
                        raise RuntimeError(
                            f'Cannot traverse indexed bundle path without following links: {relative}: {exc}') from exc
                    os.close(current_fd)
                    current_fd = child_fd
                input_fd = _open_regular_at(current_fd, parts[-1])
                try:
                    copied, _ = _copy_open_file(
                        input_fd, target, expected_size=expected_size,
                        expected_sha256=expected_sha256)
                finally:
                    os.close(input_fd)
            finally:
                os.close(current_fd)
            copied_total += copied
            if copied_total > total_bytes:
                raise RuntimeError('Staged bundle exceeded the byte count in the authenticated index')
    finally:
        os.close(source_fd)
    if copied_total != total_bytes:
        raise RuntimeError('Staged bundle byte count does not match the authenticated index')


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
    _authenticate_bootstrap(directory, keyring)
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
    source_real = source.resolve(strict=True)
    if keyring == source_real or source_real in keyring.parents:
        raise RuntimeError('Operator keyring must be supplied outside the untrusted bundle')

    base = _secure_temp_base() if install else None
    staging_root = Path(tempfile.mkdtemp(prefix='feathered-receiver-', dir=base))
    staged_bundle = staging_root / 'bundle'
    locked = False
    try:
        _stage_bootstrap(source, staged_bundle)
        _authenticate_bootstrap(staged_bundle, keyring)
        entries, total_bytes = _load_authenticated_index(staged_bundle)
        _stage_indexed_files(source, staged_bundle, entries, total_bytes)
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
