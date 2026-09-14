"""Build-local reuse of payload digests, never a substitute for verification.

Only engine-owned staging files are eligible. Identity and nanosecond change
times guard ordinary writes/replacements; this is not protection against an
actor controlling the filesystem or its clock. Final bundle seals and external
cache validation deliberately retain independent reads.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys

_WINDOWS = os.name == 'nt'


@dataclass(frozen=True)
class Identity:
    device: int
    inode: int
    size: int
    modified: int
    changed: int


@dataclass(frozen=True)
class Entry:
    identity: Identity
    sha256: str


_entries: ContextVar[dict[Path, Entry] | None] = ContextVar('payload_digests', default=None)


@contextmanager
def digest_scope() -> Iterator[None]:
    """Each publication owns a ledger; nested builds reset to their parent."""
    token = _entries.set({})
    try:
        yield
    finally:
        _entries.reset(token)


def identity(path: Path) -> Identity | None:
    if _entries.get() is None:
        return None
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    changed = info.st_ctime_ns
    if _WINDOWS:
        # Python's Windows ctime is creation time, not POSIX change time.
        # Unsupported filesystems/API failures disable reuse, never validation.
        windows_changed = _windows_change_time(path, info)
        if windows_changed is None:
            return None
        changed = windows_changed
    return Identity(info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, changed)


def _windows_change_time(path: Path, expected: os.stat_result) -> int | None:
    """Read FILE_BASIC_INFO.ChangeTime from the same file represented by stat.

    API contract: learn.microsoft.com/en-us/windows/win32/api/winbase/
    nf-winbase-getfileinformationbyhandleex (FileBasicInfo = 0).
    """
    if sys.platform != 'win32':
        return None
    import ctypes
    import msvcrt

    class BasicInfo(ctypes.Structure):
        _fields_ = [('created', ctypes.c_int64), ('accessed', ctypes.c_int64),
                    ('written', ctypes.c_int64), ('changed', ctypes.c_int64),
                    ('attributes', ctypes.c_uint32)]

    try:
        query = ctypes.WinDLL('kernel32', use_last_error=True).GetFileInformationByHandleEx
        query.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        query.restype = ctypes.c_int
        with path.open('rb') as handle:
            actual = os.fstat(handle.fileno())
            if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                    expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns):
                return None
            info = BasicInfo()
            if not query(msvcrt.get_osfhandle(handle.fileno()), 0,
                         ctypes.byref(info), ctypes.sizeof(info)):
                return None
            return int(info.changed) if info.changed > 0 else None
    except (OSError, AttributeError):
        return None


def begin_verification(path: Path) -> Identity | None:
    entries = _entries.get()
    if entries is not None:
        entries.pop(path.absolute(), None)
    return identity(path)


def remember_verified(path: Path, before: Identity | None, computed: Mapping[str, str]) -> None:
    """Call only after all required verification has succeeded."""
    entries = _entries.get()
    digest = computed.get('sha256')
    if entries is not None and digest and before is not None and before == identity(path):
        entries[path.absolute()] = Entry(before, digest)


def payload_sha256(path: Path, read: Callable[[Path], str]) -> str:
    """Reuse stable bytes for output records, without creating trust claims."""
    entries = _entries.get()
    before = identity(path)
    if entries is not None:
        previous = entries.pop(path.absolute(), None)
        if previous is not None and before == previous.identity:
            entries[path.absolute()] = previous
            return previous.sha256
    digest = read(path)
    remember_verified(path, before, {'sha256': digest})
    return digest


def publish_payload(source: Path, destination: Path) -> None:
    """Rename an exclusively owned partial, carrying a still-current digest.

    Rename changes ctime. Check the complete identity immediately before it,
    then device/inode/size/mtime afterwards and record the new ctime. No transfer
    is attempted across copies, external cache files, or unrelated renames.
    """
    entries = _entries.get()
    entry = entries.pop(source.absolute(), None) if entries is not None else None
    before = identity(source)
    if entries is not None:
        entries.pop(destination.absolute(), None)
    source.replace(destination)
    after = identity(destination)
    if entries is not None and entry is not None and before is not None and before == entry.identity and after is not None:
        if (after.device, after.inode, after.size, after.modified) == (
                before.device, before.inode, before.size, before.modified):
            entries[destination.absolute()] = Entry(after, entry.sha256)
