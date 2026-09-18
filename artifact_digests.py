"""Build-local reuse of payload digests, never a substitute for verification.

Only engine-owned staging files are eligible. Identity and filesystem change
tokens guard ordinary writes/replacements; this is not protection against an
actor controlling the filesystem. Final bundle seals and external cache
validation deliberately retain independent reads.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
from pathlib import Path
from typing import BinaryIO
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
    """Return the file USN used as a Windows change token.

    FILE_BASIC_INFO timestamps can collide across rapid same-size rewrites.
    FSCTL_READ_FILE_USN_DATA instead returns the latest update sequence number
    recorded for the file. If the filesystem has no usable USN, a content token
    preserves correctness at the cost of losing the read-avoidance optimization.
    """
    if sys.platform != 'win32':
        return None
    import ctypes
    import msvcrt

    class ReadFileUsnData(ctypes.Structure):
        _fields_ = [('min_major_version', ctypes.c_uint16),
                    ('max_major_version', ctypes.c_uint16)]

    try:
        control = ctypes.WinDLL('kernel32', use_last_error=True).DeviceIoControl
        control.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
                            ctypes.c_void_p]
        control.restype = ctypes.c_int
        with path.open('rb') as handle:
            actual = os.fstat(handle.fileno())
            if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                    expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns):
                return None
            request = ReadFileUsnData(2, 2)
            output = ctypes.create_string_buffer(1024)
            returned = ctypes.c_uint32()
            # FSCTL_READ_FILE_USN_DATA from winioctl.h. Requesting v2 keeps the
            # returned USN at the fixed USN_RECORD_V2 offset parsed below.
            if control(msvcrt.get_osfhandle(handle.fileno()), 0x000900EB,
                       ctypes.byref(request), ctypes.sizeof(request), output,
                       ctypes.sizeof(output), ctypes.byref(returned), None):
                usn = _parse_windows_usn_record(output.raw[:returned.value])
                if usn is not None:
                    return usn
            handle.seek(0)
            return _windows_content_token(handle)
    except (OSError, AttributeError, ValueError):
        return None


def _windows_content_token(handle: BinaryIO) -> int:
    """Hash bytes only when a Windows filesystem exposes no usable USN."""
    import hashlib

    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return int.from_bytes(digest.digest(), 'big')


def _parse_windows_usn_record(data: bytes) -> int | None:
    """Extract the USN from a version-2 USN record."""
    if len(data) < 32:
        return None
    record_length = int.from_bytes(data[0:4], 'little')
    major_version = int.from_bytes(data[4:6], 'little')
    if major_version != 2 or record_length < 32 or record_length > len(data):
        return None
    usn = int.from_bytes(data[24:32], 'little', signed=True)
    return usn if usn >= 0 else None


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
