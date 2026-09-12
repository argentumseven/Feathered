"""Destination payload names must not carry Windows path semantics.

posixpath.basename() splits only on '/', so a repository location using
backslashes or a drive letter survives it unchanged. On Windows,
Path('rpms') / r'\\Windows\\evil.rpm' is drive-absolute and 'C:x.rpm' is
drive-relative, either of which writes the payload outside the bundle.

repo_relative_url() refuses those locations before a fetch is attempted, so
this was not reachable. The point of the check here is that payload_filenames()
is what actually names the destination, and its safety should not depend on a
guard living in a different module.
"""
import pytest

import core


class _Pkg:
    def __init__(self, location):
        self.location = location
        self.nevra = "demo-0:1-1.x86_64"
        self.name = "demo"


@pytest.mark.parametrize("location", [
    r"C:\Windows\System32\evil.rpm",
    r"\\server\share\evil.rpm",
    r"..\..\evil.rpm",
])
def test_windows_path_semantics_are_refused(location):
    with pytest.raises(RuntimeError, match="path separator or drive marker"):
        core.payload_filenames([_Pkg(location)], ".rpm")


def test_bare_drive_relative_name_is_normalized_not_refused():
    """urlparse reads a leading 'C:' as a URL scheme, so the drive is already
    gone by the time the name is built. Recorded so the distinction from the
    backslash cases above is deliberate rather than accidental."""
    got = core.payload_filenames([_Pkg("C:evil.rpm")], ".rpm")
    assert list(got.values()) == ["evil.rpm"]


def test_ordinary_repository_location_still_works():
    got = core.payload_filenames([_Pkg("https://m/os/Packages/d/demo.rpm")], ".rpm")
    assert list(got.values()) == ["demo.rpm"]


def test_the_existing_windows_guards_are_unchanged():
    """Reserved device names and trailing dots stay refused."""
    with pytest.raises(RuntimeError, match="reserved device name"):
        core.payload_filenames([_Pkg("https://m/os/CON.rpm")], ".rpm")
