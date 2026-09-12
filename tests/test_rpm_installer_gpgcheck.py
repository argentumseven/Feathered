"""The RPM receiver workflow must enforce vendor signatures like the pacman one.

Reference: gpgcheck=0 was previously hardcoded, so a bundle whose packages had
all verified against a vendor key still installed with RPM signature checking
disabled. The asymmetry with the Arch branch was the bug.
"""
import types

import pytest

import installer
import provenance


class _Entry:
    def __init__(self, assurance, key_id="", signer="", repository="base"):
        self.assurance = assurance
        self.signing_key_id = key_id
        self.signer = signer
        self.repository = repository


def _vendor(key_id="0xFD431D51B4B5F9B4"):
    return _Entry(provenance.VERIFIED_VENDOR, key_id, "Rocky Enterprise Software Foundation")


def test_all_vendor_signed_enables_gpgcheck():
    assert installer._rpm_vendor_signed(None, [_vendor(), _vendor("ABCDEF0123456789")])


def test_one_unverified_package_disables_the_whole_transaction():
    assert not installer._rpm_vendor_signed(None, [_vendor(), _Entry(provenance.UNVERIFIED)])


def test_absent_provenance_is_not_read_as_signed():
    """None means the caller told us nothing, which is not evidence of signing."""
    assert not installer._rpm_vendor_signed(None, None)
    assert not installer._rpm_vendor_signed(None, [])


def test_archive_assurance_alone_does_not_satisfy_vendor_policy():
    """A signed Release chain vouches for the index, not for the artifact's signer."""
    assert not installer._rpm_vendor_signed(None, [_Entry(provenance.VERIFIED_ARCHIVE)])


@pytest.mark.parametrize("key_id,expected", [
    ("0xFD431D51B4B5F9B4", "b4b5f9b4"),
    ("FD431D51B4B5F9B4", "b4b5f9b4"),
    ("rsa4096 key FD431D51B4B5F9B4:", "b4b5f9b4"),
    ("short", None),
])
def test_key_ids_normalize_to_the_form_rpm_answers_to(key_id, expected):
    got = installer._rpm_short_key_ids([_Entry(provenance.VERIFIED_VENDOR, key_id)])
    assert got == ([expected] if expected else [])


def test_key_ids_are_deduplicated():
    entries = [_vendor(), _vendor(), _vendor("ABCDEF0123456789")]
    assert installer._rpm_short_key_ids(entries) == ["b4b5f9b4", "23456789"]
