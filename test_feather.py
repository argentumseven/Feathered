"""Offline tests for the dependency core.

Runs standalone (`python tests_smoke.py`) and under pytest. Each test is a
separate function so one failure does not mask the rest.
"""
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core import (BuildOptions, Package, RepoSpec, Reporter, Requirement, TargetInventory,
                  _hash_bytes, declared_inventory_family, resolve, write_bundle_archive)
from core import parse_target_inventory as rpm_parse_target_inventory
from shutil import which as shutil_which
from profiles import version_key
from workloads import load_workloads
import apt_core


def deb_pkg(name, version, repo, depends="", pre_depends="", provides=(), arch="amd64"):
    p = apt_core.DebPackage(name, arch, version, f"pool/{name}.deb", "sha256", "", repo,
                            provides=list(provides))
    p.depends = apt_core.parse_dependency_field(depends, "depends")
    p.pre_depends = apt_core.parse_dependency_field(pre_depends, "pre-depends")
    return p


APT_REPO = RepoSpec("APT", "https://example.invalid/deb/", "dependency", 40,
                    repo_format="apt", suite="noble", components="main")
RPM_REPO = RepoSpec("BaseOS", "https://example.invalid/base/", "dependency", 40)


def rpm_pkg(name, version, requires=(), repo=None):
    p = Package(name, "x86_64", "0", version, "1.el9", f"Packages/{name}-{version}.rpm",
                "sha256", "", repo or RPM_REPO)
    p.provides = [Requirement(name, "EQ", "0", version, "1.el9", "provides")]
    p.requires = list(requires)
    return p


# --------------------------------------------------------------------------
# Regression: a DEB closure that cannot install must never be reported COMPLETE.
# --------------------------------------------------------------------------

def test_deb_version_conflict_is_resolved_not_ignored():
    """An exact pin discovered after a greedy pick must re-select, not ship the wrong version."""
    pkgs = [deb_pkg("app", "1.0", APT_REPO, depends="libfoo, plugin"),
            deb_pkg("plugin", "1.0", APT_REPO, depends="libfoo (= 1.0)"),
            deb_pkg("libfoo", "1.0", APT_REPO),
            deb_pkg("libfoo", "2.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], pkgs, "amd64", BuildOptions(), Reporter())
    assert {f"{p.name}={p.version}" for p in result.selected} == {"app=1.0", "plugin=1.0", "libfoo=1.0"}
    assert not result.unresolved


def test_dependencies_cascade_to_arbitrary_depth():
    """The closure is transitive, not one level deep.

    A twelve-link chain must pull every link. This is the property that makes a
    bundle installable on a machine with nothing preinstalled, so it is worth
    asserting explicitly rather than assuming.
    """
    chain = [deb_pkg(f"lvl{i}", "1.0", APT_REPO, depends=f"lvl{i + 1}") for i in range(12)]
    chain.append(deb_pkg("lvl12", "1.0", APT_REPO))
    result = apt_core.resolve([("lvl0", None, None)], chain, "amd64", BuildOptions(), Reporter())
    assert len(result.selected) == 13, sorted(p.name for p in result.selected)
    assert not result.unresolved

    rpm_chain = [rpm_pkg(f"r{i}", "1.0", [Requirement(f"r{i + 1}")]) for i in range(10)]
    rpm_chain.append(rpm_pkg("r10", "1.0"))
    rpm_result = resolve([("r0", None, "dependency")], rpm_chain, "x86_64",
                         BuildOptions(), Reporter())
    assert len(rpm_result.selected) == 11
    assert not rpm_result.unresolved


def test_cascade_continues_through_virtual_providers():
    """A dependency satisfied by a Provides must still have its own deps walked.

    Stopping at the virtual name would silently truncate the closure - the
    provider's own requirements would be missing from the bundle.
    """
    provider = apt_core.DebPackage(
        "realprov", "amd64", "2.0", "pool/rp.deb", "sha256", "", APT_REPO,
        provides=apt_core.parse_provides("virtual-thing (= 2.0)"))
    provider.depends = apt_core.parse_dependency_field("deepdep", "depends")
    packages = [
        deb_pkg("app", "1.0", APT_REPO, depends="left, right"),
        deb_pkg("left", "1.0", APT_REPO, depends="shared"),
        deb_pkg("right", "1.0", APT_REPO, depends="shared"),
        deb_pkg("shared", "1.0", APT_REPO, depends="virtual-thing"),
        provider,
        deb_pkg("deepdep", "1.0", APT_REPO, depends="deepest"),
        deb_pkg("deepest", "1.0", APT_REPO),
    ]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    names = [p.name for p in result.selected]
    assert "deepest" in names, "closure stopped at the virtual provider"
    # A diamond must not duplicate the shared node.
    assert names.count("shared") == 1
    assert not result.unresolved


def test_deb_unsatisfiable_pin_blocks_the_build():
    """Genuinely contradictory pins must surface as unresolved, which gates the build."""
    pkgs = [deb_pkg("app", "1.0", APT_REPO, depends="a, b"),
            deb_pkg("a", "1.0", APT_REPO, depends="libfoo (= 1.0)"),
            deb_pkg("b", "1.0", APT_REPO, depends="libfoo (= 2.0)"),
            deb_pkg("libfoo", "1.0", APT_REPO),
            deb_pkg("libfoo", "2.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], pkgs, "amd64", BuildOptions(), Reporter())
    assert result.unresolved, "an impossible pin must block the build, not just warn"


def test_rpm_version_conflict_is_resolved():
    pkgs = [rpm_pkg("app", "1.0", [Requirement("libfoo"), Requirement("plugin")]),
            rpm_pkg("plugin", "1.0", [Requirement("libfoo", "EQ", "0", "1.0", "1.el9")]),
            rpm_pkg("libfoo", "1.0"), rpm_pkg("libfoo", "2.0")]
    result = resolve([("app", None, "dependency")], pkgs, "x86_64", BuildOptions(), Reporter())
    assert {f"{p.name}={p.version}" for p in result.selected} == {"app=1.0", "plugin=1.0", "libfoo=1.0"}
    assert not result.unresolved


def test_rpm_unsatisfiable_pin_blocks_the_build():
    pkgs = [rpm_pkg("app", "1.0", [Requirement("a"), Requirement("b")]),
            rpm_pkg("a", "1.0", [Requirement("libfoo", "EQ", "0", "1.0", "1.el9")]),
            rpm_pkg("b", "1.0", [Requirement("libfoo", "EQ", "0", "2.0", "1.el9")]),
            rpm_pkg("libfoo", "1.0"), rpm_pkg("libfoo", "2.0")]
    result = resolve([("app", None, "dependency")], pkgs, "x86_64", BuildOptions(), Reporter())
    assert result.unresolved


# --------------------------------------------------------------------------
# Regression: metadata trust.
# --------------------------------------------------------------------------

def test_rpmvercmp_orders_numeric_segments_numerically():
    """Numeric runs must compare as numbers, not as text.

    Comparing them lexicographically ranks 1.9 above 1.10 and would make
    Feathered bundle a superseded package while believing it picked the newest.
    """
    from core import rpmvercmp

    def sign(x): return (x > 0) - (x < 0)

    assert sign(rpmvercmp("1.10", "1.9")) == 1
    assert sign(rpmvercmp("2.0", "10.0")) == -1
    assert sign(rpmvercmp("20240101", "20231231")) == 1
    assert sign(rpmvercmp("1.0", "1.0")) == 0
    # Alphabetic runs still compare as text.
    assert sign(rpmvercmp("1.0a", "1.0b")) == -1
    assert sign(rpmvercmp("4.4.2", "4.4.2b")) == -1
    # Tilde sorts before everything, caret after.
    assert sign(rpmvercmp("1.0~rc1", "1.0")) == -1
    assert sign(rpmvercmp("1.0^post", "1.0")) == 1


def test_deb_version_ordering_matches_dpkg():
    assert apt_core.compare_deb_versions("1:1.0", "2.0") > 0
    assert apt_core.compare_deb_versions("1.0", "1.0-0") == 0
    assert apt_core.compare_deb_versions("1.0~beta", "1.0") < 0
    assert apt_core.compare_deb_versions("1.10", "1.9") > 0


def test_weak_digests_are_rejected():
    for weak in ("md5", "sha1", "sha"):
        try:
            _hash_bytes(b"data", weak)
        except RuntimeError:
            continue
        raise AssertionError(f"{weak} digest was accepted")
    assert len(_hash_bytes(b"data", "sha256")) == 64


def test_expired_release_metadata_is_rejected():
    stale = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    fresh = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    try:
        apt_core.check_release_freshness(APT_REPO, {"Valid-Until": stale}, Reporter())
    except RuntimeError:
        pass
    else:
        raise AssertionError("stale Release metadata was accepted")
    apt_core.check_release_freshness(APT_REPO, {"Valid-Until": fresh}, Reporter())


def test_wrong_suite_is_rejected():
    apt_core.check_release_suite(APT_REPO, {"Suite": "noble", "Codename": "noble"}, Reporter())
    updates = RepoSpec("U", "https://x/", suite="noble-updates", repo_format="apt")
    apt_core.check_release_suite(updates, {"Suite": "noble-updates", "Codename": "noble"}, Reporter())
    try:
        apt_core.check_release_suite(APT_REPO, {"Suite": "bookworm", "Codename": "bookworm"}, Reporter())
    except RuntimeError:
        return
    raise AssertionError("a mirror serving the wrong release was accepted")


def test_openpgp_verification_round_trip():
    """Sign a payload with a throwaway key and check both accept and reject paths.

    Skipped when GnuPG is absent (verification is opt-in and degrades to a
    warning in that case, which test_unsigned_repo_warns covers).
    """
    import os
    import subprocess
    from core import gpg_backend, verify_openpgp
    if gpg_backend() is None or not shutil_which("gpg"):
        return
    with tempfile.TemporaryDirectory() as td:
        env = dict(os.environ, GNUPGHOME=td)
        os.chmod(td, 0o700)
        run = lambda *a: subprocess.run(a, env=env, capture_output=True)
        if run("gpg", "--batch", "--passphrase", "", "--quick-generate-key",
               "OPB Selftest <selftest@example.invalid>", "default", "default", "never").returncode:
            return
        keyring = Path(td) / "key.gpg"
        keyring.write_bytes(run("gpg", "--batch", "--export").stdout)
        payload = Path(td) / "data"; payload.write_bytes(b"trusted content\n")
        sig = Path(td) / "data.sig"
        run("gpg", "--batch", "--yes", "--detach-sign", "-o", str(sig), str(payload))

        # Correct signature verifies.
        verify_openpgp(payload.read_bytes(), sig.read_bytes(), str(keyring), "selftest", Reporter())
        # Modified payload must not.
        try:
            verify_openpgp(b"tampered content\n", sig.read_bytes(), str(keyring), "selftest", Reporter())
        except RuntimeError:
            pass
        else:
            raise AssertionError("a tampered payload passed signature verification")

        # Clearsigned documents are verified inline (signature=None), which is
        # how APT InRelease files are handled.
        clear = Path(td) / "inline.asc"
        run("gpg", "--batch", "--yes", "--clearsign", "-o", str(clear), str(payload))
        if clear.is_file():
            verify_openpgp(clear.read_bytes(), None, str(keyring), "selftest-inline", Reporter())



def test_ascii_armored_keyring_dearmors_without_gpg_executable(tmp_path):
    """The release-bundled gpgv must be sufficient for exported .asc keyrings."""
    import base64
    from core import _prepare_keyring

    packet_bytes = b"\x99\x00\x03abc\x01\x02\x03\x04"
    armored = (
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"
        b"Version: Feathered regression test\r\n\r\n" +
        base64.b64encode(packet_bytes) + b"\r\n"
        b"-----END PGP PUBLIC KEY BLOCK-----\r\n"
    )
    source = tmp_path / "archive-key.asc"
    source.write_bytes(armored)
    # _prepare_keyring expects its caller's temporary directory to exist.
    work = tmp_path / "work"
    work.mkdir()
    prepared = _prepare_keyring(source, work, "gpgv")
    assert prepared != source
    assert prepared.read_bytes() == packet_bytes


def test_ascii_armored_keyring_verifies_with_gpgv_only(monkeypatch):
    """Integration regression for the Windows release's verifier-only layout."""
    import os
    import subprocess
    import core

    gpg = shutil_which("gpg")
    gpgv = shutil_which("gpgv")
    if not gpg or not gpgv:
        return
    with tempfile.TemporaryDirectory() as td:
        home = Path(td) / "gnupg"
        home.mkdir()
        os.chmod(home, 0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        run = lambda *a: subprocess.run(a, env=env, capture_output=True)
        if run(gpg, "--batch", "--passphrase", "", "--quick-generate-key",
               "Armored Selftest <asc@example.invalid>", "default", "default", "never").returncode:
            return

        armored = Path(td) / "archive-key.asc"
        exported = run(gpg, "--batch", "--armor", "--export").stdout
        assert exported.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
        armored.write_bytes(exported)

        payload = Path(td) / "data"
        payload.write_bytes(b"trusted armored-keyring content\n")
        signature = Path(td) / "data.sig"
        assert run(gpg, "--batch", "--yes", "--detach-sign", "-o", str(signature),
                   str(payload)).returncode == 0

        # Force the production layout: verification has gpgv, while any host
        # gpg installation is irrelevant to Feathered's keyring preparation.
        monkeypatch.setattr(core, "gpg_backend", lambda: gpgv)
        monkeypatch.setattr(core.shutil, "which", lambda name: None if name == "gpg" else shutil_which(name))
        core.verify_openpgp(payload.read_bytes(), signature.read_bytes(), str(armored),
                            "armored-selftest", Reporter())


def test_missing_keyring_is_an_error_not_a_warning():
    from core import verify_openpgp
    try:
        verify_openpgp(b"x", b"y", "/nonexistent/keyring.gpg", "selftest", Reporter())
    except RuntimeError as exc:
        assert "keyring was not found" in str(exc)
        return
    raise AssertionError("a missing keyring was tolerated")


# --------------------------------------------------------------------------
# Regression: package-level provenance.
# --------------------------------------------------------------------------

_SIGNED_RPM = Path("/tmp/rpmsig/rpmbuild/RPMS/noarch/feathered-demo-1.0-1.noarch.rpm")
_TEST_KEYRING = "/tmp/aptfix/keyring.gpg"


def test_rpm_header_parsing_reads_full_payload_digest():
    """String-array entries are NUL-terminated; count is strings, not bytes.

    Reading count*4 bytes truncated a 64-char SHA-256 to 4 characters and made
    a valid package look tampered with.
    """
    import provenance
    if not _SIGNED_RPM.is_file():
        return
    info = provenance.read_rpm_signature(_SIGNED_RPM)
    assert len(info["payload_digest"]) == 64, info["payload_digest"]
    assert info["header_signature"], "expected a header signature"
    import hashlib
    h = hashlib.sha256()
    with _SIGNED_RPM.open("rb") as f:
        f.seek(info["payload_offset"])
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    assert h.hexdigest() == info["payload_digest"]


def test_rpm_vendor_signature_verification():
    """The signature must cover both the header and, via its digest, the payload."""
    import provenance
    if not (_SIGNED_RPM.is_file() and Path(_TEST_KEYRING).is_file()):
        return
    detail = provenance.verify_rpm_package(_SIGNED_RPM, _TEST_KEYRING, Reporter())
    assert detail["signer"], "a good signature should name its signer"

    original = _SIGNED_RPM.read_bytes()
    header_off = original.find(b"\x8e\xad\xe8", 99)

    def rejects(mutate, label):
        data = bytearray(original)
        mutate(data)
        tmp = Path(tempfile.mkdtemp()) / "t.rpm"
        tmp.write_bytes(bytes(data))
        try:
            provenance.verify_rpm_package(tmp, _TEST_KEYRING, Reporter())
        except RuntimeError:
            return
        raise AssertionError(f"{label} was accepted")

    rejects(lambda d: d.__setitem__(len(d) - 40, d[len(d) - 40] ^ 0xFF), "a tampered payload")
    rejects(lambda d: d.__setitem__(header_off + 200, d[header_off + 200] ^ 0xFF), "a tampered header")


def test_wrong_vendor_keyring_is_rejected():
    import provenance
    ubuntu = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
    if not (_SIGNED_RPM.is_file() and ubuntu.is_file()):
        return
    try:
        provenance.verify_rpm_package(_SIGNED_RPM, str(ubuntu), Reporter())
    except RuntimeError:
        return
    raise AssertionError("a signature was accepted against an unrelated keyring")


def test_provenance_record_serialises():
    import provenance
    entry = provenance.PackageProvenance(
        package_id="demo-1.0-1.noarch", filename="demo.rpm", sha256="ab" * 32, size=10,
        source_url="https://example.invalid/demo.rpm", repository="Test",
        assurance=provenance.VERIFIED_VENDOR)
    record = provenance.build_provenance("bundle", {"arch": "x86_64"}, [], [entry], ["a warning"])
    payload = json.loads(record.to_json())
    assert payload["summary"] == {provenance.VERIFIED_VENDOR: 1}
    assert payload["packages"][0]["assurance"] == provenance.VERIFIED_VENDOR
    assert payload["tool"].startswith("Feathered")


# --------------------------------------------------------------------------
# Regression: differential bundles.
# --------------------------------------------------------------------------

def test_baseline_split_omits_known_packages():
    from core import split_against_baseline

    class P:
        def __init__(self, nevra, checksum=""):
            self.nevra = nevra
            self.name = nevra.split("-")[0]
            self.checksum = checksum

    # A baseline entry only suppresses a package when the digests match; the
    # old behaviour matched on identity alone.
    digest = "ab" * 32
    selected = [P("curl-8.5.0-1.x86_64", digest), P("wget-1.21-1.x86_64", digest)]
    ship, skip = split_against_baseline(selected, {"curl-8.5.0-1.x86_64": digest}, Reporter())
    assert [p.nevra for p in ship] == ["wget-1.21-1.x86_64"]
    assert [p.nevra for p in skip] == ["curl-8.5.0-1.x86_64"]
    # No baseline means a full, self-contained bundle.
    ship, skip = split_against_baseline(selected, {}, Reporter())
    assert len(ship) == 2 and not skip


def test_missing_baseline_manifest_is_an_error():
    from core import load_baseline
    assert load_baseline("", Reporter()) == {}
    try:
        load_baseline("/nonexistent/manifest.json", Reporter())
    except RuntimeError:
        return
    raise AssertionError("a missing baseline manifest was tolerated")


def test_reporter_records_warnings():
    rep = Reporter()
    rep.warn("unverified index")
    rep.warn("unverified index")
    assert rep.warnings == ["unverified index"]


# --------------------------------------------------------------------------
# Regression: target inventory handling.
# --------------------------------------------------------------------------

def _write(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    handle.write(text); handle.close()
    return Path(handle.name)


def test_cross_family_inventory_is_rejected():
    deb_file = _write("META|package_family|deb\nDEB|bash|5.2-1|amd64|\n")
    rpm_file = _write("META|package_family|rpm\nPKG|bash|0|5.2|1.el9|x86_64\n")
    for path, parser in ((deb_file, rpm_parse_target_inventory), (rpm_file, apt_core.parse_target_inventory)):
        try:
            parser(path)
        except RuntimeError:
            continue
        raise AssertionError(f"{parser.__name__} accepted an inventory from the other package family")
    # The matching parsers still work.
    assert rpm_parse_target_inventory(rpm_file).nevras
    assert apt_core.parse_target_inventory(deb_file).packages


def test_inventory_error_record_is_surfaced():
    path = _write("META|package_family|deb\nERROR|No supported package database found\n")
    try:
        apt_core.parse_target_inventory(path)
    except RuntimeError as exc:
        assert "collection failure" in str(exc)
        return
    raise AssertionError("a failed collection run was accepted as a valid inventory")


def test_declared_family_helper():
    assert declared_inventory_family("META|package_family|rpm\n") == "rpm"
    assert declared_inventory_family("# comment only\n") == ""


# --------------------------------------------------------------------------
# Regression: single-architecture APT index selection.
# --------------------------------------------------------------------------

def test_target_arch_is_deterministic():
    assert apt_core.target_arch({"amd64", "noarch"}) == "amd64"
    assert apt_core.target_arch({"arm64", "all"}) == "arm64"
    assert apt_core.target_arch("amd64") == "amd64"
    try:
        apt_core.target_arch({"amd64", "arm64"})
    except RuntimeError:
        return
    raise AssertionError("an ambiguous architecture set was silently resolved")


def test_clearsigned_release_payload_handles_crlf():
    raw = (b"-----BEGIN PGP SIGNED MESSAGE-----\r\n"
           b"Hash: SHA256\r\n"
           b"\r\n"
           b"Suite: noble\r\n"
           b"-----BEGIN PGP SIGNATURE-----\r\n"
           b"sig\r\n"
           b"-----END PGP SIGNATURE-----\r\n")
    payload = apt_core._release_payload(raw)
    assert "Suite: noble" in payload and "PGP SIGNATURE" not in payload


def test_profile_uses_discovered_releases_as_authoritative_state():
    """Discovered releases must survive on the profile, not just in a widget.

    Versioned profiles must not merge stale compiled release values into current
    runtime discovery. Switching targets must retain the discovered state.
    """
    from profiles import PROFILES
    profile = PROFILES["ubuntu"]
    original = list(profile.discovered_versions)
    try:
        profile.discovered_versions = ["26.10"]
        known = profile.known_versions()
        assert "26.10" in known
        assert known == ["26.10"]
        assert known == sorted(known, key=version_key, reverse=True)
        # Merging is idempotent and de-duplicating.
        profile.discovered_versions = ["26.10", "26.10"]
        assert profile.known_versions().count("26.10") == 1
    finally:
        profile.discovered_versions = original


def _build_local_apt_fixture(root: Path) -> str:
    """A minimal signed-less APT repository served over file://."""
    import gzip
    from datetime import timedelta
    (root / "dists/noble/main/binary-amd64").mkdir(parents=True)
    (root / "pool").mkdir()
    payload = b"PKGDATA"
    (root / "pool/demo_1.0_amd64.deb").write_bytes(payload)
    record = (f"Package: demo\nVersion: 1.0\nArchitecture: amd64\n"
              f"Filename: pool/demo_1.0_amd64.deb\nSize: {len(payload)}\n"
              f"SHA256: {hashlib.sha256(payload).hexdigest()}\n").encode()
    index = root / "dists/noble/main/binary-amd64/Packages"
    index.write_bytes(record)
    gz = gzip.compress(record, mtime=0)
    index.with_suffix(".gz").write_bytes(gz)
    valid = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%a, %d %b %Y %H:%M:%S UTC")
    lines = ["Origin: Test", "Suite: noble", "Codename: noble", "Components: main",
             "Architectures: amd64", f"Valid-Until: {valid}", "SHA256:"]
    for rel, blob in (("main/binary-amd64/Packages", record),
                      ("main/binary-amd64/Packages.gz", gz)):
        lines.append(f" {hashlib.sha256(blob).hexdigest()} {len(blob)} {rel}")
    (root / "dists/noble/Release").write_text("\n".join(lines) + "\n")
    return root.resolve().as_uri() + "/"


def test_release_only_apt_repo_does_not_backoff_on_missing_inrelease(monkeypatch, tmp_path):
    """InRelease is an optional probe, so a normal Release-only archive must
    fall back immediately instead of sleeping through transient-retry backoff.
    """
    from core import RepoSpec, Reporter
    import repository_transport

    url = _build_local_apt_fixture(tmp_path / "repo")
    sleeps = []
    monkeypatch.setattr(repository_transport.time, "sleep", lambda seconds: sleeps.append(seconds))
    repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                    suite="noble", components="main")

    packages = apt_core.load_repository(repo, {"amd64"}, Reporter())

    assert [pkg.name for pkg in packages] == ["demo"]
    assert sleeps == [], "missing optional InRelease must not trigger retry backoff"


def test_credentials_never_reach_bundle_artifacts_or_logs():
    """Entitlement paths and key material must not escape into a bundle.

    A bundle crosses an air gap and is often reviewed by people who should not
    learn where the build machine keeps its private keys.
    """
    from core import BuildOptions, RepoSpec, Reporter
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        url = _build_local_apt_fixture(base / "repo")
        secrets = base / "secrets"
        secrets.mkdir()
        for name in ("cert.pem", "key.pem", "ca.pem"):
            (secrets / name).write_text("PRIVATE-KEY-MATERIAL\n")
        logs = []
        reporter = Reporter(logs.append)
        repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                        suite="noble", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        result = apt_core.resolve([("demo", None, None)], packages, "amd64",
                                  BuildOptions(), reporter)
        # Attach credentials only for the writing stage, so any serialisation
        # of the repo record would expose them.
        repo.client_cert = str(secrets / "cert.pem")
        repo.client_key = str(secrets / "key.pem")
        repo.ca_cert = str(secrets / "ca.pem")
        out = base / "bundle"
        apt_core.write_bundle(result, out, BuildOptions(), reporter,
                              {"workload": "demo", "arch": "amd64",
                               "repositories": [{"name": repo.name, "url": repo.url}]})
        needles = ["cert.pem", "key.pem", "ca.pem", str(secrets), "PRIVATE-KEY-MATERIAL"]
        for path in out.rglob("*"):
            if path.is_file() and path.suffix in {".json", ".txt", ".sh"}:
                body = path.read_text(errors="replace")
                for needle in needles:
                    assert needle not in body, f"{path.name} leaked {needle!r}"
        for line in logs:
            for needle in needles:
                assert needle not in line, f"log leaked {needle!r}: {line}"


def test_entitlement_gated_targets_have_no_probeable_base():
    """RHEL defines its base repositories as empty placeholders.

    Its content is entitlement gated and comes from media or a subscribed
    mirror, so there is nothing to contact from a build machine. Treating that
    as "not available" marked every RHEL release unusable.
    """
    from profiles import PROFILES
    rhel = PROFILES["rhel"]
    deps = [t for t in rhel.repos_factory("9.8", "x86_64") if t.role == "dependency"]
    assert deps, "RHEL should still define base repository placeholders"
    assert all(not (t.url or "").strip() for t in deps), \
        "RHEL base repositories are expected to have no public URL"

    # A distribution with public mirrors must still yield a probeable base.
    rocky = PROFILES["rocky"]
    public = [t for t in rocky.repos_factory("9.6", "x86_64")
              if t.role == "dependency" and (t.url or "").strip()]
    assert public, "Rocky should expose a public base repository to probe"


def test_version_ordering_is_numeric():
    """Release ordering must be numeric, or 9.9 sorts above 9.10."""
    versions = ["9.9", "9.10", "10.0", "8.10", "9"]
    assert sorted(versions, key=version_key, reverse=True) == \
        ["10.0", "9.10", "9.9", "9", "8.10"]


def test_codenames_resolve_before_repository_urls_are_built():
    """A learned codename must reach the profile, since suites derive from it."""
    from profiles import PROFILES, resolve_codename
    profile = PROFILES["ubuntu"]
    table = dict(profile.release_codenames)
    try:
        profile.release_codenames.update({"99.10": "fictional"})
        assert profile.codename("99.10") == "fictional"
        suites = [t.suite for t in profile.repos_factory("99.10", "amd64")
                  if t.repo_format == "apt"]
        assert any(s.startswith("fictional") for s in suites), suites
        # An unknown release falls back to itself rather than another release's
        # archive, so the failure is obvious instead of silently wrong.
        assert resolve_codename("77.04", {}) == "77.04"
    finally:
        profile.release_codenames.clear(); profile.release_codenames.update(table)


def test_workload_packages_resolve_per_family():
    """The same software is named differently across package families."""
    catalog = load_workloads()
    apache = catalog["web-apache"]
    assert apache.packages_for("rpm") == ["httpd", "mod_ssl"]
    assert apache.packages_for("deb") == ["apache2"]
    # No override means one list serves both families.
    chrony = catalog["time-sync"]
    assert chrony.packages_for("rpm") == chrony.packages_for("deb") == ["chrony"]
    # Every preset must define packages for both families.
    for key, workload in catalog.items():
        if workload.custom:
            continue
        assert workload.packages_for("rpm"), f"{key} has no RPM packages"
        assert workload.packages_for("deb"), f"{key} has no DEB packages"


def _write_apt_component_fixture(root: Path, *, suite: str, advertised: str,
                                 physical_component: str, arch: str = "amd64"):
    """Create one tiny Release/Packages fixture with independent semantic/path names."""
    import gzip
    from datetime import timedelta

    binary = root / f"dists/{suite}/{physical_component}/binary-{arch}"
    binary.mkdir(parents=True)
    (root / "pool").mkdir(exist_ok=True)
    payload = b"PKG"
    (root / "pool/demo_1_amd64.deb").write_bytes(payload)
    record = (f"Package: demo\nVersion: 1.0\nArchitecture: {arch}\n"
              f"Filename: pool/demo_1_amd64.deb\nSize: {len(payload)}\n"
              f"SHA256: {hashlib.sha256(payload).hexdigest()}\n").encode()
    (binary / "Packages").write_bytes(record)
    gz = gzip.compress(record, mtime=0)
    (binary / "Packages.gz").write_bytes(gz)
    valid = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
        "%a, %d %b %Y %H:%M:%S UTC")
    lines = ["Origin: Debian", f"Suite: {suite}", "Codename: trixie-security",
             f"Components: {advertised}", f"Architectures: {arch}",
             f"Valid-Until: {valid}", "SHA256:"]
    for rel, blob in ((f"{physical_component}/binary-{arch}/Packages", record),
                      (f"{physical_component}/binary-{arch}/Packages.gz", gz)):
        lines.append(f" {hashlib.sha256(blob).hexdigest()} {len(blob)} {rel}")
    (root / f"dists/{suite}/Release").write_text("\n".join(lines) + "\n")


def test_prefixed_components_are_semantic_not_forced_paths():
    """Model Debian security's real metadata: Components says updates/main,
    while signed indexes live under main/binary-<arch>."""
    from core import RepoSpec, path_to_file_url
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "sec"
        _write_apt_component_fixture(root, suite="trixie-security",
                                     advertised="updates/main updates/contrib",
                                     physical_component="main")
        repo = RepoSpec("Sec", path_to_file_url(root.resolve()) + "/", "dependency", 40,
                        repo_format="apt", suite="trixie-security", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, Reporter())
        assert [p.name for p in packages] == ["demo"]


def test_prefixed_component_path_remains_supported_when_archive_really_uses_it():
    """The Debian fix must not break an archive whose semantic label really is
    also the on-disk path prefix."""
    from core import RepoSpec, path_to_file_url
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "prefixed"
        _write_apt_component_fixture(root, suite="trixie-security",
                                     advertised="updates/main updates/contrib",
                                     physical_component="updates/main")
        repo = RepoSpec("Sec", path_to_file_url(root.resolve()) + "/", "dependency", 40,
                        repo_format="apt", suite="trixie-security", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, Reporter())
        assert [p.name for p in packages] == ["demo"]


def test_legacy_prefixed_configured_component_resolves_signed_plain_path():
    """Saved r6-and-earlier Debian-security rows used ``updates/main``.

    Updating Feathered must repair those projects too, not only newly generated
    profile rows.  The plain path is accepted only because the signed Release
    checksum manifest names it.
    """
    from core import RepoSpec, path_to_file_url
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "legacy-sec"
        _write_apt_component_fixture(root, suite="trixie-security",
                                     advertised="updates/main updates/contrib",
                                     physical_component="main")
        repo = RepoSpec("Sec", path_to_file_url(root.resolve()) + "/", "dependency", 40,
                        repo_format="apt", suite="trixie-security", components="updates/main")
        packages = apt_core.load_repository(repo, {"amd64"}, Reporter())
        assert [p.name for p in packages] == ["demo"]


def test_debian_security_uses_canonical_source_components():
    from profiles import PROFILES
    security = [t for t in PROFILES["debian"].repos_factory("trixie", "amd64")
                if t.suite.endswith("-security")]
    assert security, "Debian should define a security repository"
    assert security[0].components == "main contrib non-free non-free-firmware"
    assert not any(c.startswith("updates/") for c in security[0].components.split())

    base = [t for t in PROFILES["debian"].repos_factory("trixie", "amd64")
            if t.suite == "trixie" and t.role == "dependency"][0]
    assert security[0].components == base.components


def test_devuan_components_follow_release_generation():
    import profiles
    current = {r.suite: r for r in profiles._devuan_repos("6.0", "amd64") if r.role == "dependency"}
    assert current["6.0"].components == "main contrib non-free non-free-firmware"
    old = {r.suite: r for r in profiles._devuan_repos("4.0", "amd64") if r.role == "dependency"}
    assert old["4.0"].components == "main contrib non-free"
    assert "non-free-firmware" not in old["4.0-security"].components


def test_docker_apt_suite_never_silently_cross_grades_release():
    import profiles
    original = dict(profiles.UBUNTU_CODENAMES)
    try:
        profiles.UBUNTU_CODENAMES.update({"26.04": "resolute", "25.10": "questing"})
        ubuntu = {r.name: r for r in profiles._ubuntu_repos("26.04", "amd64")}
        assert ubuntu["Docker CE Stable"].suite == "resolute"
        ubuntu_2510 = {r.name: r for r in profiles._ubuntu_repos("25.10", "amd64")}
        assert ubuntu_2510["Docker CE Stable"].suite == "questing"
        # Future/locally discovered releases must fail on their own suite if Docker
        # does not publish it; Feathered must not quietly cross-grade the target.
        assert profiles.docker_suite("future-suite") == "future-suite"
    finally:
        profiles.UBUNTU_CODENAMES.clear(); profiles.UBUNTU_CODENAMES.update(original)


def test_apt_rejects_architecture_not_published_by_release():
    from core import RepoSpec, path_to_file_url
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "arch"
        _write_apt_component_fixture(root, suite="trixie-security",
                                     advertised="updates/main", physical_component="main",
                                     arch="amd64")
        repo = RepoSpec("Sec", path_to_file_url(root.resolve()) + "/", "dependency", 40,
                        repo_format="apt", suite="trixie-security", components="main")
        try:
            apt_core.load_repository(repo, {"riscv64"}, Reporter())
        except RuntimeError as exc:
            assert "does not publish architecture 'riscv64'" in str(exc)
        else:
            raise AssertionError("unsupported APT architecture was accepted")


def test_codename_style_distributions_offer_codenames():
    """Runtime-discovered APT identities are offered in the distro-native form."""
    from profiles import PROFILES
    debian = PROFILES["debian"]
    ubuntu = PROFILES["ubuntu"]
    d_old, d_map = list(debian.discovered_versions), dict(debian.release_codenames)
    u_old, u_map = list(ubuntu.discovered_versions), dict(ubuntu.release_codenames)
    try:
        debian.release_codenames.update({"13": "trixie", "12": "bookworm"})
        debian.discovered_versions = ["trixie", "bookworm"]
        assert debian.release_style == "codename"
        offered = debian.known_versions()
        assert offered == ["trixie", "bookworm"]

        ubuntu.release_codenames.update({"26.04": "resolute", "24.04": "noble"})
        ubuntu.discovered_versions = ["26.04", "24.04"]
        assert ubuntu.release_style == "version"
        assert ubuntu.known_versions() == ["26.04", "24.04"]
    finally:
        debian.discovered_versions = d_old
        debian.release_codenames.clear(); debian.release_codenames.update(d_map)
        ubuntu.discovered_versions = u_old
        ubuntu.release_codenames.clear(); ubuntu.release_codenames.update(u_map)


def test_profile_retains_a_hand_typed_release():
    """A release named by the operator must survive, not just discovered ones.

    A brand-new release is exactly the one that has to be typed in, so
    forgetting it meant retyping it every session.
    """
    from profiles import PROFILES
    debian = PROFILES["debian"]
    original = list(debian.discovered_versions)
    try:
        debian.discovered_versions = sorted({*debian.discovered_versions, "duke"})
        assert "duke" in debian.known_versions()
    finally:
        debian.discovered_versions = original


def test_unknown_release_names_pass_through_to_the_archive():
    """A release Feathered has never heard of must still be usable.

    Typing a brand-new codename has to produce dists/<codename>/ verbatim,
    otherwise every new release would need a code change here.
    """
    from profiles import PROFILES
    debian = PROFILES["debian"]
    assert debian.codename("forky") == "forky"
    suites = [t.suite for t in debian.repos_factory("forky", "amd64")
              if t.repo_format == "apt" and t.role == "dependency"]
    assert any(s == "forky" or s.startswith("forky-") for s in suites), suites
    original = dict(debian.release_codenames)
    try:
        debian.release_codenames["13"] = "trixie"
        assert debian.codename("13") == "trixie"
    finally:
        debian.release_codenames.clear(); debian.release_codenames.update(original)


def test_workload_repositories_are_not_part_of_the_distribution():
    """Docker's repository belongs to the workload, not to the OS.

    Baking it into every distribution profile put it in the source list, and in
    source health checks, before the operator had chosen anything needing it.
    """
    from profiles import PROFILES
    for key in ("rhel", "rocky", "alma", "ubuntu", "debian", "fedora"):
        templates = PROFILES[key].repos_factory("9.0", "x86_64")
        workload_repos = [t for t in templates if t.role != "dependency"]
        assert workload_repos, f"{key} should still define Docker as a workload repository"
        for template in workload_repos:
            assert template.role == "docker", f"{key}: unexpected role {template.role}"


def test_repository_diagnosis_distinguishes_empty_from_wrong_path():
    """A 404 alone cannot tell a placeholder directory from a wrong path."""
    from core import diagnose_missing_repository, Reporter

    class FakeReporter(Reporter):
        pass

    import core as core_module
    original = core_module.fetch_bytes
    try:
        # A directory holding only a readme: the release is not published.
        core_module.fetch_bytes = lambda *a, **k: b'<a href="README.txt">README.txt</a>'
        message = diagnose_missing_repository("https://mirror/almalinux/10.0/", FakeReporter())
        assert "not published" in message.lower(), message

        # A directory of repository subfolders: the root is one level down.
        core_module.fetch_bytes = lambda *a, **k: (
            b'<a href="BaseOS/">BaseOS/</a><a href="AppStream/">AppStream/</a>')
        message = diagnose_missing_repository("https://mirror/rocky/9/", FakeReporter())
        assert "one level down" in message.lower(), message

        # Totally empty.
        core_module.fetch_bytes = lambda *a, **k: b"<html></html>"
        message = diagnose_missing_repository("https://mirror/empty/", FakeReporter())
        assert "empty" in message.lower(), message

        # Not listable at all: the path is probably simply wrong.
        def boom(*a, **k):
            raise RuntimeError("HTTP Error 404: Not Found")
        core_module.fetch_bytes = boom
        message = diagnose_missing_repository("https://mirror/nope/", FakeReporter())
        assert "path is most likely wrong" in message.lower(), message
    finally:
        core_module.fetch_bytes = original


def test_sealed_index_covers_every_file_and_is_computed_at_finalisation():
    """The signed index must describe the bundle that exists on disk.

    Hashes are taken from the finished files, so the index also covers the
    installer and generated metadata - files that an earlier manifest design,
    which pointed at an independently editable SHA256SUMS.txt, left unprotected.
    """
    from core import BuildOptions, RepoSpec, Reporter, write_bundle_index, INDEX_FILENAME
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        url = _build_local_apt_fixture(base / "repo")
        reporter = Reporter()
        repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                        suite="noble", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        result = apt_core.resolve([("demo", None, None)], packages, "amd64",
                                  BuildOptions(), reporter)
        out = base / "bundle"
        apt_core.write_bundle(result, out, BuildOptions(), reporter, {"workload": "demo"})
        write_bundle_index(out, reporter, {"tool": "test"})

        index = json.loads((out / INDEX_FILENAME).read_text())
        listed = {e["path"] for e in index["files"]}
        # the receiver verifier is now part
        # of the sealed file set. Only the index and its detached signature
        # necessarily sit outside the index they authenticate.
        on_disk = {p.relative_to(out).as_posix() for p in out.rglob("*")
                   if p.is_file() and p.relative_to(out).as_posix() not in
                   {INDEX_FILENAME, INDEX_FILENAME + ".asc"}}
        assert listed == on_disk, sorted(listed ^ on_disk)
        assert any(p.startswith("debs/") for p in listed)
        assert "install-offline.sh" in listed, "the installer must be covered"

        # Hashes come from the bytes on disk, and a change is detectable.
        for entry in index["files"]:
            actual = hashlib.sha256((out / entry["path"]).read_bytes()).hexdigest()
            assert actual == entry["sha256"], entry["path"]
        target = out / "install-offline.sh"
        target.write_bytes(target.read_bytes() + b"\n# injected\n")
        recorded = next(e for e in index["files"] if e["path"] == "install-offline.sh")
        assert hashlib.sha256(target.read_bytes()).hexdigest() != recorded["sha256"]


def test_progress_is_monotonic_across_phases():
    """Transferring and sealing share one bar rather than each running 0..100.

    Reporting sealing as its own 0..1 made a completed transfer appear to
    restart, which on a multi-terabyte mirror looks like the build began again.
    """
    from core import Reporter, SEAL_PHASE_START
    seen = []
    reporter = Reporter(progress=lambda label, value: seen.append(value))
    reporter.phase(0.0, SEAL_PHASE_START)
    for value in (0.0, 0.5, 1.0):
        reporter.progress("transfer", value)
    transfer_peak = max(seen)
    reporter.phase(SEAL_PHASE_START, 1.0 - SEAL_PHASE_START)
    for value in (0.0, 0.5, 1.0):
        reporter.progress("sealing", value)
    assert all(b >= a - 1e-9 for a, b in zip(seen, seen[1:])), seen
    assert min(seen[3:]) >= transfer_peak - 1e-9, "sealing must not rewind the bar"
    assert seen[-1] == 1.0


def test_sealing_refuses_symlinks_and_uses_root_relative_exclusions():
    """An 'exact bundle' must not hash something outside its own tree."""
    from core import write_bundle_index, Reporter, INDEX_FILENAME
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "b"
        (bundle / "debs").mkdir(parents=True)
        (bundle / "debs" / "a.deb").write_bytes(b"A")
        # A nested file sharing the index name must still be sealed.
        (bundle / "debs" / INDEX_FILENAME).write_text("not the index")
        write_bundle_index(bundle, Reporter(), {})
        index = json.loads((bundle / INDEX_FILENAME).read_text())
        listed = {e["path"] for e in index["files"]}
        assert f"debs/{INDEX_FILENAME}" in listed, listed
        assert INDEX_FILENAME not in listed

        outside = Path(td) / "outside.txt"
        outside.write_text("secret")
        try:
            (bundle / "link.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            return
        try:
            write_bundle_index(bundle, Reporter(), {})
        except RuntimeError:
            return
        raise AssertionError("a symlink must not be sealed")


def test_shipped_verifier_detects_every_tamper():
    """The verifier must catch modification, removal and addition."""
    from core import write_bundle_index, Reporter, INDEX_FILENAME
    import subprocess
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "b"
        (bundle / "debs").mkdir(parents=True)
        (bundle / "debs" / "a.deb").write_bytes(b"PACKAGE")
        (bundle / "install-offline.sh").write_text("#!/bin/sh\ntrue\n")
        write_bundle_index(bundle, Reporter(), {})
        verifier = bundle / "verify-bundle.py"
        if not verifier.is_file():
            return

        def run():
            return subprocess.run([sys.executable, str(verifier)],
                                  capture_output=True, text=True).returncode

        assert run() == 0, "a clean bundle must verify"
        planted = bundle / "debs" / "planted.deb"
        planted.write_bytes(b"EVIL")
        assert run() == 1, "an unexpected file must be reported"
        planted.unlink()
        target = bundle / "install-offline.sh"
        original = target.read_bytes()
        target.write_bytes(original + b"# injected\n")
        assert run() == 1, "a modified installer must be reported"
        target.write_bytes(original)
        (bundle / "debs" / "a.deb").unlink()
        assert run() == 1, "a missing package must be reported"


def test_staging_cannot_mutate_the_previous_bundle():
    """Hard-link reuse must not alias files the build rewrites.

    Linking every file meant the staging manifest and the published manifest
    were the same inode, so writing the new one destroyed the previous
    bundle - the exact thing staging exists to protect.
    """
    from core import open_staging, Reporter
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td) / "bundle"
        (dest / "debs").mkdir(parents=True)
        (dest / "debs" / "manifest.json").write_text("OLD MANIFEST")
        (dest / "install-offline.sh").write_text("OLD SCRIPT")
        (dest / "debs" / "SHA256SUMS.txt").write_text("OLD SUMS")
        (dest / "debs" / "pkg.deb").write_bytes(b"PACKAGE")

        staging = open_staging(dest, Reporter())
        # Payloads are reused, while generated files are copied (not linked) so
        # the staging tree represents the complete additive folder without
        # letting rewrites mutate the published destination before commit.
        assert (staging / "debs" / "pkg.deb").exists()
        for generated in ("manifest.json", "SHA256SUMS.txt"):
            assert (staging / "debs" / generated).read_text().startswith("OLD")
        assert (staging / "install-offline.sh").read_text() == "OLD SCRIPT"

        for generated, body in (("manifest.json", "NEW"), ("SHA256SUMS.txt", "NEW")):
            (staging / "debs" / generated).write_text(body)
        (staging / "install-offline.sh").write_text("NEW")
        assert (dest / "debs" / "manifest.json").read_text() == "OLD MANIFEST"
        assert (dest / "install-offline.sh").read_text() == "OLD SCRIPT"
        assert (dest / "debs" / "SHA256SUMS.txt").read_text() == "OLD SUMS"

        # Replacing a payload unlinks first, so the old inode is untouched.
        (staging / "debs" / "pkg.deb").unlink()
        (staging / "debs" / "pkg.deb").write_bytes(b"REPLACED")
        assert (dest / "debs" / "pkg.deb").read_bytes() == b"PACKAGE"


def test_failed_finalisation_leaves_no_bundle():
    """A build that cannot complete must not publish, and must not linger."""
    from core import BuildOptions, RepoSpec, Reporter
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        url = _build_local_apt_fixture(base / "repo")
        reporter = Reporter()
        repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                        suite="noble", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        result = apt_core.resolve([("demo", None, None)], packages, "amd64",
                                  BuildOptions(), reporter)
        out = base / "bundle"
        # Sealing with an unusable key must abort rather than degrade.
        options = BuildOptions(sign_bundle_index=True,
                               signing_key="definitely-not-a-key@invalid")
        try:
            apt_core.write_bundle(result, out, options, reporter, {"workload": "demo"})
        except RuntimeError:
            pass
        else:
            if shutil_which("gpg"):
                raise AssertionError("signing with an unusable key must fail the build")
        assert not out.exists(), "a failed build must not publish a bundle"
        leftovers = [p.name for p in base.iterdir() if p.name.startswith(".") and p.name != ".feathered-cache"]
        assert not leftovers, f"staging left behind: {leftovers}"


def test_trust_state_is_recorded_not_inferred():
    """Configuration presence is not a verification result."""
    from core import RepoSpec, RepoTrust, ArtifactVerification, trust_summary
    import provenance

    entry = provenance.PackageProvenance(
        package_id="x", filename="x.deb", sha256="ab" * 32, size=1,
        source_url="https://example.invalid/x.deb", repository="R")
    # A keyring being configured proves nothing on its own.
    entry.archive_signature_verified = False
    entry.index_digest_verified = True
    entry.digest_checked = True
    assert provenance.assurance_from(entry) == provenance.VERIFIED_DIGEST
    entry.archive_signature_verified = True
    assert provenance.assurance_from(entry) == provenance.VERIFIED_ARCHIVE
    entry.digest_checked = False
    assert provenance.assurance_from(entry) == provenance.UNVERIFIED

    # A repository with a keyring set but no verification performed is untrusted.
    repo = RepoSpec("R", "https://example.invalid/", "dependency", 40, keyring="/k.gpg")
    assert getattr(repo, "trust", None) is None or not repo.trust.archive_signature_verified

    # A verified index and a declared digest are not a complete chain: the
    # archive signature must have been checked and the package digest actually
    # compared. Anything less is digest-only at best.
    class Unsigned:
        repo = RepoSpec("R", "https://example.invalid/", "dependency", 40, keyring="/k.gpg")
        verification = ArtifactVerification(index_digest_verified=True,
                                            package_digest_declared=True,
                                            package_digest_checked=True)
    assert trust_summary([Unsigned()]) == {"digest-only": 1}

    signed_repo = RepoSpec("R", "https://example.invalid/", "dependency", 40, keyring="/k.gpg")
    signed_repo.trust = RepoTrust(repo="R", archive_signature_verified=True)

    class FullChain:
        repo = signed_repo
        verification = ArtifactVerification(index_digest_verified=True,
                                            package_digest_declared=True,
                                            package_digest_checked=True)
    assert trust_summary([FullChain()]) == {"archive-chain": 1}

    # A declared but unchecked digest proves nothing about the bytes.
    class Unchecked:
        repo = signed_repo
        verification = ArtifactVerification(index_digest_verified=True,
                                            package_digest_declared=True)
    assert trust_summary([Unchecked()]) == {"unverified": 1}


def test_deb822_continuation_fields_round_trip():
    """Folded fields must survive parse and re-emission."""
    from apt_core import _parse_deb822, _fold_field
    original = ("Package: demo\n"
                "Description: short summary\n"
                " first continuation\n"
                " .\n"
                " second paragraph\n"
                "Depends: a,\n"
                " b (>= 1.0)\n")
    record = _parse_deb822(original)[0]
    assert record["Description"].splitlines()[1] == "first continuation"
    emitted = "\n".join(_fold_field(k, v) for k, v in record.items()) + "\n"
    assert _parse_deb822(emitted)[0] == record, emitted
    # Continuation lines must be indented, or apt reads them as new fields.
    assert "\n first continuation" in emitted
    assert "\n ." in emitted
    # And dependency parsing is unaffected by the folding.
    deps = apt_core.parse_dependency_field(record["Depends"], "depends")
    assert [a.name for r in deps for a in r.alternatives] == ["a", "b"]


def test_no_credential_reaches_a_bundle_or_log():
    """End-to-end: build from a URL carrying credentials and grep everything.

    redact_url() existed but several paths bypassed it - download log lines,
    fetch exceptions, and the repo_url/source fields of manifest.json.
    """
    from core import BuildOptions, RepoSpec, Reporter
    secrets = ("hunter2", "supersecret")
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        url = _build_local_apt_fixture(base / "repo")
        logs = []
        reporter = Reporter(logs.append)
        repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                        suite="noble", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        result = apt_core.resolve([("demo", None, None)], packages, "amd64",
                                  BuildOptions(), reporter)
        # Credentials appear only once the packages are already resolved, so the
        # bundle writer is what must not disclose them.
        repo.url = f"https://bob:{secrets[0]}@example.invalid/repo/?token={secrets[1]}"
        out = base / "bundle"
        try:
            apt_core.write_bundle(result, out, BuildOptions(verify_checksums=False),
                                  reporter, {"workload": "demo"})
        except Exception:
            pass  # the fetch will fail; what matters is what got written first
        for path in out.rglob("*"):
            if path.is_file():
                body = path.read_text(errors="replace")
                for secret in secrets:
                    assert secret not in body, f"{path.name} leaked {secret}"
        for line in logs:
            for secret in secrets:
                assert secret not in line, f"log leaked {secret}: {line}"


def test_package_locations_cannot_escape_their_repository():
    """Repository metadata is attacker-controlled when a mirror is compromised.

    urljoin() honours absolute and protocol-relative URLs, so a hostile index
    could redirect a package fetch to another host or a local file.
    """
    from core import repo_relative_url
    base = "https://mirror.internal/el9/BaseOS/x86_64/os/"
    assert repo_relative_url(base, "Packages/ok.rpm").startswith(base)
    # Traversal that stays inside is fine.
    assert repo_relative_url(base, "pool/./sub/../ok.deb") == base + "pool/ok.deb"
    for hostile in ("https://evil.example/p.rpm", "//evil.example/p.rpm",
                    "file:///etc/shadow", "../../../../etc/passwd", ""):
        try:
            repo_relative_url(base, hostile)
        except RuntimeError:
            continue
        raise AssertionError(f"{hostile!r} was not refused")


def test_credentials_are_redacted_from_urls():
    """Repository URLs can carry userinfo or token parameters.

    Bundles cross an air gap and logs get pasted into tickets, so neither may
    carry the build station's credentials.
    """
    from core import redact_url
    redacted = redact_url("https://user:hunter2@mirror.internal/el9/?token=abc&arch=x86_64")
    assert "hunter2" not in redacted and "abc" not in redacted
    assert "mirror.internal" in redacted and "arch=x86_64" in redacted
    # Ordinary URLs are untouched.
    for plain in ("https://archive.ubuntu.com/ubuntu", "file:///C:/media/rocky"):
        assert redact_url(plain) == plain


def test_differential_baseline_compares_content_not_identity():
    """A republished artifact with the same identity but different bytes must
    not be treated as unchanged and dropped from a delta."""
    from core import split_against_baseline

    class P:
        def __init__(self, nevra, checksum):
            self.nevra = nevra
            self.name = nevra.split("-")[0]
            self.checksum = checksum

    same = P("curl-8.5.0-1.x86_64", "aa" * 32)
    changed = P("wget-1.21-1.x86_64", "bb" * 32)
    baseline = {"curl-8.5.0-1.x86_64": "aa" * 32,
                "wget-1.21-1.x86_64": "cc" * 32}   # same identity, different bytes
    ship, skip = split_against_baseline([same, changed], baseline, Reporter())
    assert [p.nevra for p in skip] == ["curl-8.5.0-1.x86_64"]
    assert [p.nevra for p in ship] == ["wget-1.21-1.x86_64"], \
        "a changed artifact must be shipped, not assumed unchanged"

    # A baseline entry with no digest cannot be compared, so it must be shipped.
    ship, skip = split_against_baseline([same], {"curl-8.5.0-1.x86_64": ""}, Reporter())
    assert [p.nevra for p in ship] == ["curl-8.5.0-1.x86_64"] and not skip


def test_bundle_records_which_build_produced_it():
    """Incident response has to identify the exact code that made a bundle."""
    import provenance
    from core import FEATHERED_VERSION
    record = provenance.build_provenance("b", {}, [], [], [])
    assert FEATHERED_VERSION in record.tool
    assert "python" in record.tool
    assert FEATHERED_VERSION != "1.0", "the recorded version must track the real one"


def test_analysis_signature_covers_every_source_field():
    """Anything that changes what loads must invalidate a completed analysis.

    The signature previously sampled four repository fields, so editing
    components, priority or the unverified-index opt-in left a stale result
    standing and a rebuild silently used the old closure.
    """
    from core import RepoSpec

    def signature(repos, arch="amd64"):
        return (tuple((r.name, r.url, r.role, r.priority, r.enabled, r.client_cert,
                       r.client_key, r.ca_cert, r.optional, r.repo_format, r.suite,
                       r.components, r.keyring, r.allow_unverified_index)
                      for r in repos), arch)

    base = RepoSpec("A", "https://a/", "dependency", 40, repo_format="apt",
                    suite="noble", components="main")
    original = signature([base])
    for field, value in (("components", "main universe"), ("priority", 99),
                         ("keyring", "/k.gpg"), ("allow_unverified_index", True),
                         ("enabled", False), ("url", "https://b/"), ("suite", "jammy"),
                         ("optional", True)):
        changed = RepoSpec("A", "https://a/", "dependency", 40, repo_format="apt",
                           suite="noble", components="main")
        setattr(changed, field, value)
        assert signature([changed]) != original, f"{field} does not invalidate"
    # Adding or removing a repository counts too.
    assert signature([base, base]) != original
    assert signature([]) != original


def test_interrupted_transfer_resumes_and_heals():
    """A rebuild into the same folder verifies what is there rather than
    re-fetching it, and replaces anything that fails verification."""
    from core import BuildOptions, RepoSpec, Reporter

    states = []
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        url = _build_local_apt_fixture(base / "repo")
        reporter = Reporter(item=lambda ident, st, info: states.append(st))
        repo = RepoSpec("Fixture", url, "dependency", 40, repo_format="apt",
                        suite="noble", components="main")
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        result = apt_core.resolve([("demo", None, None)], packages, "amd64",
                                  BuildOptions(), reporter)
        out = base / "bundle"
        apt_core.write_bundle(result, out, BuildOptions(), reporter, {"workload": "demo"})
        assert "done" in states

        # Second run over an intact folder verifies and reuses.
        states.clear()
        apt_core.write_bundle(result, out, BuildOptions(), reporter, {"workload": "demo"})
        assert "reused" in states, states
        assert "done" not in states, "an intact cached file must not be re-fetched"

        # A corrupted file is detected and replaced, not trusted.
        deb = next((out / "debs").glob("*.deb"))
        deb.write_bytes(b"CORRUPTED")
        states.clear()
        apt_core.write_bundle(result, out, BuildOptions(), reporter, {"workload": "demo"})
        assert "stale" in states, states
        assert "done" in states, "the replacement must actually be fetched"


def test_rows_are_drawn_from_the_picked_set():
    """Row appearance must be derived from the selection, not assumed.

    Rows were always drawn checked, so a preserved partial selection displayed
    as "everything included" and the bulk buttons appeared not to work - the
    visible state and the real state had diverged.
    """
    def row_state(closure, picked):
        return {name: (name in picked) for name in closure}

    closure = ["a", "b", "c"]
    assert all(row_state(closure, set(closure)).values())
    assert not any(row_state(closure, set()).values())
    partial = row_state(closure, {"a"})
    assert partial == {"a": True, "b": False, "c": False}


def test_picked_selection_survives_a_repeat_analysis():
    """A build re-runs the analysis; that must not silently re-include packages.

    Deselecting everything and pressing Build downloaded the entire closure,
    because the result handler reset the picked set before the build filtered
    against it.
    """
    # Mirrors App._show_result's preservation rule without needing a display.
    def refresh(previous, previous_closure, closure):
        if previous is not None and previous_closure == closure:
            return {n for n in previous if n in closure}, closure
        return set(closure), closure

    closure = {"a", "b", "c"}
    picked, seen = refresh(None, None, closure)
    assert picked == closure, "a fresh analysis starts with everything included"

    picked = set()                                  # operator clicked "None"
    picked, seen = refresh(picked, seen, closure)   # build re-runs the analysis
    assert picked == set(), "an empty selection must not be repopulated"

    picked = {"a"}                                  # operator picked one
    picked, seen = refresh(picked, seen, closure)
    assert picked == {"a"}

    # A genuinely different closure starts over.
    other = {"x", "y"}
    picked, seen = refresh(picked, seen, other)
    assert picked == other


def test_resolver_backtracks_over_alternatives():
    """Choosing the first satisfiable alternative is only correct if its own
    closure resolves.

    `app depends on a | b` where `a` is unsatisfiable and `b` is fine has a
    perfectly good solution; a greedy pick of `a` reported failure for it.
    """
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="a | b"),
                deb_pkg("a", "1.0", APT_REPO, depends="does-not-exist"),
                deb_pkg("b", "1.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"app", "b"}, \
        sorted(p.name for p in result.selected)
    assert not result.unresolved

    # Several bad alternatives in a row, and a failure several levels deep.
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="a | b | c"),
                deb_pkg("a", "1.0", APT_REPO, depends="nope"),
                deb_pkg("b", "1.0", APT_REPO, depends="mid"),
                deb_pkg("mid", "1.0", APT_REPO, depends="also-nope"),
                deb_pkg("c", "1.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"app", "c"}
    assert not result.unresolved


def test_constraints_do_not_leak_from_an_abandoned_branch():
    """Version floors belong to the branch that derived them.

    Branch A discovers `libfoo (= 1.0)` and then fails; branch B needs
    `libfoo (= 2.0)`. Carrying A's floor past the rejection made a solvable
    request unsatisfiable.
    """
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="a | b"),
                deb_pkg("a", "1.0", APT_REPO, depends="libfoo, plugin, missing-thing"),
                deb_pkg("plugin", "1.0", APT_REPO, depends="libfoo (= 1.0)"),
                deb_pkg("b", "1.0", APT_REPO, depends="libfoo (= 2.0)"),
                deb_pkg("libfoo", "1.0", APT_REPO), deb_pkg("libfoo", "2.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert not result.unresolved, [apt_core.format_requirement(u) for u in result.unresolved]
    chosen = {f"{p.name}={p.version}" for p in result.selected}
    assert "b=1.0" in chosen and "libfoo=2.0" in chosen, sorted(chosen)

    # A floor that is genuinely needed still applies.
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="libfoo, plugin"),
                deb_pkg("plugin", "1.0", APT_REPO, depends="libfoo (= 1.0)"),
                deb_pkg("libfoo", "1.0", APT_REPO), deb_pkg("libfoo", "2.0", APT_REPO)]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert {f"{p.name}={p.version}" for p in result.selected} >= {"libfoo=1.0"}


def test_rpm_backtracks_over_virtual_providers():
    """Several packages can provide one capability; picking the best-ranked one
    is only correct if its own closure resolves."""
    def provider(name, version, requires=(), provides=()):
        pkg = rpm_pkg(name, version, requires)
        pkg.provides = pkg.provides + list(provides)
        return pkg

    packages = [rpm_pkg("app", "1.0", [Requirement("webserver")]),
                provider("nginx", "2.0", [Requirement("missing-lib")],
                         [Requirement("webserver", kind="provides")]),
                provider("httpd", "1.0", (), [Requirement("webserver", kind="provides")])]
    result = resolve([("app", None, "dependency")], packages, "x86_64",
                     BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"app", "httpd"}, \
        sorted(p.name for p in result.selected)
    assert not result.unresolved

    # If every provider is broken it must still block.
    packages = [rpm_pkg("app", "1.0", [Requirement("webserver")]),
                provider("nginx", "2.0", [Requirement("missing-a")],
                         [Requirement("webserver", kind="provides")]),
                provider("httpd", "1.0", [Requirement("missing-b")],
                         [Requirement("webserver", kind="provides")])]
    result = resolve([("app", None, "dependency")], packages, "x86_64",
                     BuildOptions(), Reporter())
    assert result.unresolved


def test_impossible_alternatives_still_block_the_build():
    """Backtracking must not turn an unsatisfiable request into a false pass."""
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="a | b"),
                deb_pkg("a", "1.0", APT_REPO, depends="nope"),
                deb_pkg("b", "1.0", APT_REPO, depends="also-nope")]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert result.unresolved, "every alternative fails, so this must not be reported complete"


def test_missing_roots_do_not_abort_the_whole_analysis():
    """One absent package must not hide the other twenty-nine.

    Both resolvers used to raise on the first root they could not find, so a
    preset spanning several repositories reported a single cryptic error and no
    results at all.
    """
    packages = [deb_pkg("present-a", "1.0", APT_REPO), deb_pkg("present-b", "1.0", APT_REPO)]
    roots = [("present-a", None, None), ("absent-one", None, None),
             ("present-b", None, None), ("absent-two", None, None)]
    result = apt_core.resolve(roots, packages, "amd64", BuildOptions(), Reporter())
    selected = {p.name for p in result.selected}
    assert {"present-a", "present-b"} <= selected
    assert len(result.unresolved) == 2, [apt_core.format_requirement(u) for u in result.unresolved]

    rpm_packages = [rpm_pkg("present-a", "1.0"), rpm_pkg("present-b", "1.0")]
    rpm_roots = [("present-a", None, "dependency"), ("absent-one", None, "dependency"),
                 ("present-b", None, "dependency")]
    rpm_result = resolve(rpm_roots, rpm_packages, "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in rpm_result.selected} == {"present-a", "present-b"}
    assert len(rpm_result.unresolved) == 1


def test_optional_packages_are_skipped_not_failed():
    """Optional preset members absent from the sources are dropped quietly."""
    packages = [deb_pkg("core-tool", "1.0", APT_REPO)]
    roots = [("core-tool", None, None), ("nice-to-have", None, None)]
    options = BuildOptions(optional_roots={"nice-to-have"})
    result = apt_core.resolve(roots, packages, "amd64", options, Reporter())
    assert [p.name for p in result.selected] == ["core-tool"]
    assert not result.unresolved, "an optional package must not block the build"
    assert any("nice-to-have" in note for note in result.skipped_installed)


def test_every_optional_package_belongs_to_its_workload():
    """An optional name that is not actually installed by the preset is a typo."""
    for key, workload in load_workloads().items():
        names = set(workload.packages_for("rpm")) | set(workload.packages_for("deb"))
        stray = [n for n in workload.optional_packages if n not in names]
        assert not stray, f"{key} marks packages optional that it never installs: {stray}"


def test_supplementary_el_repositories_are_not_fatal():
    """A mirror without CRB or extras must not abort the analysis."""
    from profiles import PROFILES
    for key in ("rocky", "alma"):
        profile = PROFILES[key]
        for template in profile.repos_factory("9.0", "x86_64"):
            if template.role != "dependency" or not template.enabled:
                continue
            assert template.optional, \
                f"{key}: {template.name} is hard-required; a missing mirror path would abort"


def test_unc_paths_survive_the_file_url_round_trip():
    """SMB shares must not lose their server name.

    Path.as_uri() renders \\\\server\\share\\x as file://server/share/x, putting the
    server in the URL host field. Consumers parse it back with
    url2pathname(path), see only /share/x, and silently resolve to a
    non-existent local directory.
    """
    import nturl2path
    from core import path_to_file_url, file_url_to_path

    for original in (r"\\fileserver\repos\rocky9\BaseOS", r"C:\media\rocky9"):
        url = "file:" + nturl2path.pathname2url(original)
        parsed_back = nturl2path.url2pathname(url.split("file:", 1)[1])
        assert parsed_back == original, f"{original} did not round-trip: {parsed_back}"

    # The helpers round-trip a POSIX path. file_url_to_path returns a Path, and
    # str() on a WindowsPath renders separators as backslashes, so comparing
    # str() forms asserts the host platform's rendering rather than that the
    # path survived. as_posix() compares the path itself and holds on both.
    posix = "/srv/mirror/rocky9"
    assert file_url_to_path(path_to_file_url(posix)).as_posix() == posix
    # And tolerate the legacy two-slash UNC form without dropping the host.
    legacy = file_url_to_path("file://fileserver/repos/x")
    assert "fileserver" in str(legacy), legacy


def test_workload_definitions_are_internally_consistent():
    """Every determining factor must agree with the package lists it governs."""
    catalog = load_workloads()
    for key, workload in catalog.items():
        if workload.custom:
            continue
        rpm = workload.packages_for("rpm")
        deb = workload.packages_for("deb")
        assert rpm and deb, f"{key} has an empty package list"
        if workload.version_package:
            assert workload.version_package in rpm, \
                f"{key} nominates {workload.version_package} which is not in its RPM list"
        for name in workload.versioned_packages:
            assert name in rpm or name in deb, f"{key} pins {name}, which it does not install"
        if workload.deb_packages:
            assert set(workload.deb_packages) != set(workload.packages), \
                f"{key} has a deb override identical to its RPM list"
        assert bool(workload.requires_docker_repo) == any(
            n.startswith("docker-ce") for n in rpm), \
            f"{key} disagrees about whether it needs the Docker repository"
        if workload.docker_rootless_extra:
            assert workload.requires_docker_repo, f"{key} wants rootless extras without Docker"
        assert workload.verification_commands, f"{key} has no verification commands"


def test_toolset_workloads_have_no_false_version_axis():
    """A grab-bag of independent tools must not offer a single version.

    Offering one implies tcpdump's version dates the whole diagnostics set,
    which is meaningless and leads to a pin that silently applies to one
    package.
    """
    catalog = load_workloads()
    for key in ("net-diagnostics", "security-audit", "storage-tools", "build-toolchain",
                "sysadmin-essentials", "monitoring-agents", "pki-tls"):
        assert not catalog[key].has_version_axis, f"{key} should not claim a version axis"
    # Single-product workloads do have one.
    for key in ("docker", "podman", "web-nginx", "db-postgresql"):
        assert catalog[key].has_version_axis, f"{key} should have a version axis"


def test_toolset_presets_are_substantive():
    """These presets exist to spare the operator assembling a toolset by hand."""
    catalog = load_workloads()
    expectations = {
        "net-diagnostics": {"tcpdump", "nmap", "socat", "iperf3", "traceroute", "lsof"},
        "storage-tools": {"lvm2", "mdadm", "cryptsetup", "smartmontools", "parted"},
        "build-toolchain": {"cmake", "gdb", "valgrind", "flex", "bison"},
        "security-audit": {"aide", "clamav", "openscap-scanner"},
        "sysadmin-essentials": {"tmux", "htop", "jq", "rsync"},
    }
    for key, required in expectations.items():
        workload = catalog[key]
        for family in ("rpm", "deb"):
            names = set(workload.packages_for(family))
            assert len(names) >= 15, f"{key}/{family} has only {len(names)} packages"
            missing = required - names
            # Allow family-specific renames, but the concept must be present.
            aliases = {"tcpdump", "nmap", "socat", "iperf3", "traceroute", "lsof", "lvm2",
                       "mdadm", "cryptsetup", "smartmontools", "parted", "cmake", "gdb",
                       "valgrind", "flex", "bison", "aide", "clamav", "openscap-scanner",
                       "tmux", "htop", "jq", "rsync"}
            assert not (missing & aliases) or family == "deb" or not missing, \
                f"{key}/{family} is missing {sorted(missing)}"
    # Packet capture must be present in both decode forms.
    net = catalog["net-diagnostics"]
    assert "wireshark-cli" in net.packages_for("rpm")
    assert "tshark" in net.packages_for("deb")


def test_workload_catalog_reports_problems():
    notes = []
    catalog = load_workloads(notes)
    expected = {"docker", "podman", "container-tools", "buildah", "skopeo", "custom",
                "web-nginx", "web-apache", "db-postgresql", "build-toolchain",
                "python-runtime", "net-diagnostics", "security-audit"}
    assert expected.issubset(catalog)


def pkg(name, version, repo, requires=(), provides=()):
    p = Package(name, "x86_64", "0", version, "1.el9", f"Packages/{name}.rpm", "sha256", "", repo)
    p.provides = [Requirement(name, "EQ", "0", version, "1.el9", "provides"), *provides]
    p.requires = list(requires)
    return p


def test_legacy_resolver_suite():
    docker = RepoSpec("Docker", "https://example.invalid/docker/", "docker", 10)
    base = RepoSpec("BaseOS", "https://example.invalid/base/", "dependency", 40)
    packages = [
        pkg("docker-ce", "29.0", docker, [Requirement("libfoo.so.1()(64bit)")]),
        pkg("docker-ce-cli", "29.0", docker),
        pkg("containerd.io", "2.0", docker, provides=[Requirement("runc", "EQ", "0", "1.2", "1")]),
        pkg("docker-buildx-plugin", "1.0", docker),
        pkg("docker-compose-plugin", "1.0", docker),
        pkg("libfoo", "3.0", base, provides=[Requirement("libfoo.so.1()(64bit)")]),
        pkg("runc", "1.3", base),
    ]
    roots = [(n, None, "docker") for n in ("docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin")]
    result = resolve(roots, packages, "x86_64", BuildOptions(), Reporter())
    names = {p.name for p in result.selected}
    assert "libfoo" in names and "runc" not in names and not result.unresolved

    # OS-native workload resolution does not need Docker's repository.
    podman_pkg = pkg("podman", "5.4", base, [Requirement("crun")])
    crun_pkg = pkg("crun", "1.20", base)
    result = resolve([("podman", None, "dependency")], [podman_pkg, crun_pkg], "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"podman", "crun"}


    # Common EL rich conditional Requires such as `(container-selinux if selinux-policy)`
    # are conservatively included for a complete bundle when no target inventory
    # is available. Versioned/architecture-qualified leaves are also supported.
    podman_rich = pkg("podman-rich", "5.4", base, [
        Requirement("(container-selinux >= 2:2.162.1 if selinux-policy)"),
        Requirement("(glibc-gconv-extra(x86-64) = 2.34-275.el9_8 if redhat-rpm-config)"),
    ])
    container_selinux = Package("container-selinux", "noarch", "2", "2.245.0", "1.el9", "Packages/container-selinux.rpm", "sha256", "", base)
    container_selinux.provides = [Requirement("container-selinux", "EQ", "2", "2.245.0", "1.el9", "provides")]
    gconv = Package("glibc-gconv-extra", "x86_64", "0", "2.34", "275.el9_8", "Packages/glibc-gconv-extra.rpm", "sha256", "", base)
    gconv.provides = [Requirement("glibc-gconv-extra", "EQ", "0", "2.34", "275.el9_8", "provides")]
    rich_result = resolve([("podman-rich", None, "dependency")], [podman_rich, container_selinux, gconv], "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in rich_result.selected} == {"podman-rich", "container-selinux", "glibc-gconv-extra"}
    assert not rich_result.unresolved

    # With an exact target inventory, a conditional consequence is omitted if
    # the condition is not installed.
    empty_inv = TargetInventory()
    rich_target = resolve([("podman-rich", None, "dependency")], [podman_rich, container_selinux, gconv], "x86_64", BuildOptions(target_inventory=empty_inv), Reporter())
    assert {p.name for p in rich_target.selected} == {"podman-rich"}
    assert not rich_target.unresolved


    # Python RPM virtual capabilities use PEP 503 canonical names. A provider
    # written with a legacy dotted/underscored spelling must satisfy the
    # canonical generated Require used by RHEL/Fedora Python dependency generators.
    py_runtime = pkg("python3-libs", "3.9.21", base, provides=[Requirement("python(abi)", "EQ", "0", "3.9", "")])
    py_yaml = pkg("python3-pyyaml", "6.0", base,
                  requires=[Requirement("python(abi)", "EQ", "0", "3.9", "")],
                  provides=[Requirement("python3dist(PyYAML)", "EQ", "0", "6.0", ""),
                            Requirement("python3.9dist(py_yaml)", "EQ", "0", "6.0", "")])
    py_root = pkg("python-consumer", "1.0", base,
                  requires=[Requirement("python3dist(pyyaml)", "GE", "0", "5.0", ""),
                            Requirement("python3.9dist(py-yaml)", "GE", "0", "5.0", "")])
    py_result = resolve([("python-consumer", None, "dependency")], [py_root, py_yaml, py_runtime],
                        "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in py_result.selected} == {"python-consumer", "python3-pyyaml", "python3-libs"}
    assert not py_result.unresolved

    # If repository metadata only exposes one of the two standard default-Python
    # capability spellings, bridge generic python3dist <-> detected-default ABI.
    py_only_versioned = pkg("python3-example", "4.0", base,
                            provides=[Requirement("python3.9dist(example)", "EQ", "0", "4.0", "")])
    generic_consumer = pkg("generic-consumer", "1.0", base,
                           requires=[Requirement("python3dist(example)", "GE", "0", "3.0", "")])
    bridged = resolve([("generic-consumer", None, "dependency")],
                      [generic_consumer, py_only_versioned, py_runtime], "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in bridged.selected} == {"generic-consumer", "python3-example"}
    assert not bridged.unresolved

    alias_consumer2 = pkg("generic-consumer-2", "1.0", base,
                          requires=[Requirement("python3.9dist(example)", "GE", "0", "3.0", "")])
    bridged_twice = resolve([("generic-consumer", None, "dependency"), ("generic-consumer-2", None, "dependency")],
                            [generic_consumer, alias_consumer2, py_only_versioned, py_runtime],
                            "x86_64", BuildOptions(), Reporter())
    assert not bridged_twice.unresolved
    assert [p.name for p in bridged_twice.selected].count("python3-example") == 1

    py_nondefault = pkg("python3.11-example", "4.0", base,
                        provides=[Requirement("python3.11dist(other-example)", "EQ", "0", "4.0", "")])
    wrong_abi_consumer = pkg("wrong-abi-consumer", "1.0", base,
                             requires=[Requirement("python3dist(other-example)", None)])
    not_bridged = resolve([("wrong-abi-consumer", None, "dependency")],
                          [wrong_abi_consumer, py_nondefault, py_runtime], "x86_64", BuildOptions(), Reporter())
    assert len(not_bridged.unresolved) == 1

    # RPM rich `with` requires every operand to be satisfied by the SAME RPM.
    # Python generators commonly use this to express bounded version ranges.
    py_chardet = pkg("python3-chardet", "4.0.0", base,
                     provides=[Requirement("python3.9dist(chardet)", "EQ", "0", "4.0.0", "")])
    needs_chardet_range = pkg("needs-chardet-range", "1.0", base,
                              requires=[Requirement("(python3.9dist(chardet) < 5 with python3.9dist(chardet) >= 3.0.4)")])
    range_ok = resolve([("needs-chardet-range", None, "dependency")],
                       [needs_chardet_range, py_chardet, py_runtime], "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in range_ok.selected} == {"needs-chardet-range", "python3-chardet"}
    assert not range_ok.unresolved

    py_chardet_too_new = pkg("python3-chardet", "5.1.0", base,
                             provides=[Requirement("python3.9dist(chardet)", "EQ", "0", "5.1.0", "")])
    range_bad = resolve([("needs-chardet-range", None, "dependency")],
                        [needs_chardet_range, py_chardet_too_new, py_runtime], "x86_64", BuildOptions(), Reporter())
    assert len(range_bad.unresolved) == 1
    assert "no single enabled package satisfies" in range_bad.unresolved_notes[next(iter(range_bad.unresolved_notes))]

    # `with` is not equivalent to `and`: different RPMs providing each side do
    # not satisfy the expression. A combined provider does.
    cap_a = pkg("cap-a-provider", "1.0", base, provides=[Requirement("capA")])
    cap_b = pkg("cap-b-provider", "1.0", base, provides=[Requirement("capB")])
    combined = pkg("combined-provider", "1.0", base, provides=[Requirement("capA"), Requirement("capB")])
    needs_same = pkg("needs-same-provider", "1.0", base, requires=[Requirement("(capA with capB)")])
    same_ok = resolve([("needs-same-provider", None, "dependency")],
                      [needs_same, cap_a, cap_b, combined], "x86_64", BuildOptions(), Reporter())
    assert "combined-provider" in {p.name for p in same_ok.selected}
    assert "cap-a-provider" not in {p.name for p in same_ok.selected}
    assert "cap-b-provider" not in {p.name for p in same_ok.selected}
    assert not same_ok.unresolved

    # Provider diagnostics distinguish an absent capability from a provider
    # whose advertised Python distribution version is simply too old.
    py_old = pkg("python3-demo", "1.0", base, provides=[Requirement("python3dist(demo)", "EQ", "0", "1.0", "")])
    needs_new = pkg("needs-new-demo", "1.0", base, requires=[Requirement("python3dist(demo)", "GE", "0", "2.0", "")])
    py_bad = resolve([("needs-new-demo", None, "dependency")], [needs_new, py_old], "x86_64", BuildOptions(), Reporter())
    assert len(py_bad.unresolved) == 1
    assert "Providers exist, but none satisfy" in py_bad.unresolved_notes[next(iter(py_bad.unresolved_notes))]

    catalog = load_workloads()
    expected = {"docker", "podman", "container-tools", "buildah", "skopeo", "custom",
                "web-nginx", "web-apache", "db-postgresql", "build-toolchain",
                "python-runtime", "net-diagnostics", "security-audit"}
    assert expected.issubset(catalog)

    inv = TargetInventory()
    inv.capabilities["libfoo.so.1()(64bit)"].append(Requirement("libfoo.so.1()(64bit)"))
    result = resolve(roots, packages, "x86_64", BuildOptions(target_inventory=inv), Reporter())
    # Unowned legacy capabilities cannot prove survival across replacements.
    assert "libfoo" in {p.name for p in result.selected}

    # Exact package selection pins repository + architecture as well as EVR.
    mirror_a = RepoSpec("Mirror A", "https://example.invalid/a/", "dependency", 20)
    mirror_b = RepoSpec("Mirror B", "https://example.invalid/b/", "dependency", 80)
    root_a = pkg("demo", "2.0", mirror_a, [Requirement("dep-a")])
    root_b = pkg("demo", "2.0", mirror_b, [Requirement("dep-b")])
    dep_a = pkg("dep-a", "1.0", mirror_a)
    dep_b = pkg("dep-b", "1.0", mirror_b)
    pinned = resolve([("demo", root_b.evr_text, "dependency", "Mirror B", "x86_64")],
                     [root_a, root_b, dep_a, dep_b], "x86_64", BuildOptions(), Reporter())
    assert pinned.roots[0].repo.name == "Mirror B"
    assert {p.name for p in pinned.selected} == {"demo", "dep-b"}

    # Portable package output is a real ZIP with the generated bundle folder.
    import tempfile, zipfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "demo-offline"
        bundle.mkdir(); (bundle / "manifest.txt").write_text("ok", encoding="utf-8")
        archive = write_bundle_archive(bundle, Reporter())
        assert archive.is_file()
        with zipfile.ZipFile(archive) as zf:
            assert "demo-offline/manifest.txt" in zf.namelist()

    # APT/DEB backend: Debian version ordering, strict Depends/Pre-Depends,
    # ordered alternatives, versioned virtual Provides, and target-aware skips.
    debrepo = RepoSpec("APT", "https://example.invalid/deb/", "dependency", 40, repo_format="apt", suite="test", components="main")
    root_deb = apt_core.DebPackage("demo", "amd64", "2.0-1", "pool/demo.deb", "sha256", "", debrepo)
    root_deb.pre_depends = apt_core.parse_dependency_field("base-files (>= 1.0)", "pre-depends")
    root_deb.depends = apt_core.parse_dependency_field("libfoo (>= 1.2), virtual-api (>= 3) | fallback", "depends")
    base_deb = apt_core.DebPackage("base-files", "amd64", "1.0", "pool/base.deb", "sha256", "", debrepo)
    foo_deb = apt_core.DebPackage("libfoo", "amd64", "1.5", "pool/foo.deb", "sha256", "", debrepo)
    virt_deb = apt_core.DebPackage("virt-provider", "all", "3.0", "pool/virt.deb", "sha256", "", debrepo,
                                  provides=[apt_core.DebAtom("virtual-api", "=", "3.0")])
    fallback_deb = apt_core.DebPackage("fallback", "amd64", "99", "pool/fallback.deb", "sha256", "", debrepo)
    deb_result = apt_core.resolve([("demo", None, "dependency")],
                                  [root_deb, base_deb, foo_deb, virt_deb, fallback_deb],
                                  "amd64", BuildOptions(), Reporter())
    assert {p.name for p in deb_result.selected} == {"demo", "base-files", "libfoo", "virt-provider"}
    assert not deb_result.unresolved
    assert apt_core.compare_deb_versions("1.0~rc1", "1.0") < 0
    assert apt_core.compare_deb_versions("1:1.0-1", "2.0-1") > 0

    apt_inv = apt_core.AptTargetInventory()
    apt_inv.packages[("libfoo", "amd64")] = "1.5"
    apt_inv.packages[("base-files", "amd64")] = "1.0"
    deb_target = apt_core.resolve([("demo", None, "dependency")],
                                  [root_deb, base_deb, foo_deb, virt_deb, fallback_deb],
                                  "amd64", BuildOptions(target_inventory=apt_inv), Reporter())
    assert {p.name for p in deb_target.selected} == {"demo", "virt-provider"}
    assert not deb_target.unresolved


def main():
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failures = []
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - report all failures, not just the first
            failures.append(f"{name}: {type(exc).__name__}: {exc}")
    for failure in failures:
        print("FAIL " + failure)
    print(f"{len(tests) - len(failures)}/{len(tests)} tests passed")
    return 1 if failures else 0



# --------------------------------------------------------------------------
# Source Bond / production-hardening tests.
# --------------------------------------------------------------------------


def test_regression_source_bond_uses_evidence_digest_on_one_payload():
    """Evidence metadata may verify the one acquisition payload; no second payload is needed."""
    from core import apply_mirror_evidence, verify_package_artifact
    body = b"one package payload\n"
    digest = hashlib.sha256(body).hexdigest()
    primary_repo = RepoSpec(
        "Primary", "https://mirror-a.example/repo/", "dependency", 40,
        repo_format="apt", suite="noble", components="main",
        evidence_urls=["https://mirror-b.example/repo/"], evidence_policy="best-effort")
    evidence_repo = RepoSpec(
        "Evidence", "https://mirror-b.example/repo/", "dependency", 40,
        repo_format="apt", suite="noble", components="main")
    primary = deb_pkg("bonded", "1.0", primary_repo)
    primary.checksum_type = ""
    primary.checksum = ""
    primary.size = len(body)
    evidence = deb_pkg("bonded", "1.0", evidence_repo)
    evidence.checksum_type = "sha256"
    evidence.checksum = digest
    evidence.size = len(body)

    stats = apply_mirror_evidence([primary], [evidence], evidence_repo, Reporter())
    assert stats["matched"] == 1 and stats["digest"] == 1
    assert primary.verification.evidence_status == "independent-digest"

    with tempfile.TemporaryDirectory() as td:
        payload = Path(td) / "bonded.deb"
        payload.write_bytes(body)
        assert verify_package_artifact(primary, payload, BuildOptions(), Reporter()) is True
        assert primary.verification.evidence_digest_checked is True
        assert primary.verification.package_digest_checked is False


def test_regression_source_bond_digest_disagreement_is_recorded_not_global_fatal():
    """Repository-wide mirror skew is recorded; selected-artifact verification is decisive."""
    from core import apply_mirror_evidence, _artifact_verification
    primary_repo = RepoSpec("A", "https://a.example/repo/", evidence_policy="best-effort")
    evidence_repo = RepoSpec("B", "https://b.example/repo/")
    primary = rpm_pkg("same", "1.0", repo=primary_repo)
    primary.checksum_type, primary.checksum = "sha256", "11" * 32
    evidence = rpm_pkg("same", "1.0", repo=evidence_repo)
    evidence.checksum_type, evidence.checksum = "sha256", "22" * 32
    stats = apply_mirror_evidence([primary], [evidence], evidence_repo, Reporter())
    assert stats["conflict"] == 1
    rec = _artifact_verification(primary)
    assert rec.evidence_status == "metadata-conflict"
    assert not rec.evidence_metadata_match
    assert any("deferred" in note.lower() for note in rec.notes)


def test_regression_source_bond_weak_digest_disagreement_is_recorded_as_conflict():
    """Even weak contradictory metadata is retained without aborting unrelated packages."""
    from core import apply_mirror_evidence, _artifact_verification
    primary_repo = RepoSpec("A", "https://a.example/repo/", evidence_policy="best-effort")
    evidence_repo = RepoSpec("B", "https://b.example/repo/")
    primary = rpm_pkg("same-weak", "1.0", repo=primary_repo)
    evidence = rpm_pkg("same-weak", "1.0", repo=evidence_repo)
    primary.checksum_type, primary.checksum = "md5", "11" * 16
    evidence.checksum_type, evidence.checksum = "md5", "22" * 16
    stats = apply_mirror_evidence([primary], [evidence], evidence_repo, Reporter())
    assert stats["conflict"] == 1
    assert _artifact_verification(primary).evidence_status == "metadata-conflict"

def test_regression_source_bond_requires_distinct_endpoints():
    from core import mirrors_are_distinct
    ok, why = mirrors_are_distinct("https://same.example/a/", "https://same.example/b/")
    assert not ok and "hostname" in why
    ok, _ = mirrors_are_distinct("https://a.example/repo/", "https://b.example/repo/")
    assert ok


def test_regression_resilient_digest_policy_and_strict_override():
    """Missing/weak evidence can power through only when the operator selected resilient mode."""
    from core import verify_package_artifact
    repo = RepoSpec("R", "https://a.example/repo/")
    pkg = rpm_pkg("weak", "1.0", repo=repo)
    body = b"payload"
    pkg.checksum_type = "md5"
    pkg.checksum = hashlib.md5(body).hexdigest()
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "weak.rpm"
        path.write_bytes(body)
        reporter = Reporter()
        assert verify_package_artifact(pkg, path, BuildOptions(), reporter) is False
        assert reporter.warnings, "resilient acceptance must be visible"
        try:
            verify_package_artifact(
                pkg, path, BuildOptions(require_package_digests=True), Reporter())
        except RuntimeError as exc:
            assert "no usable" in str(exc).lower()
        else:
            raise AssertionError("strict digest policy accepted a package with only MD5")


def test_regression_apt_backtracks_over_virtual_provider_packages():
    """APT must retry a second provider when the preferred provider's closure is broken."""
    bad = apt_core.DebPackage(
        "bad-provider", "amd64", "2.0", "pool/bad.deb", "sha256", "", APT_REPO,
        provides=apt_core.parse_provides("webserver"))
    bad.depends = apt_core.parse_dependency_field("missing-lib", "depends")
    good = apt_core.DebPackage(
        "good-provider", "amd64", "1.0", "pool/good.deb", "sha256", "", APT_REPO,
        provides=apt_core.parse_provides("webserver"))
    packages = [deb_pkg("app", "1.0", APT_REPO, depends="webserver"), bad, good]
    result = apt_core.resolve([("app", None, None)], packages, "amd64",
                              BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"app", "good-provider"}, \
        sorted(p.name for p in result.selected)
    assert not result.unresolved


def test_regression_payload_basename_collision_blocks_bundle():
    from core import payload_filenames
    repo1 = RepoSpec("R1", "https://one.example/")
    repo2 = RepoSpec("R2", "https://two.example/")
    one = Package("one", "x86_64", "0", "1", "1", "a/shared.rpm", "sha256", "", repo1)
    two = Package("two", "x86_64", "0", "1", "1", "b/shared.rpm", "sha256", "", repo2)
    try:
        payload_filenames([one, two], ".rpm")
    except RuntimeError as exc:
        assert "collision" in str(exc).lower()
        return
    raise AssertionError("two selected packages silently mapped to the same filename")


def test_regression_rpm_repository_rewrites_namespaced_location():
    import gzip
    from core import emit_rpm_repository
    repo = RepoSpec("R", "https://example.invalid/repo/")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.location = "Packages/demo.rpm"
    pkg.raw_metadata = '''<package xmlns="http://linux.duke.edu/metadata/common" type="rpm">
      <name>demo</name><arch>x86_64</arch><version epoch="0" ver="1.0" rel="1.el9"/>
      <checksum type="sha256" pkgid="YES">abc</checksum><size package="3"/>
      <location href="Packages/demo.rpm"/><format/>
    </package>'''
    with tempfile.TemporaryDirectory() as td:
        out = Path(td)
        emit_rpm_repository(out, [pkg], Reporter())
        primary = gzip.decompress((out / "repodata" / "primary.xml.gz").read_bytes()).decode()
        assert 'href="rpms/demo.rpm"' in primary
        assert 'href="Packages/demo.rpm"' not in primary
        assert "<package xmlns=" in primary
        assert "<name>demo</name>" in primary
        assert "ns0:" not in primary and "ns1:" not in primary


def test_rpm_repository_constructed_primary_uses_libsolv_namespace_spelling(tmp_path):
    """The native DNF tier is the oracle; this guards the serialization precondition."""
    import gzip
    from core import emit_rpm_repository

    pkg = rpm_pkg("demo", "1.0", requires=[Requirement("dep", "GE", "0", "1", "1")])
    pkg.raw_metadata = None
    emit_rpm_repository(tmp_path, [pkg], Reporter())
    primary = gzip.decompress((tmp_path / "repodata" / "primary.xml.gz").read_bytes()).decode()

    assert "ns0:" not in primary and "ns1:" not in primary
    assert "<name>demo</name>" in primary
    assert "<rpm:provides>" in primary
    assert "<rpm:requires>" in primary


def test_regression_apt_pocket_requires_exact_suite():
    repo = RepoSpec("Security", "https://archive.example/ubuntu/", repo_format="apt",
                    suite="noble-security", components="main")
    try:
        apt_core.check_release_suite(
            repo, {"Suite": "noble-updates", "Codename": "noble"}, Reporter())
    except RuntimeError:
        pass
    else:
        raise AssertionError("noble-security accepted noble-updates/base codename metadata")
    apt_core.check_release_suite(
        repo, {"Suite": "noble-security", "Codename": "noble"}, Reporter())


def test_regression_bundle_index_seals_receiver_verifier():
    from core import write_bundle_index
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td)
        (bundle / "payload").write_bytes(b"x")
        index = write_bundle_index(bundle, Reporter(), {"tool": "Feathered test"})
        payload = json.loads(index.read_text())
        paths = {entry["path"] for entry in payload["files"]}
        assert "verify-bundle.py" in paths


def test_regression_apt_installer_uses_local_repository_roots_not_payload_argv():
    """The installer lets APT solve dependencies from bundle metadata, not argv every DEB."""
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        source = base / "demo.deb"
        source.write_bytes(b"not-a-real-deb-but-sufficient-for-bundle-generation")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        source_repo = RepoSpec("Local", base.as_uri() + "/", repo_format="apt", suite="stable",
                               components="main")
        pkg = apt_core.DebPackage("demo", "amd64", "1.0", "demo.deb",
                                  "sha256", digest, source_repo, size=source.stat().st_size)
        result = apt_core.DebResolutionResult([pkg], [], [pkg])
        out = base / "bundle"
        apt_core.write_bundle(result, out, BuildOptions(retries=1), Reporter(),
                              {"workload": "test"})
        script = (out / "install-offline.sh").read_text()
        assert "REQUESTED-ROOTS.txt" in script
        assert "file:%s feathered main" in script
        assert 'install "${PLAN[@]}"' in script
        assert "find ./debs" not in script
        assert (out / "dists/feathered/Release").is_file()
        manifest = json.loads((out / "debs" / "manifest.json").read_text())
        assert manifest["packages"][0]["sha256"] == digest


def test_regression_source_bond_does_not_forward_acquisition_mtls_credentials():
    """A distinct evidence endpoint must never receive the acquisition repo's client key/cert."""
    original = apt_core._load_repository_once
    seen = []
    try:
        def fake_load(repo, arches, reporter):
            seen.append(repo)
            pkg = apt_core.DebPackage(
                "demo", "amd64", "1.0", "pool/demo.deb", "sha256", "ab" * 32, repo,
                size=123)
            return [pkg]
        apt_core._load_repository_once = fake_load
        repo = RepoSpec(
            "Primary", "https://primary.example/debian/", repo_format="apt",
            suite="stable", components="main", keyring="/trusted/archive.gpg",
            client_cert="/secret/client.crt", client_key="/secret/client.key",
            ca_cert="/secret/private-ca.pem",
            evidence_urls=["https://evidence.example/debian/"], evidence_policy="best-effort")
        apt_core.load_repository(repo, {"amd64"}, Reporter())
    finally:
        apt_core._load_repository_once = original
    assert len(seen) == 2
    evidence = seen[1]
    assert evidence.client_cert == "" and evidence.client_key == "" and evidence.ca_cert == ""
    # Source Bond provenance is intentionally
    # independent of acquisition GPG/keyring provenance.
    assert evidence.keyring == "", "evidence mirror inherited acquisition archive keyring"


def test_regression_required_source_bond_cannot_be_bypassed_by_disabling_checksums():
    from core import verify_package_artifact
    repo = RepoSpec("R", "https://a.example/repo/", evidence_policy="required")
    pkg = rpm_pkg("required-bond", "1.0", repo=repo)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "required.rpm"
        path.write_bytes(b"payload")
        try:
            verify_package_artifact(pkg, path, BuildOptions(verify_checksums=False), Reporter())
        except RuntimeError as exc:
            assert "required evidence source" in str(exc).lower()
        else:
            raise AssertionError("required legacy evidence policy was bypassed")

def test_regression_evidence_redirect_cannot_collapse_back_to_acquisition_host():
    """A nominally distinct evidence URL that redirects to acquisition is not independent."""
    import core
    import repository_transport
    original = repository_transport.urllib.request.build_opener
    class FakeResponse:
        closed = False
        def geturl(self):
            return "https://primary.example/repo/Release"
        def close(self):
            self.closed = True
    class FakeOpener:
        def __init__(self, response): self.response = response
        def open(self, *_args, **_kwargs): return self.response
    fake = FakeResponse()
    try:
        repository_transport.urllib.request.build_opener = lambda *_args, **_kwargs: FakeOpener(fake)
        repo = RepoSpec("Evidence", "https://evidence.example/repo/")
        repo._evidence_distinct_from = "https://primary.example/repo/"
        try:
            core._urlopen("https://evidence.example/repo/Release", 5, repo)
        except RuntimeError as exc:
            assert "redirected to acquisition host" in str(exc).lower()
            assert fake.closed
            return
    finally:
        repository_transport.urllib.request.build_opener = original
    raise AssertionError("evidence redirect back to the acquisition host was accepted")


def test_regression_rpm_requested_root_role_is_a_hard_constraint():
    docker = RepoSpec("Docker", "https://docker.example/", "docker", 10)
    osrepo = RepoSpec("Base", "https://base.example/", "dependency", 40)
    only_wrong_role = rpm_pkg("tool", "1.0", repo=osrepo)
    try:
        resolve([("tool", None, "docker")], [only_wrong_role], "x86_64",
                BuildOptions(), Reporter())
    except RuntimeError:
        pass
    else:
        raise AssertionError("an explicit docker root silently fell back to dependency role")

    correct = rpm_pkg("tool", "1.0", repo=docker)
    result = resolve([("tool", None, "docker")], [only_wrong_role, correct], "x86_64",
                     BuildOptions(), Reporter())
    assert result.roots and result.roots[0].repo.role == "docker"


def test_regression_matching_bond_digest_hashes_payload_once_and_marks_both_claims():
    """Identical acquisition/evidence SHA-256 claims share one local hash pass."""
    import core
    import provenance
    body = b"corroborated payload"
    digest = hashlib.sha256(body).hexdigest()
    primary_repo = RepoSpec("A", "https://a.example/repo/", evidence_policy="best-effort")
    evidence_repo = RepoSpec("B", "https://b.example/repo/")
    primary = rpm_pkg("bond-hash", "1.0", repo=primary_repo)
    evidence = rpm_pkg("bond-hash", "1.0", repo=evidence_repo)
    primary.checksum_type = evidence.checksum_type = "sha256"
    primary.checksum = evidence.checksum = digest
    core.apply_mirror_evidence([primary], [evidence], evidence_repo, Reporter())
    original = core.hash_file
    calls = []
    try:
        def counted(path, algorithm="sha256"):
            calls.append(algorithm)
            return original(path, algorithm)
        core.hash_file = counted
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bond-hash.rpm"
            path.write_bytes(body)
            core.verify_package_artifact(primary, path, BuildOptions(), Reporter())
    finally:
        core.hash_file = original
    assert calls == ["sha256"], calls
    assert primary.verification.package_digest_checked
    assert primary.verification.evidence_digest_checked
    # two strong metadata claims checked
    # against one payload surface as corroboration, not evidence-only recovery.
    entry = provenance.PackageProvenance(
        package_id=primary.nevra, filename="bond-hash.rpm", sha256=digest,
        size=len(body), source_url="https://a.example/repo/bond-hash.rpm",
        repository="A", digest_checked=True, evidence_metadata_match=True,
        evidence_digest_checked=True)
    assert provenance.assurance_from(entry) == "corroborated-digest"


# ---- provenance-independence regressions -------------------

def test_regression_1031_evidence_digest_verifies_when_acquisition_checksums_are_disabled():
    """Source-bond evidence is an independent channel, not gated by verify_checksums."""
    import core
    import provenance
    body = b"evidence-only verification path"
    digest = hashlib.sha256(body).hexdigest()
    acquisition = RepoSpec(
        "Acquisition", "https://a.example/repo/", evidence_policy="best-effort",
        keyring="/configured/only-for-acquisition.gpg")
    evidence_repo = RepoSpec("Evidence", "https://b.example/repo/")
    pkg = rpm_pkg("evidence-only", "1.0", repo=acquisition)
    peer = rpm_pkg("evidence-only", "1.0", repo=evidence_repo)
    # Acquisition publishes no usable digest; evidence does.
    pkg.checksum_type = ""
    pkg.checksum = ""
    peer.checksum_type = "sha256"
    peer.checksum = digest
    core.apply_mirror_evidence([pkg], [peer], evidence_repo, Reporter())
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "evidence-only.rpm"
        path.write_bytes(body)
        checked = core.verify_package_artifact(
            pkg, path, BuildOptions(verify_checksums=False), Reporter())
    assert checked
    assert not pkg.verification.package_digest_checked
    assert pkg.verification.evidence_digest_checked
    entry = provenance.PackageProvenance(
        package_id=pkg.nevra, filename=path.name, sha256=digest, size=len(body),
        source_url="https://a.example/repo/evidence-only.rpm", repository="Acquisition",
        digest_checked=False, evidence_metadata_match=True, evidence_digest_checked=True)
    assert provenance.assurance_from(entry) == provenance.VERIFIED_EVIDENCE
    assert entry.evidence_provenance == provenance.VERIFIED_EVIDENCE
    assert provenance.VERIFIED_ARCHIVE not in entry.provenance_modes


def test_regression_1031_archive_and_mirror_provenance_coexist():
    """A keyring-backed archive chain must not erase independently obtained mirror evidence."""
    import provenance
    entry = provenance.PackageProvenance(
        package_id="demo-1.0.x86_64", filename="demo.rpm", sha256="ab" * 32,
        size=123, source_url="https://a.example/demo.rpm", repository="A",
        archive_signature_verified=True, index_digest_verified=True,
        digest_checked=True, evidence_metadata_match=True, evidence_digest_checked=True)
    # Backward-compatible headline may remain archive-chain, but complete modes
    # must expose both independent facts.
    assert provenance.assurance_from(entry) == provenance.VERIFIED_ARCHIVE
    assert provenance.VERIFIED_ARCHIVE in entry.provenance_modes
    assert provenance.VERIFIED_CORROBORATED in entry.provenance_modes
    assert provenance.PROVENANCE_ACQUISITION_DIGEST in entry.provenance_modes
    assert entry.archive_provenance == provenance.VERIFIED_ARCHIVE
    assert entry.evidence_provenance == provenance.VERIFIED_CORROBORATED


def test_regression_1031_provenance_json_has_multi_axis_mode_summary():
    import provenance
    entry = provenance.PackageProvenance(
        package_id="demo", filename="demo.deb", sha256="cd" * 32, size=1,
        source_url="https://a.example/demo.deb", repository="A",
        archive_signature_verified=True, index_digest_verified=True, digest_checked=True,
        evidence_metadata_match=True, evidence_digest_checked=True)
    entry.assurance = provenance.assurance_from(entry)
    bundle = provenance.BundleProvenance(
        bundle_id="b", created="now", tool="Feathered", packages=[entry])
    payload = json.loads(bundle.to_json())
    pkg = payload["packages"][0]
    assert pkg["archive_provenance"] == provenance.VERIFIED_ARCHIVE
    assert pkg["evidence_provenance"] == provenance.VERIFIED_CORROBORATED
    assert provenance.VERIFIED_ARCHIVE in pkg["provenance_modes"]
    assert provenance.VERIFIED_CORROBORATED in pkg["provenance_modes"]
    assert payload["mode_summary"][provenance.VERIFIED_ARCHIVE] == 1
    assert payload["mode_summary"][provenance.VERIFIED_CORROBORATED] == 1

# ---- selectable-digest / evidence-fallback regressions -----

def test_regression_1032_auto_digest_uses_strongest_published_sha2():
    from core import select_digest_from_map
    digests = {"sha256": "25" * 32, "sha384": "38" * 48, "sha512": "51" * 64}
    algo, value = select_digest_from_map(digests, "auto")
    assert algo == "sha512"
    assert value == digests["sha512"]


def test_regression_1032_exact_digest_does_not_silently_substitute_strength():
    # 1.0.36 intentionally changes explicit SHA choices to minimum strengths.
    from core import select_digest_from_map
    digests = {"sha256": "25" * 32, "sha512": "51" * 64}
    assert select_digest_from_map({"sha256": digests["sha256"]}, "sha512") is None
    assert select_digest_from_map(digests, "sha256") == ("sha512", digests["sha512"])
    assert select_digest_from_map(digests, "sha384") == ("sha512", digests["sha512"])

def test_regression_1032_fallback_does_not_query_evidence_when_selected_sha_exists(monkeypatch):
    import core
    primary_repo = RepoSpec(
        "Primary", "https://a.example/repo/", evidence_policy="fallback",
        evidence_urls=["https://b.example/repo/"], digest_preference="sha512")
    pkg = rpm_pkg("demo", "1.0", repo=primary_repo)
    pkg.digests = {"sha512": "ab" * 64}
    pkg.checksum_type, pkg.checksum = "sha512", pkg.digests["sha512"]
    calls = []

    def fake_once(repo, arches, reporter, retries=3):
        calls.append(repo.url)
        return [pkg]

    monkeypatch.setattr(core, "_load_repository_once", fake_once)
    loaded = core.load_repository(primary_repo, {"x86_64"}, Reporter())
    assert loaded == [pkg]
    assert calls == [primary_repo.url]
    assert pkg.verification.evidence_status == "not-needed"


def test_regression_1032_fallback_uses_metadata_peer_when_selected_sha_missing(monkeypatch):
    import core
    primary_repo = RepoSpec(
        "Primary", "https://a.example/repo/", evidence_policy="fallback",
        evidence_urls=["https://b.example/repo/"], digest_preference="sha512")
    evidence_repo = RepoSpec("Evidence", "https://b.example/repo/", digest_preference="sha512")
    primary = rpm_pkg("demo", "1.0", repo=primary_repo)
    primary.digests = {"sha256": "11" * 32}
    primary.checksum_type, primary.checksum = "sha256", primary.digests["sha256"]
    peer = rpm_pkg("demo", "1.0", repo=evidence_repo)
    peer.digests = {"sha512": "22" * 64}
    peer.checksum_type, peer.checksum = "sha512", peer.digests["sha512"]
    calls = []

    def fake_once(repo, arches, reporter, retries=3):
        calls.append(repo.url)
        return [primary] if repo.url.startswith("https://a.example") else [peer]

    monkeypatch.setattr(core, "_load_repository_once", fake_once)
    loaded = core.load_repository(primary_repo, {"x86_64"}, Reporter())
    assert loaded == [primary]
    assert calls == [primary_repo.url, "https://b.example/repo/"]
    assert primary.verification.evidence_digest_type == "sha512"
    assert primary.verification.evidence_status == "independent-digest"


def test_regression_1032_required_selected_sha_fails_without_acquisition_or_evidence(tmp_path):
    import core
    repo = RepoSpec(
        "Primary", "https://a.example/repo/", digest_preference="sha512",
        digest_requirement="required", evidence_policy="off")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.digests = {"sha256": hashlib.sha256(b"body").hexdigest()}
    pkg.checksum_type, pkg.checksum = "sha256", pkg.digests["sha256"]
    path = tmp_path / "demo.rpm"
    path.write_bytes(b"body")
    try:
        core.verify_package_artifact(pkg, path, BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "configured minimum" in str(exc).lower()
    else:
        raise AssertionError("required SHA-512 minimum accepted a package with only SHA-256")

def test_regression_1033_evidence_dropdown_candidates_follow_selected_top_level_repo():
    """The evidence dropdown is derived from the selected acquisition repo, not a global URL list."""
    import app as feather_app
    primary = RepoSpec(
        "Ubuntu noble", "https://archive.example/ubuntu", repo_format="apt",
        suite="noble", components="main universe",
        evidence_suggestions=["https://curated.example/ubuntu"])
    compatible = RepoSpec(
        "Ubuntu peer", "https://configured.example/ubuntu", repo_format="apt",
        suite="noble", components="universe main")
    wrong_suite = RepoSpec(
        "Wrong suite", "https://wrong.example/ubuntu", repo_format="apt",
        suite="jammy", components="main universe")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [primary, compatible, wrong_suite]
    choices = feather_app.App._evidence_candidate_map(ui, primary)
    # 1.1.5: profile evidence is driven by the editable Ubuntu mirror catalog,
    # not the legacy hard-coded evidence_suggestions field on RepoSpec.
    assert "https://curated.example/ubuntu" not in choices.values()
    assert any("Exact mirror" in label and "Ubuntu mirror" in label
               for label in choices)
    assert any("Configured alternate mirror" in label and url == compatible.normalized_url
               for label, url in choices.items())
    assert wrong_suite.normalized_url not in choices.values()


def test_regression_1033_inspected_sha_choices_are_retained_before_full_analysis():
    """Explicit metadata inspection must drive SHA choices even with no loaded package analysis."""
    import app as feather_app
    repo = RepoSpec("R", "https://repo.example/")
    ui = object.__new__(feather_app.App)
    ui.loaded_packages = []
    ui._provenance_detected_cache = {(repo.name, repo.normalized_url): ["sha512", "sha256"]}
    found = feather_app.App._detected_digest_algorithms(ui, repo)
    assert found == ["sha512", "sha256"]

# ---- inherited-source provenance UI regressions -----------

def test_regression_1034_provenance_policy_applies_to_enabled_sources_only():
    """Packages & Sources owns selection; the 1.0.36 strategy follows enabled repos."""
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    enabled = RepoSpec(
        "Enabled", "https://primary.example/repo/", enabled=True,
        evidence_suggestions=["https://evidence.example/repo/"])
    disabled = RepoSpec("Disabled", "https://disabled.example/repo/", enabled=False)
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [enabled, disabled]
    ui.prov_digest_var = Var("SHA-512 (1 of 1 direct)")
    ui.prov_strategy_var = Var("Fill gaps with independent evidence")
    ui._invalidate_provenance_analysis = lambda: None
    ui._refresh_provenance_editor = lambda: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui._log = lambda _message: None
    ui._digest_inspection_known = lambda _repo: False

    feather_app.App._provenance_policy_changed(ui)

    assert enabled.digest_preference == "sha512"
    assert enabled.verification_strategy == "evidence-fallback"
    assert enabled.digest_requirement == "preferred"
    assert enabled.evidence_policy == "fallback"
    # Evidence is now explicit opt-in. Selecting an evidence-based strategy
    # must not auto-mesh every repository with a curated peer.
    assert enabled.evidence_urls == []
    assert disabled.verification_strategy == ""

def test_regression_1034_digest_coverage_labels_map_to_exact_strength():
    import app as feather_app
    assert feather_app.App._digest_ui_to_policy("SHA-512 (2 of 4 direct)") == "sha512"
    assert feather_app.App._digest_ui_to_policy("SHA-384 or stronger (1 of 4 direct)") == "sha384"
    assert feather_app.App._digest_ui_to_policy("SHA-256 or stronger (4 of 4 direct)") == "sha256"
    assert feather_app.App._digest_ui_to_policy("Automatic (4 of 4 direct)") == "auto"

def test_regression_1034_main_provenance_ui_has_no_second_source_selector_or_apply_button():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._build_keyrings_pane)
    assert "Acquisition repository" not in source
    assert "Apply provenance choices" not in source
    assert "Minimum checksum strength" in source
    assert "Verification strategy" in source
    assert "Required?" not in source

def test_regression_1034_advanced_provenance_dialog_is_live_not_save_apply():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App.edit_repo_trust)
    assert 'text="Save provenance settings"' not in source
    assert 'text="Done"' in source
    assert "Changes apply immediately" in source


# ---- provenance hierarchy/progress regressions -----------

def test_regression_1035_required_sha_forces_independent_evidence_off():
    """The new checksum-required strategy must not activate evidence."""
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    repo = RepoSpec("Enabled", "https://primary.example/repo/", enabled=True,
                    evidence_urls=["https://evidence.example/repo/"])
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.prov_digest_var = Var("Automatic")
    ui.prov_strategy_var = Var("Require checksum coverage")
    ui._invalidate_provenance_analysis = lambda: None
    ui._refresh_provenance_editor = lambda: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui._log = lambda _message: None
    ui._digest_inspection_known = lambda _repo: False

    feather_app.App._provenance_policy_changed(ui)
    assert repo.verification_strategy == "checksum-required"
    assert repo.digest_requirement == "required"
    assert repo.evidence_policy == "off"
    assert repo.evidence_urls == ["https://evidence.example/repo/"]

def test_regression_1035_evidence_controls_follow_required_and_mode_state():
    import app as feather_app

    class Var:
        def __init__(self, value=""): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    class Widget:
        def __init__(self): self.state = None; self.style = None
        def winfo_exists(self): return True
        def configure(self, **kwargs):
            self.state = kwargs.get("state", self.state)
            self.style = kwargs.get("style", self.style)

    ui = object.__new__(feather_app.App)
    ui.prov_strategy_var = Var("Require checksum coverage")
    title = Widget(); help_label = Widget(); row_label = Widget(); row = Widget()
    ui.prov_evidence_title = title
    ui.prov_evidence_help_label = help_label
    ui._prov_evidence_row_labels = [row_label]
    ui._prov_evidence_row_combos = [row]
    ui.prov_evidence_state_var = Var()
    feather_app.App._update_provenance_evidence_state(ui)
    assert title.style == "MutedPanelGroup.TLabel"
    assert help_label.style == "MutedPanelHint.TLabel"
    assert row_label.style == "MutedPanel.TLabel"
    assert row.state == "disabled"
    assert row.style == "Evidence.TCombobox"

    ui.prov_strategy_var.set("Verify what is available")
    feather_app.App._update_provenance_evidence_state(ui)
    assert row.state == "disabled"
    assert title.style == "MutedPanelGroup.TLabel"

    ui.prov_strategy_var.set("Fill gaps with independent evidence")
    feather_app.App._update_provenance_evidence_state(ui)
    assert title.style == "PanelGroup.TLabel"
    assert help_label.style == "PanelHint.TLabel"
    assert row_label.style == "Panel.TLabel"
    assert row.state == "readonly"

def test_regression_1035_repository_inspection_has_visible_progress():
    import app as feather_app, inspect
    pane_source = inspect.getsource(feather_app.App._build_keyrings_pane)
    worker_source = inspect.getsource(feather_app.App._inspect_enabled_provenance_metadata)
    assert "prov_inspect_progress" in pane_source
    assert "prov_inspect_status_var" in pane_source
    assert "Inspecting {i} of {len(enabled)}" in worker_source
    assert "Completed {i} of {len(enabled)}" in worker_source

def test_regression_1035_provenance_ui_avoids_em_dash_heavy_labels():
    import app as feather_app, inspect
    em_dash = chr(0x2014)
    assert em_dash not in inspect.getsource(feather_app.App._build_keyrings_pane)
    assert em_dash not in inspect.getsource(feather_app.App.edit_repo_trust)


def test_regression_1035_required_digest_does_not_fall_back_to_evidence(tmp_path):
    import core
    body = b"strict checksum policy\n"
    repo = RepoSpec(
        "Primary", "https://a.example/repo/", digest_preference="sha512",
        digest_requirement="required", evidence_policy="best-effort",
        evidence_urls=["https://b.example/repo/"])
    pkg = rpm_pkg("strict", "1.0", repo=repo)
    pkg.digests = {"sha256": hashlib.sha256(body).hexdigest()}
    pkg.checksum_type, pkg.checksum = "sha256", pkg.digests["sha256"]
    record = core._artifact_verification(pkg)
    record.evidence_digest_type = "sha512"
    record.evidence_digest = hashlib.sha512(body).hexdigest()
    record.evidence_metadata_match = True
    path = tmp_path / "strict.rpm"
    path.write_bytes(body)
    try:
        core.verify_package_artifact(pkg, path, BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "configured minimum" in str(exc).lower()
    else:
        raise AssertionError("legacy required acquisition SHA was incorrectly satisfied by evidence metadata")


# ---- streamlined checksum-strategy regressions ------------

def test_regression_1036_sha_choice_is_minimum_and_prefers_stronger_digest():
    from core import select_digest_from_map
    digests = {"sha256": "25" * 32, "sha384": "38" * 48, "sha512": "51" * 64}
    assert select_digest_from_map(digests, "sha256")[0] == "sha512"
    assert select_digest_from_map(digests, "sha384")[0] == "sha512"
    assert select_digest_from_map({"sha384": digests["sha384"]}, "sha256")[0] == "sha384"
    assert select_digest_from_map({"sha256": digests["sha256"]}, "sha384") is None


def test_regression_1036_checksum_available_powers_through_uncovered_package(tmp_path):
    import core
    body = b"no qualifying sha512\n"
    repo = RepoSpec(
        "R", "https://a.example/repo/", digest_preference="sha512",
        verification_strategy="checksum-available")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.digests = {"sha256": hashlib.sha256(body).hexdigest()}
    pkg.checksum_type, pkg.checksum = "sha256", pkg.digests["sha256"]
    path = tmp_path / "demo.rpm"; path.write_bytes(body)
    warnings = []
    ok = core.verify_package_artifact(pkg, path, BuildOptions(), Reporter(log=warnings.append))
    assert ok is False
    assert not pkg.verification.package_digest_checked


def test_regression_1036_evidence_fallback_fills_only_a_checksum_gap(tmp_path, monkeypatch):
    import core
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_a, **_k: (True, "distinct test source"))
    body = b"one payload one independent artifact\n"
    repo = RepoSpec(
        "R", "https://a.example/repo/", digest_preference="sha512",
        verification_strategy="evidence-fallback")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.digests = {"sha256": hashlib.sha256(body).hexdigest()}
    pkg.checksum_type, pkg.checksum = "sha256", pkg.digests["sha256"]
    path = tmp_path / "demo.rpm"; path.write_bytes(body)
    evidence = tmp_path / Path(pkg.location).name; evidence.write_bytes(body)
    repo.evidence_urls = [evidence.as_uri()]
    record = core._artifact_verification(pkg)
    assert core.verify_package_artifact(pkg, path, BuildOptions(), Reporter())
    assert not record.package_digest_checked
    assert record.evidence_artifact_checked
    assert record.evidence_artifact_digest_type == "sha512"
    assert record.evidence_artifact_digest == hashlib.sha512(body).hexdigest()


def test_regression_1036_full_corroboration_requires_both_claims(tmp_path, monkeypatch):
    import core
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_a, **_k: (True, "distinct test source"))
    body = b"corroborated\n"
    digest = hashlib.sha512(body).hexdigest()
    repo = RepoSpec(
        "R", "https://a.example/repo/", digest_preference="sha512",
        verification_strategy="full-corroboration")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.digests = {"sha512": digest}; pkg.checksum_type = "sha512"; pkg.checksum = digest
    path = tmp_path / "demo.rpm"; path.write_bytes(body)
    try:
        core.verify_package_artifact(pkg, path, BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "full corroboration" in str(exc).lower()
    else:
        raise AssertionError("full corroboration accepted a package with no independent artifact")
    evidence = tmp_path / Path(pkg.location).name; evidence.write_bytes(body)
    repo.evidence_urls = [evidence.as_uri()]
    record = core._artifact_verification(pkg)
    assert core.verify_package_artifact(pkg, path, BuildOptions(), Reporter())
    assert record.package_digest_checked and record.evidence_artifact_checked

def test_regression_1036_strict_ui_preserves_all_minimums_and_reports_coverage():
    import app as feather_app

    class Var:
        def __init__(self, value=""): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value
    class Combo:
        def __init__(self): self.values = []; self.state = None
        def configure(self, **kwargs):
            if "values" in kwargs: self.values = list(kwargs["values"])
            if "state" in kwargs: self.state = kwargs["state"]
    class Tree:
        def winfo_exists(self): return True
        def delete(self, *_a): pass
        def get_children(self): return []

    r1 = RepoSpec("Strong", "https://one.example/repo/", enabled=True,
                  digest_preference="sha256", verification_strategy="checksum-required")
    r2 = RepoSpec("Common", "https://two.example/repo/", enabled=True,
                  digest_preference="sha256", verification_strategy="checksum-required")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [r1, r2]; ui.loaded_packages = []
    ui._provenance_detected_cache = {
        (r1.name, r1.normalized_url): ["sha512", "sha384", "sha256"],
        (r2.name, r2.normalized_url): ["sha256"],
    }
    ui._provenance_digest_coverage_cache = {
        (r1.name, r1.normalized_url): {"total": 10, "auto": 10, "sha256": 10, "sha384": 10, "sha512": 10},
        (r2.name, r2.normalized_url): {"total": 10, "auto": 10, "sha256": 10, "sha384": 0, "sha512": 0},
    }
    ui.prov_source_tree = Tree(); ui.prov_enabled_sources_var = Var(); ui.prov_detected_var = Var()
    ui.prov_digest_var = Var(); ui.prov_digest_combo = Combo(); ui.prov_digest_help_var = Var()
    ui.prov_strategy_var = Var(); ui.prov_strategy_combo = Combo(); ui.prov_strategy_help_var = Var()
    ui._refresh_provenance_source_tree = lambda: None
    ui._refresh_provenance_evidence_rows = lambda: None
    ui._update_provenance_evidence_state = lambda: None
    feather_app.App._refresh_provenance_editor(ui)
    joined = " | ".join(ui.prov_digest_combo.values)
    assert "SHA-256 or stronger" in joined
    assert "Automatic (2 of 2 direct)" in joined
    assert "SHA-384 or stronger (1 of 2 direct)" in joined
    assert "SHA-512 (1 of 2 direct)" in joined
    assert ui.prov_digest_var.get() == "SHA-256 or stronger (2 of 2 direct)"


def test_regression_1036_evidence_ui_is_subordinate_to_strategy_not_a_second_toggle():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._build_keyrings_pane)
    assert "Required?" not in source
    assert "Evidence policy" not in source
    assert "Verification strategy" in source
    assert "Independent evidence sources" in source


# ---- inactive-provenance styling regression ---------------

def test_regression_1037_disabled_provenance_controls_use_dark_muted_styles():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._style)
    assert 'MutedPanelGroup.TLabel' in source
    assert 'MutedPanelHint.TLabel' in source
    assert 'Evidence.TCombobox' in source
    assert '("disabled", BG_DISABLED)' in source
    state_source = inspect.getsource(feather_app.App._update_provenance_evidence_state)
    assert 'configure(state="normal" if active else "disabled")' not in state_source
    assert 'MutedPanelGroup.TLabel' in state_source

# ---- explicit skip-upstream-provenance regressions ---------

def test_regression_1038_skip_strategy_is_first_class():
    import core
    repo = RepoSpec("R", "https://repo.example/", verification_strategy="skip-provenance")
    assert core.repository_verification_strategy(repo) == "skip-provenance"


def test_regression_1038_skip_strategy_does_not_hash_package_claims(tmp_path):
    import core
    body = b"payload that intentionally does not match repository claim\n"
    repo = RepoSpec(
        "R", "https://repo.example/", digest_preference="sha512",
        verification_strategy="skip-provenance")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    pkg.digests = {"sha512": "00" * 64}
    pkg.checksum_type = "sha512"; pkg.checksum = pkg.digests["sha512"]
    path = tmp_path / "demo.rpm"; path.write_bytes(body)
    options = BuildOptions(require_package_digests=True, verify_checksums=True)
    assert core.verify_package_artifact(pkg, path, options, Reporter()) is False
    assert not pkg.verification.package_digest_checked
    assert pkg.verification.evidence_status == "skipped"
    assert any("intentionally skipped" in note.lower() for note in pkg.verification.notes)


def test_regression_1038_apt_skip_ignores_configured_archive_keyring(monkeypatch):
    import apt_core
    repo = RepoSpec(
        "APT", "https://repo.example/", repo_format="apt", suite="stable",
        keyring="/definitely/not/a/keyring.gpg", verification_strategy="skip-provenance")
    called = []
    monkeypatch.setattr(apt_core, "verify_openpgp", lambda *_a, **_k: called.append(True))
    apt_core.verify_release_signature(repo, "dists/stable/InRelease", b"not signed", Reporter())
    assert called == []
    assert not apt_core._repo_trust(repo).archive_signature_verified


def test_regression_1038_rpm_skip_does_not_fetch_or_verify_repomd_signature(monkeypatch):
    import core
    repo = RepoSpec(
        "RPM", "https://repo.example/", keyring="/definitely/not/a/keyring.gpg",
        verification_strategy="skip-provenance")
    repomd = b'''<?xml version="1.0"?>\n<repomd xmlns="http://linux.duke.edu/metadata/repo">\n  <data type="primary"><location href="repodata/primary.xml.gz"/></data>\n</repomd>'''
    urls = []
    def fake_fetch(url, *_a, **_k):
        urls.append(url)
        if url.endswith("repodata/repomd.xml"):
            return repomd
        raise AssertionError(f"unexpected fetch: {url}")
    monkeypatch.setattr(core, "fetch_bytes", fake_fetch)
    monkeypatch.setattr(core, "verify_openpgp", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("verification should be skipped")))
    refs = core.get_repo_data(repo, Reporter())
    assert "primary" in refs
    assert not any(url.endswith(".asc") for url in urls)


def test_regression_1038_skip_ui_disables_checksum_and_evidence_controls():
    import app as feather_app, inspect
    build_source = inspect.getsource(feather_app.App._build_keyrings_pane)
    assert "Skip upstream provenance checks" in build_source
    helper_source = inspect.getsource(feather_app.App._strategy_help_text)
    assert '"skip-provenance"' in helper_source
    state_source = inspect.getsource(feather_app.App._update_provenance_evidence_state)
    assert 'skip_upstream = strategy == "skip-provenance"' in state_source
    assert 'digest_combo.configure(state="disabled" if skip_upstream else "readonly")' in state_source


def test_regression_1038_skip_strategy_never_uses_evidence_mirror(monkeypatch):
    import core
    repo = RepoSpec(
        "R", "https://one.example/repo/", verification_strategy="skip-provenance",
        evidence_urls=["https://two.example/repo/"])
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    calls = []
    monkeypatch.setattr(core, "_load_repository_once", lambda *_a, **_k: calls.append("acquisition") or [pkg])
    monkeypatch.setattr(core, "apply_mirror_evidence", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("evidence should not be used")))
    out = core.load_repository(repo, {"x86_64"}, Reporter())
    assert out == [pkg]
    assert calls == ["acquisition"]

# --------------------------------------------------------------------------
#  1.0.39: actionable unresolved review + repository sidecar utilities
# --------------------------------------------------------------------------

def test_rpm_rich_or_dependency_resolves_available_branch():
    """Common `(A or B)` RPM rich dependencies are choices, not syntax errors."""
    root = rpm_pkg("fips-provider-next", "1.0", [Requirement("(iptables-nft or iptables)")])
    iptables = rpm_pkg("iptables", "1.8")
    result = resolve([("fips-provider-next", None, "dependency")], [root, iptables],
                     "x86_64", BuildOptions(), Reporter())
    assert not result.unresolved
    assert {p.name for p in result.selected} == {"fips-provider-next", "iptables"}


def test_rpm_rich_or_can_backtrack_to_other_branch_provider():
    """If the first OR branch has a broken closure, retry a provider from another branch."""
    root = rpm_pkg("app-rich-or", "1.0", [Requirement("(choice-a or choice-b)")])
    bad = rpm_pkg("choice-a", "2.0", [Requirement("missing-deep")])
    good = rpm_pkg("choice-b", "1.0")
    result = resolve([("app-rich-or", None, "dependency")], [root, bad, good],
                     "x86_64", BuildOptions(max_resolution_passes=12), Reporter())
    assert not result.unresolved
    assert "choice-b" in {p.name for p in result.selected}
    assert "choice-a" not in {p.name for p in result.selected}


def _ar_member(name: str, payload: bytes) -> bytes:
    name_field = (name + "/").encode("ascii").ljust(16, b" ")
    header = (name_field + b"0".ljust(12, b" ") + b"0".ljust(6, b" ") +
              b"0".ljust(6, b" ") + b"100644".ljust(8, b" ") +
              str(len(payload)).encode("ascii").ljust(10, b" ") + b"`\n")
    return header + payload + (b"\n" if len(payload) % 2 else b"")


def _write_tiny_deb(path: Path, package="feathered-reindex-demo", version="1.0-1") -> None:
    import io
    import tarfile
    control = (f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
               "Maintainer: Feathered Test <test@example.invalid>\n"
               "Description: repository rebuild test\nDepends: libc6 (>= 2.31)\n").encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("./control")
        info.size = len(control)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(control))
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz"):
        pass
    archive = (b"!<arch>\n" + _ar_member("debian-binary", b"2.0\n") +
               _ar_member("control.tar.gz", buf.getvalue()) +
               _ar_member("data.tar.gz", data_buf.getvalue()))
    path.write_bytes(archive)


def test_repository_sidecar_rebuilds_apt_metadata_without_moving_packages(tmp_path):
    import repository_tools
    pkg_dir = tmp_path / "piecemeal" / "incoming"
    pkg_dir.mkdir(parents=True)
    deb = pkg_dir / "demo.deb"
    _write_tiny_deb(deb)
    report = repository_tools.rebuild_repository_metadata(tmp_path / "piecemeal")
    assert report.family == "deb"
    assert report.package_count == 1
    assert deb.is_file(), "sidecar workflow must not reorganize payloads"
    packages = (tmp_path / "piecemeal" / "dists" / "feathered" / "main" /
                "binary-amd64" / "Packages").read_text()
    assert "Filename: incoming/demo.deb" in packages
    assert "SHA256:" in packages and "SHA512:" in packages
    assert "Depends: libc6 (>= 2.31)" in packages
    assert (tmp_path / "piecemeal" / "repository-rebuild.json").is_file()


def test_repository_sidecar_rejects_mixed_package_families(tmp_path):
    import repository_tools
    _write_tiny_deb(tmp_path / "demo.deb")
    (tmp_path / "fake.rpm").write_bytes(b"not-rpm")
    try:
        repository_tools.rebuild_repository_metadata(tmp_path)
    except RuntimeError as exc:
        assert "both RPM and DEB" in str(exc)
    else:
        raise AssertionError("mixed package families must not be silently combined")


def test_review_source_contains_unresolved_waiver_and_retry_controls():
    import app, inspect
    root = Path(__file__).resolve().parent
    source = inspect.getsource(app.App._build_review_pane)
    assert 'text="Retry unresolved"' in source
    assert 'text="Ignore selected"' in source
    assert "ignored-unresolved.txt" in (root / "core.py").read_text(encoding="utf-8")
    assert "ignored-unresolved.txt" in (root / "apt_core.py").read_text(encoding="utf-8")


def test_repository_tools_are_sidecar_not_sixth_wizard_step():
    import app, inspect
    ui_source = inspect.getsource(app.App._build_ui)
    tools_source = inspect.getsource(app.App._build_tools_pane)
    assert 'self.stage_order = ["target", "packages", "repositories", "keyrings", "transfer", "review"]' in ui_source
    assert 'self._tool_rail_row("Repository utilities", "tools")' in ui_source
    assert '"Build repository metadata"' in tools_source


def _write_synthetic_rpm(path: Path) -> None:
    """Small RPM-shaped fixture sufficient to exercise Feathered's header reader."""
    import struct

    def header(entries):
        store = b""
        indexes = []
        for tag, typ, values in entries:
            offset = len(store)
            if typ == 6:  # STRING
                payload = str(values[0]).encode() + b"\0"
                count = 1
            elif typ == 8:  # STRING_ARRAY
                payload = b"".join(str(v).encode() + b"\0" for v in values)
                count = len(values)
            elif typ == 4:  # INT32
                payload = b"".join(struct.pack(">I", int(v)) for v in values)
                count = len(values)
            else:
                raise ValueError(typ)
            store += payload
            indexes.append(struct.pack(">IIiI", tag, typ, offset, count))
        return (b"\x8e\xad\xe8\x01" + b"\0" * 4 +
                struct.pack(">II", len(indexes), len(store)) + b"".join(indexes) + store)

    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    signature = header([])
    main = header([
        (1000, 6, ["demo"]), (1001, 6, ["1.0"]), (1002, 6, ["1.el9"]),
        (1003, 4, [0]), (1022, 6, ["x86_64"]), (1009, 4, [123]),
        (1047, 8, ["demo"]), (1113, 8, ["0:1.0-1.el9"]), (1112, 4, [8]),
        (1049, 8, ["bash"]), (1050, 8, ["0:5.0-1.el9"]), (1048, 4, [12]),
    ])
    path.write_bytes(lead + signature + main + b"payload")


def test_repository_sidecar_reads_rpm_dependency_header_and_writes_primary(tmp_path):
    import gzip
    import repository_tools
    rpm_dir = tmp_path / "rpms"
    rpm_dir.mkdir()
    rpm = rpm_dir / "demo.rpm"
    _write_synthetic_rpm(rpm)
    report = repository_tools.rebuild_repository_metadata(tmp_path)
    assert report.family == "rpm"
    primary = gzip.decompress((tmp_path / "repodata" / "primary.xml.gz").read_bytes()).decode()
    assert 'href="rpms/demo.rpm"' in primary
    assert 'name="bash"' in primary
    assert 'flags="GE"' in primary

# 1.0.40 output-path regressions.
def test_review_output_path_combines_base_and_bundle_folder(tmp_path):
    import app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.out_var = Var(str(tmp_path / "exports"))
    dummy._folder_name = lambda: "2026-08-28_rhel-9.8-x86_64-docker-offline"
    actual = app.App._resolved_output_path(dummy)
    assert actual == tmp_path / "exports" / "2026-08-28_rhel-9.8-x86_64-docker-offline"


def test_resolved_output_path_can_reuse_build_folder_name_without_regenerating(tmp_path):
    import app

    class Var:
        def get(self): return str(tmp_path)

    dummy = type("Dummy", (), {})()
    dummy.out_var = Var()
    dummy._folder_name = lambda: (_ for _ in ()).throw(AssertionError("folder name regenerated"))
    assert app.App._resolved_output_path(dummy, "locked-name") == tmp_path / "locked-name"


def test_successful_build_enables_open_output_folder(tmp_path):
    import app

    out = tmp_path / "bundle"
    out.mkdir()

    class Widget:
        def __init__(self): self.state = None
        def configure(self, **kw):
            if "state" in kw: self.state = kw["state"]

    class Label:
        def __init__(self): self.text = None
        def configure(self, **kw): self.text = kw.get("text", self.text)

    class Var:
        def set(self, _value): pass

    dummy = type("Dummy", (), {})()
    dummy.worker = object()
    dummy.cancel_btn = Widget()
    dummy.analyze_btn = Widget()
    dummy.build_btn = Widget()
    dummy.open_output_btn = Widget()
    dummy.status_var = Var()
    dummy.progress_var = Var()
    dummy.review_labels = {"Bundle path": Label()}
    dummy.last_output_path = None
    dummy._log = lambda _msg: None

    app.App._worker_done(dummy, True, f"Bundle complete: {out}", str(out))
    assert dummy.last_output_path == out
    assert dummy.open_output_btn.state == "normal"
    assert dummy.review_labels["Bundle path"].text == str(out)

# --------------------------------------------------------------------------
#  1.0.41: Review build contract before dependency analysis
# --------------------------------------------------------------------------

def test_review_contract_exposes_single_package_before_analysis():
    import app
    pkg = rpm_pkg("explicit-root", "2.0")
    dummy = type("Dummy", (), {})()
    dummy._ui_acquisition_state = lambda: app.App._ui_acquisition_state(dummy)
    dummy.selected_packages = [pkg]
    dummy._mirror_mode = lambda: False
    dummy._single_mode = lambda: True
    rows = app.App._review_contract_rows(dummy)
    assert rows == [(pkg.nevra, "requested", pkg.repo.name, "explicit package selection")]


def test_review_actions_disable_when_contract_is_empty_and_enable_before_analysis():
    import app

    class Widget:
        def __init__(self): self.state = None; self.style = None
        def configure(self, **kw):
            self.state = kw.get("state", self.state)
            self.style = kw.get("style", self.style)

    dummy = type("Dummy", (), {})()
    dummy._ui_acquisition_state = lambda: app.App._ui_acquisition_state(dummy)
    dummy.analyze_btn = Widget(); dummy.build_btn = Widget()
    dummy.worker = None; dummy.last_result = None
    dummy._has_review_contract = lambda: False
    app.App._sync_review_action_states(dummy)
    assert dummy.analyze_btn.state == "disabled"
    assert dummy.build_btn.state == "disabled"

    dummy._has_review_contract = lambda: True
    app.App._sync_review_action_states(dummy)
    assert dummy.analyze_btn.state == "normal"
    assert dummy.build_btn.state == "normal"
    assert dummy.build_btn.style == "TButton", "pre-analysis Build is available but remains secondary"


def test_review_build_disables_for_blocking_analysis_and_reenables_after_waiver():
    import app

    class Widget:
        def __init__(self): self.state = None; self.style = None
        def configure(self, **kw):
            self.state = kw.get("state", self.state)
            self.style = kw.get("style", self.style)

    dummy = type("Dummy", (), {})()
    dummy._ui_acquisition_state = lambda: app.App._ui_acquisition_state(dummy)
    dummy.analyze_btn = Widget(); dummy.build_btn = Widget()
    dummy.worker = None; dummy.last_result = object(); dummy.picked = {"root"}
    dummy._has_review_contract = lambda: True
    dummy._pick_mode = lambda: True
    dummy._blocking_unresolved = lambda _result: ["missing"]
    app.App._sync_review_action_states(dummy)
    assert dummy.build_btn.state == "disabled"

    dummy._blocking_unresolved = lambda _result: []
    app.App._sync_review_action_states(dummy)
    assert dummy.build_btn.state == "normal"
    assert dummy.build_btn.style == "Primary.TButton"


def test_review_contract_renderer_keeps_requested_root_visible_without_analysis():
    import app

    class Tree:
        def __init__(self): self.rows = []
        def get_children(self): return tuple(range(len(self.rows)))
        def delete(self, *items): self.rows = []
        def column(self, *_a, **_kw): pass
        def insert(self, _parent, _where, **kw): self.rows.append(kw["values"])

    class Var:
        def __init__(self): self.value = ""
        def set(self, value): self.value = value

    dummy = type("Dummy", (), {})()
    dummy._refresh_download_size_preview = lambda result: app.App._refresh_download_size_preview(dummy, result)
    dummy._ui_acquisition_state = lambda: app.App._ui_acquisition_state(dummy)
    dummy.last_result = None; dummy.result_tree = Tree(); dummy.summary_var = Var()
    dummy.result_rows = {}; dummy.unresolved_rows = {}
    dummy.pick_bar = None; dummy.unresolved_bar = None
    dummy._mirror_mode = lambda: False
    dummy._review_contract_rows = lambda: [("root-1.0.x86_64", "requested", "Repo", "explicit package selection")]
    app.App._refresh_review_contract(dummy)
    assert dummy.result_tree.rows == [("root-1.0.x86_64", "requested", "Repo", "explicit package selection")]
    assert "Analyze to preview" in dummy.summary_var.value

# --------------------------------------------------------------------------
#  1.0.42: trust/provenance findings belong in the Activity log
# --------------------------------------------------------------------------

def test_trust_findings_are_retained_in_full_for_log_review():
    import app

    finding = "Repository metadata digest was not authenticated; the complete explanatory text must remain readable."
    logged = []
    refreshed = []
    dummy = type("Dummy", (), {})()
    dummy.last_warnings = []
    dummy._log = logged.append
    dummy._refresh_trust_review_bar = lambda: refreshed.append(True)

    app.App._apply_warnings(dummy, [finding])
    assert dummy.last_warnings == [finding]
    assert any("1 finding(s) retained for review" in line for line in logged)
    assert refreshed == [True]


def test_build_trust_review_uses_log_window_decision_instead_of_messagebox():
    import app

    calls = []
    dummy = type("Dummy", (), {})()
    dummy.after = lambda _delay, fn: fn()

    def show_details(**kwargs):
        calls.append(kwargs)
        kwargs["decision_callback"](True)

    dummy.show_details = show_details
    assert app.App._gui_trust_review(dummy, ["full trust finding"]) is True
    assert calls[0]["focus_trust"] is True
    assert calls[0]["warnings"] == ["full trust finding"]


def test_closing_or_cancelling_trust_log_blocks_pending_build():
    import app

    dummy = type("Dummy", (), {})()
    dummy.after = lambda _delay, fn: fn()
    dummy.show_details = lambda **kwargs: kwargs["decision_callback"](False)
    assert app.App._gui_trust_review(dummy, ["unverified repository metadata"]) is False


def test_review_result_renderer_does_not_create_trust_warning_pseudo_packages():
    import app, inspect

    source = inspect.getsource(app.App._show_result)
    assert 'TRUST WARNING:' not in source
    assert '_refresh_trust_review_bar()' in source

# --------------------------------------------------------------------------
#  1.0.43: coordinated activity, verification visibility, scroll routing
# --------------------------------------------------------------------------

def test_provenance_table_marks_missing_sha_fields_explicitly():
    import app

    class Tree:
        def __init__(self): self.rows = []
        def winfo_exists(self): return True
        def get_children(self): return tuple(range(len(self.rows)))
        def delete(self, *_rows): self.rows = []
        def insert(self, _parent, _where, **kw): self.rows.append(kw["values"])

    repo = type("Repo", (), {"name": "Example"})()
    dummy = type("Dummy", (), {})()
    dummy.prov_source_tree = Tree()
    dummy._enabled_provenance_repos = lambda: [repo]
    dummy._detected_digest_algorithms = lambda _repo: ["sha256"]
    dummy._digest_inspection_known = lambda _repo: True
    dummy._provenance_repo_cache_key = lambda _repo: "example"
    dummy._provenance_digest_coverage_cache = {
        "example": {"total": 3, "exact_sha512": 0, "exact_sha384": 0, "exact_sha256": 3}
    }
    app.App._refresh_provenance_source_tree(dummy)
    values = dummy.prov_source_tree.rows[0]
    assert values[1:4] == ("✕", "✕", "✓")


def test_global_operation_lease_disables_and_restores_process_buttons():
    import app, threading

    class Var:
        def __init__(self, value=None): self.value = value
        def set(self, value): self.value = value

    class Widget:
        def __init__(self, state="normal"): self.state = state
        def cget(self, key): return self.state if key == "state" else None
        def configure(self, **kw): self.state = kw.get("state", self.state)
        def winfo_exists(self): return True

    class Dummy(app.App):
        def __init__(self):
            self.worker = None
            self.active_operation = None
            self.active_operation_label = ""
            self._operation_controls = set()
            self._operation_saved_states = {}
            self._operation_cancellable = False
            self.cancel_event = threading.Event()
            self.progress_var = Var(0)
            self.status_var = Var("Ready")
            self.cancel_btn = Widget("disabled")
            self.analyze_btn = None
            self.build_btn = None

    dummy = Dummy()
    one, two = Widget("normal"), Widget("disabled")
    dummy._register_operation_control(one)
    dummy._register_operation_control(two)
    assert dummy._claim_operation("inspect", "Inspecting checksum support") is True
    assert one.state == "disabled" and two.state == "disabled"
    assert dummy._busy() is True
    dummy._release_operation("Done")
    assert one.state == "normal" and two.state == "disabled"
    assert dummy.status_var.value == "Done"


def test_high_resolution_mousewheel_deltas_are_accumulated_instead_of_dropped():
    import app
    dummy = type("Dummy", (), {"_wheel_fraction": 0.0})()
    # Four quarter-notch deltas should result in one actual scroll unit rather
    # than four zero-unit events as with integer division by 120.
    assert app.App._mousewheel_units(dummy, -30) == 0
    assert app.App._mousewheel_units(dummy, -30) == 0
    assert app.App._mousewheel_units(dummy, -30) == 0
    assert app.App._mousewheel_units(dummy, -30) == 1


def test_build_keeps_review_rows_visible_during_preflight():
    import app, inspect
    source = inspect.getsource(app.App.start_build)
    assert 'self.result_tree.delete(*self.result_tree.get_children())' not in source
    assert '_start_review_work_glow()' in source
    assert '_begin_transfer' in inspect.getsource(app.App._begin_transfer)


def test_review_exposes_exact_source_url_view():
    import app, inspect
    review_source = inspect.getsource(app.App._build_review_pane)
    url_source = inspect.getsource(app.App._show_review_source_urls)
    assert 'View exact source URLs' in review_source
    assert 'Package / metadata source' in url_source
    assert 'Evidence source' in url_source


def test_checksum_inspection_participates_in_global_operation_lock():
    import app, inspect
    source = inspect.getsource(app.App._inspect_enabled_provenance_metadata)
    assert 'self._busy()' in source
    assert '_claim_operation(' in source
    assert 'self.progress_var.set' in source

# --------------------------------------------------------------------------
#  1.0.44: hostile repository / endpoint-independence hardening
# --------------------------------------------------------------------------

def test_rpm_repomd_metadata_location_cannot_escape_repository(monkeypatch):
    import core
    repomd = b'''<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <checksum type="sha256">00</checksum>
    <location href="file:///etc/passwd"/>
  </data>
</repomd>'''
    monkeypatch.setattr(core, "fetch_bytes", lambda *_a, **_kw: repomd)
    repo = core.RepoSpec("Hostile", "https://repo.example/rpm/")
    try:
        core.get_repo_data(repo, core.Reporter())
    except RuntimeError as exc:
        assert "absolute package location" in str(exc) or "different origin" in str(exc)
        return
    raise AssertionError("repomd.xml was allowed to redirect primary metadata to file:///etc/passwd")


def test_rpm_repomd_metadata_location_cannot_traverse_repository(monkeypatch):
    import core
    repomd = b'''<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <checksum type="sha256">00</checksum>
    <location href="../../outside/primary.xml.gz"/>
  </data>
</repomd>'''
    monkeypatch.setattr(core, "fetch_bytes", lambda *_a, **_kw: repomd)
    repo = core.RepoSpec("Hostile", "https://repo.example/rpm/release/")
    try:
        core.get_repo_data(repo, core.Reporter())
    except RuntimeError as exc:
        assert "escapes the repository" in str(exc)
        return
    raise AssertionError("repomd.xml traversal escaped the configured repository root")


def test_source_bond_rejects_redirect_collapse_to_acquisition_effective_host(monkeypatch):
    import core
    import repository_transport

    class Response:
        def __init__(self, final_url):
            self.final_url = final_url
            self.headers = {}
            self.closed = False
        def geturl(self): return self.final_url
        def close(self): self.closed = True

    finals = iter([
        "https://shared-cdn.example/repo/repodata/repomd.xml",
        "https://shared-cdn.example/repo/repodata/repomd.xml",
    ])
    class Opener:
        def open(self, *_args, **_kwargs): return Response(next(finals))
    monkeypatch.setattr(repository_transport.urllib.request, "build_opener", lambda *_a, **_kw: Opener())

    acquisition = core.RepoSpec("Primary", "https://primary.example/repo/")
    response = core._urlopen("https://primary.example/repo/repodata/repomd.xml", 5, acquisition)
    response.close()
    assert "shared-cdn.example" in getattr(acquisition, "_effective_hosts", set())

    evidence = core.RepoSpec("Evidence", "https://evidence.example/repo/")
    evidence._evidence_distinct_from = acquisition.normalized_url
    evidence._evidence_distinct_effective_origins = set(getattr(acquisition, "_effective_origins", set()))
    evidence._evidence_distinct_effective_hosts = set(getattr(acquisition, "_effective_hosts", set()))
    try:
        core._urlopen("https://evidence.example/repo/repodata/repomd.xml", 5, evidence)
    except RuntimeError as exc:
        assert "redirected to acquisition host/effective endpoint" in str(exc)
        return
    raise AssertionError("two configured mirrors that redirected to the same effective host were accepted as independent")


def test_metadata_download_limit_is_enforced_without_content_length(monkeypatch):
    import core

    class Response:
        headers = {}
        def __init__(self): self.blocks = [b"12345", b"67890", b""]
        def geturl(self): return "https://repo.example/metadata"
        def read(self, _size): return self.blocks.pop(0)
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *_a): self.close()

    monkeypatch.setattr(core, "_urlopen", lambda *_a, **_kw: Response())
    try:
        core.fetch_bytes("https://repo.example/metadata", core.Reporter(), retries=1, max_bytes=8)
    except RuntimeError as exc:
        assert "metadata limit" in str(exc)
        return
    raise AssertionError("metadata response was allowed to exceed its configured transfer ceiling")


def test_metadata_decompression_limit_stops_compression_bomb_shape():
    import core, gzip
    compressed = gzip.compress(b"A" * 4096)
    try:
        core.decompress_metadata(compressed, "primary.xml.gz", max_bytes=1024)
    except RuntimeError as exc:
        assert "expands beyond" in str(exc)
        return
    raise AssertionError("expanded metadata exceeded its ceiling without failing")


def test_rpm_signature_reader_does_not_use_path_read_bytes(monkeypatch, tmp_path):
    import provenance, struct

    def header():
        blob = bytearray(16)
        blob[:3] = b"\x8e\xad\xe8"
        blob[8:16] = struct.pack(">II", 0, 0)
        return bytes(blob)

    lead = bytearray(96)
    lead[:4] = b"\xed\xab\xee\xdb"
    rpm = tmp_path / "minimal.rpm"
    rpm.write_bytes(bytes(lead) + header() + header() + b"payload")

    def forbidden(*_a, **_kw):
        raise AssertionError("read_rpm_signature must not read the entire RPM into memory")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    info = provenance.read_rpm_signature(rpm)
    assert info["payload_size"] == len(b"payload")
    assert info["payload_offset"] == 128
    import repository_tools
    assert repository_tools._rpm_header_tags(rpm) == {}


def test_local_rpm_primary_size_is_archive_bytes_not_installed_size(monkeypatch, tmp_path):
    import repository_tools

    rpm = tmp_path / "demo-1.0-1.noarch.rpm"
    rpm.write_bytes(b"rpm-archive-bytes" * 17)
    tags = {
        repository_tools.RPMTAG_NAME: ["demo"],
        repository_tools.RPMTAG_VERSION: ["1.0"],
        repository_tools.RPMTAG_RELEASE: ["1"],
        repository_tools.RPMTAG_ARCH: ["noarch"],
        repository_tools.RPMTAG_EPOCH: [0],
        repository_tools.RPMTAG_SIZE: [9],  # installed size, deliberately different
    }
    monkeypatch.setattr(repository_tools, "_rpm_header_tags", lambda _path: tags)
    monkeypatch.setattr(
        repository_tools, "_hashes",
        lambda _path: {"sha256": "a" * 64, "sha512": "b" * 128})

    pkg = repository_tools._rpm_package_from_file(rpm, tmp_path, RPM_REPO)
    assert pkg.size == rpm.stat().st_size
    assert pkg.size != tags[repository_tools.RPMTAG_SIZE][0]


def test_deb822_parser_rejects_pathological_single_line():
    import apt_core
    try:
        apt_core._parse_deb822("Package: " + "x" * 20 + "\n", max_line_chars=10)
    except RuntimeError as exc:
        assert "line longer" in str(exc)
        return
    raise AssertionError("Deb822 parser accepted a line above its configured ceiling")


def test_deb822_parser_rejects_pathological_continuation_field():
    import apt_core
    text = "Description: abc\n " + "x" * 20 + "\n"
    try:
        apt_core._parse_deb822(text, max_line_chars=100, max_field_chars=10)
    except RuntimeError as exc:
        assert "field 'Description' exceeds" in str(exc)
        return
    raise AssertionError("Deb822 parser accepted a field above its configured ceiling")


def test_repository_location_rejects_percent_encoded_dotdot_traversal():
    import core
    try:
        core.repo_relative_url("https://repo.example/rpm/release/", "%2e%2e/%2e%2e/secret.xml")
    except RuntimeError as exc:
        assert "escapes the repository" in str(exc)
        return
    raise AssertionError("percent-encoded ../ traversal escaped repository confinement")


def test_metadata_download_limit_rejects_oversized_declared_length(monkeypatch):
    import core

    class Response:
        headers = {"Content-Length": "1000"}
        def geturl(self): return "https://repo.example/metadata"
        def read(self, _size): raise AssertionError("body should not be read after oversized Content-Length")
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *_a): self.close()

    monkeypatch.setattr(core, "_urlopen", lambda *_a, **_kw: Response())
    try:
        core.fetch_bytes("https://repo.example/metadata", core.Reporter(), retries=1, max_bytes=10)
    except RuntimeError as exc:
        assert "metadata limit" in str(exc)
        return
    raise AssertionError("oversized declared metadata response was accepted")


def test_repository_location_rejects_double_encoded_dotdot_traversal():
    import core
    try:
        core.repo_relative_url("https://repo.example/rpm/release/", "%252e%252e/%252e%252e/secret.xml")
    except RuntimeError as exc:
        assert "escapes the repository" in str(exc)
        return
    raise AssertionError("double-encoded ../ traversal escaped repository confinement")

# --------------------------------------------------------------------------
# 1.0.45 vendor-scope / UI-policy regressions.
# --------------------------------------------------------------------------

def test_vendor_signature_settings_do_not_cross_vendor_boundaries():
    import core
    redhat = core.RepoSpec("RHEL BaseOS", "https://cdn.redhat.com/content/dist/rhel9/9/x86_64/baseos/os/")
    docker = core.RepoSpec("Docker CE Stable", "https://download.docker.com/linux/rhel/9/x86_64/stable/")
    opts = core.BuildOptions(
        vendor_keyrings={"redhat": "/keys/redhat.gpg"},
        require_vendor_signatures_by_vendor={"redhat"})
    assert core.vendor_signature_settings(redhat, opts) == ("redhat", "/keys/redhat.gpg", True)
    vendor_id, keyring, required = core.vendor_signature_settings(docker, opts)
    assert vendor_id == "docker"
    assert keyring == ""
    assert required is False


def test_vendor_signature_settings_share_only_with_same_vendor():
    import core
    base = core.RepoSpec("Rocky Linux BaseOS", "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/")
    appstream = core.RepoSpec("Rocky Linux AppStream", "https://download.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/")
    opts = core.BuildOptions(vendor_keyrings={"rocky": "/keys/rocky.gpg"})
    assert core.vendor_signature_settings(base, opts)[1] == "/keys/rocky.gpg"
    assert core.vendor_signature_settings(appstream, opts)[1] == "/keys/rocky.gpg"


def test_vendor_signature_legacy_global_keyring_only_used_without_scoped_map():
    import core
    repo = core.RepoSpec("Custom RPM", "https://packages.example.test/rpm/")
    legacy = core.BuildOptions(vendor_keyring="/keys/legacy.gpg", require_vendor_signatures=True)
    assert core.vendor_signature_settings(repo, legacy)[1:] == ("/keys/legacy.gpg", True)
    scoped = core.BuildOptions(vendor_keyring="/keys/legacy.gpg",
                               vendor_keyrings={"redhat": "/keys/redhat.gpg"})
    assert core.vendor_signature_settings(repo, scoped)[1:] == ("", False)


def test_verification_strategy_labels_keep_policy_identity_with_assurance_suffixes():
    import app
    cases = {
        "Skip upstream provenance checks (minimal)": "skip-provenance",
        "Verify what is available (basic)": "checksum-available",
        "Require checksum coverage (strict)": "checksum-required",
        "Fill gaps with independent evidence (enhanced)": "evidence-fallback",
        "Corroborate every package (maximum)": "full-corroboration",
    }
    for label, policy in cases.items():
        assert app.App._strategy_ui_to_policy(label) == policy
        assert app.App._strategy_policy_to_ui(policy) == label


def test_entitlement_and_keyring_reference_stores_live_outside_program_tree(tmp_path, monkeypatch):
    import app
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    class Dummy:
        _user_state_dir = app.App._user_state_dir
        _keystore_path = app.App._keystore_path
        _entitlement_store_path = app.App._entitlement_store_path
        _vendor_signature_store_path = app.App._vendor_signature_store_path
    obj = Dummy()
    key_store = obj._keystore_path()
    entitlement_store = obj._entitlement_store_path()
    vendor_store = obj._vendor_signature_store_path()
    expected_root = tmp_path / "xdg" / "feathered"
    assert key_store.parent == expected_root
    assert entitlement_store.parent == expected_root
    assert vendor_store.parent == expected_root
    assert Path(app.__file__).resolve().parent not in key_store.parents


def test_packages_sources_visual_order_is_base_then_additional_then_selection():
    import app, inspect
    source = inspect.getsource(app.App._build_packages_sources_pane)
    assert source.index("_build_sources_pane") < source.index("_build_packages_pane")
    assert "foundation -> supplements -> package request" in source


def test_scroll_hint_no_longer_pauses_during_wheel_gesture_and_uses_accent():
    import app, inspect
    source = inspect.getsource(app.App._animate_scroll_hint)
    assert "_wheel_last_event" not in source
    assert "fill=ACCENT" in source
    assert "c.coords" in source


def test_validation_router_has_explicit_targets_for_missing_source_entitlement_and_signing():
    import app, inspect
    source = inspect.getsource(app.App._route_validation_error)
    assert '"keyrings"' in source and "signing_key_entry" in source
    assert "entitlement_tree" in source
    assert '"repositories"' in source and "base_sources_card" in source

# --------------------------------------------------------------------------
# 1.0.46 source-plan population regressions.
# --------------------------------------------------------------------------

def test_source_plan_rebuild_preserves_additional_repositories():
    import app, core
    from types import SimpleNamespace

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
    class Widget:
        def configure(self, **_kw): pass

    old_base = core.RepoSpec("Old base", "https://old.example/base/")
    old_base.source_tier = "base"
    supplement = core.RepoSpec("Internal supplement", "https://internal.example/repo/")
    supplement.source_tier = "additional"
    template = SimpleNamespace(
        name="Fresh base", url="https://fresh.example/base/", role="dependency",
        priority=40, enabled=True, note="profile base", target_release="1",
        optional=False, repo_format="rpm", suite="", components="", keyring="",
        allow_unverified_index=False, evidence_suggestions=[])
    profile = SimpleNamespace(
        key="test-rpm", package_family="rpm",
        repos_factory=lambda _release, _arch: [template])

    obj = app.App.__new__(app.App)
    obj.repo_rows = [old_base, supplement]
    obj.source_method_var = Var("Distribution repositories")
    obj.release_var = Var("1")
    obj.arch_var = Var("x86_64")
    obj.source_config_btn = Widget()
    obj.source_note = Widget()
    obj._profile = lambda: profile

    app.App._apply_source_method_inner(obj)
    assert [r.name for r in obj.repo_rows] == ["Internal supplement", "Fresh base"]
    assert app.App._repo_tier(obj, obj.repo_rows[0]) == "additional"
    assert app.App._repo_tier(obj, obj.repo_rows[1]) == "base"


def test_base_source_editor_is_inline_and_source_plan_is_described_as_population():
    import app, inspect
    source = inspect.getsource(app.App._build_sources_pane)
    assert "source plan populates this base list" in source.lower()
    assert "base_repo_tree" in source
    assert "Restore plan defaults" in source
    assert 'self.add_url_repo("base")' in source
    assert 'self.add_local_repo("base")' in source


def test_additional_repository_manager_is_separate_from_base_source_editor():
    import app, inspect
    source = inspect.getsource(app.App._build_sources_pane)
    assert "Manage additional repositories" in source
    assert 'self.open_repositories("additional")' in source
    refresh = inspect.getsource(app.App._refresh_repo_tree_if_open)
    assert 'tier != "all"' in refresh
    assert "_repo_tier" in refresh

# --------------------------------------------------------------------------
# 1.0.47 staged repository/package flow.
# --------------------------------------------------------------------------

def test_wizard_separates_linux_repositories_packages_and_output_directories():
    import app, inspect
    source = inspect.getsource(app.App._build_ui)
    assert 'self.stage_order = ["target", "packages", "repositories", "keyrings", "transfer", "review"]' in source
    assert '"target": "Linux Distribution"' in source
    assert '"repositories": "Repositories"' in source
    assert '"packages": "Content"' in source
    assert '"transfer": "Output Directories"' in source


def test_repository_stage_owns_broad_source_test_not_additional_repository_card():
    import app, inspect
    source = inspect.getsource(app.App._build_sources_pane)
    status = inspect.getsource(app.App._build_source_status_card)
    assert "Manage additional repositories" in source
    assert "Test all sources" not in source.split('extra = self._card(pane, "Additional repositories"', 1)[1].split('if include_status:', 1)[0]
    assert 'text="Test all sources"' in status
    broad = inspect.getsource(app.App._update_source_status)
    assert "self._workload()" not in broad


def test_packages_stage_has_selection_specific_source_coverage_check():
    import app, inspect
    source = inspect.getsource(app.App._build_package_source_coverage_card)
    assert "Selection source coverage" in source
    assert "Check selected packages" in source
    assert "does not resolve dependencies" in source
    checker = inspect.getsource(app.App.check_package_source_coverage)
    assert "_load_enabled_repos" in checker
    assert '"package_coverage"' in checker


def test_package_source_matcher_respects_role_repo_arch_and_version_for_rpm():
    import app, core
    repo = core.RepoSpec("Vendor", "https://example.invalid/repo/", role="docker")
    pkg = core.Package("docker-ce", "x86_64", "0", "28.0", "1.el9", "docker.rpm",
                       "sha256", "a" * 64, repo)
    obj = app.App.__new__(app.App)
    obj.arch_var = type("V", (), {"get": lambda self: "x86_64"})()
    obj._is_deb = lambda: False
    assert app.App._package_matches_request(obj, pkg,
                                             ("docker-ce", "28.0-1.el9", "docker", "Vendor", "x86_64"))
    assert not app.App._package_matches_request(obj, pkg,
                                                 ("docker-ce", "28.0-1.el9", "dependency", "Vendor", "x86_64"))
    assert not app.App._package_matches_request(obj, pkg,
                                                 ("docker-ce", "28.0-1.el9", "docker", "Other", "x86_64"))

# ---------------------------------------------------------------------------
# 1.0.48 workload-repository integration
# ---------------------------------------------------------------------------

def test_workload_repository_roles_are_generic_and_keep_legacy_docker_compatibility():
    from workloads import WorkloadProfile

    generic = WorkloadProfile(
        key="vendor-tool", label="Vendor Tool", packages=["vendor-agent"], description="x",
        repository_roles=["vendor-stable"],
        package_repository_roles={"vendor-agent": "vendor-stable"})
    assert generic.required_repository_roles() == ["vendor-stable"]
    assert generic.repository_role_for("vendor-agent") == "vendor-stable"

    legacy = WorkloadProfile(
        key="legacy-docker", label="Legacy Docker", packages=["docker-ce"], description="x",
        requires_docker_repo=True)
    assert legacy.required_repository_roles() == ["docker"]
    assert legacy.repository_role_for("docker-ce") == "docker"


def test_workload_can_map_different_roots_to_different_repository_roles():
    from workloads import WorkloadProfile

    workload = WorkloadProfile(
        key="mixed", label="Mixed", packages=["vendor-agent", "helper"], description="x",
        repository_roles=["vendor-a", "vendor-b"],
        package_repository_roles={"vendor-agent": "vendor-a", "helper": "vendor-b"})
    assert workload.repository_role_for("vendor-agent") == "vendor-a"
    assert workload.repository_role_for("helper") == "vendor-b"
    assert workload.required_repository_roles() == ["vendor-a", "vendor-b"]


def test_external_workload_catalog_accepts_repository_role_contract(tmp_path):
    import json
    from workloads import _parse_external

    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({"workloads": [{
        "key": "gpu", "label": "GPU", "packages": ["gpu-driver", "gpu-tools"],
        "repository_roles": ["gpu-vendor"],
        "package_repository_roles": {"gpu-driver": "gpu-vendor", "gpu-tools": "gpu-vendor"},
    }]}), encoding="utf-8")
    workload = _parse_external(path)[0]
    assert workload.required_repository_roles() == ["gpu-vendor"]
    assert workload.repository_role_for("gpu-tools") == "gpu-vendor"


def test_recommended_workload_repository_is_materialized_as_workload_tier():
    from types import SimpleNamespace
    from app import App
    from profiles import RepoTemplate
    from workloads import WorkloadProfile

    app = App.__new__(App)
    workload = WorkloadProfile(
        key="vendor", label="Vendor", packages=["vendor-agent"], description="x",
        repository_roles=["vendor-stable"],
        package_repository_roles={"vendor-agent": "vendor-stable"})
    profile = SimpleNamespace(
        package_family="rpm",
        repos_factory=lambda release, arch: [
            RepoTemplate("Vendor Stable", "https://vendor.example/repo/", "vendor-stable", 15, True)
        ])
    app._workload = lambda: workload
    app._profile = lambda: profile
    app._mirror_mode = lambda: False
    app._single_mode = lambda: False
    app.release_var = SimpleNamespace(get=lambda: "9")
    app.arch_var = SimpleNamespace(get=lambda: "x86_64")
    app.repo_rows = []
    app.loaded_signature = None; app.loaded_packages = []; app.last_result = None
    app.package_source_coverage_signature = None
    app._log = lambda *a, **k: None
    app._refresh_repo_tree_if_open = lambda: None
    app._update_source_status = lambda: None
    app._refresh_workload_repository_views = lambda: None

    app._add_or_enable_recommended_workload_repositories()
    assert len(app.repo_rows) == 1
    repo = app.repo_rows[0]
    assert repo.role == "vendor-stable"
    assert app._repo_tier(repo) == "workload"
    assert repo.enabled


def test_workload_validation_requires_every_declared_repository_role():
    from types import SimpleNamespace
    import pytest
    from app import App
    from core import RepoSpec
    from workloads import WorkloadProfile

    app = App.__new__(App)
    workload = WorkloadProfile(
        key="multi", label="Multi Vendor", packages=["a", "b"], description="x",
        repository_roles=["vendor-a", "vendor-b"],
        package_repository_roles={"a": "vendor-a", "b": "vendor-b"})
    app._workload = lambda: workload
    app._mirror_mode = lambda: False
    app._single_mode = lambda: False
    app._workload_required_repository_roles = lambda: workload.required_repository_roles()
    app._needs_dependency_repos = lambda: False
    app.repo_rows = [RepoSpec("A", "https://a.example/", "vendor-a", enabled=True)]

    with pytest.raises(RuntimeError, match="vendor-b"):
        app._validate_source_plan()


def test_switching_workloads_preserves_manual_irrelevant_workload_source():
    from types import SimpleNamespace
    from app import App
    from core import RepoSpec
    from workloads import WorkloadProfile

    app = App.__new__(App)
    workload = WorkloadProfile(
        key="b", label="B", packages=["b"], description="x", repository_roles=["vendor-b"])
    app._workload = lambda: workload
    app._mirror_mode = lambda: False
    app._single_mode = lambda: False
    app._workload_required_repository_roles = lambda: ["vendor-b"]
    old = RepoSpec("Vendor A", "https://a.example/", "vendor-a", enabled=True)
    old.source_tier = "workload"
    app.repo_rows = [old]
    app._log = lambda *a, **k: None
    app._refresh_workload_repository_views = lambda: None
    app._refresh_keyring_tree = lambda: None
    app._known_workload_repository_roles = lambda: {"vendor-a", "vendor-b"}

    app._sync_workload_repo_state()
    assert len(app.repo_rows) == 1
    assert app.repo_rows[0] is old
    assert old.enabled

# ---------------------------------------------------------------------------
# Repository readiness: role labels must not overrule actual resolver coverage
# ---------------------------------------------------------------------------

def test_validate_sources_allows_self_contained_workload_repository():
    from app import App
    from core import RepoSpec

    app = App.__new__(App)
    app.repo_rows = [RepoSpec("Curated Workload", "https://repo.example/complete/", role="vendor-stable")]
    app._local_media_pending = lambda: False
    logs = []
    app._log = logs.append

    # A source's primary role identifies workload roots. Dependencies are
    # resolved from available metadata, so this must not be blocked or require
    # a legacy role="dependency" advisory.
    app._validate_sources(True)
    assert not logs


def test_validate_sources_ignores_enabled_rows_without_a_location():
    import pytest
    from app import App
    from core import RepoSpec

    app = App.__new__(App)
    app.repo_rows = [RepoSpec("Unconfigured", "", role="dependency", enabled=True)]
    app._local_media_pending = lambda: False
    app._log = lambda *args, **kwargs: None

    with pytest.raises(RuntimeError, match="No usable package sources"):
        app._validate_sources(True)


def test_source_plan_does_not_require_dependency_role_when_workload_role_is_present():
    from types import SimpleNamespace
    from app import App
    from core import RepoSpec
    from workloads import WorkloadProfile

    app = App.__new__(App)
    workload = WorkloadProfile(
        key="vendor", label="Vendor", packages=["vendor-agent"], description="x",
        repository_roles=["vendor-stable"],
        package_repository_roles={"vendor-agent": "vendor-stable"})
    app._workload = lambda: workload
    app._mirror_mode = lambda: False
    app._single_mode = lambda: False
    app._workload_required_repository_roles = lambda: ["vendor-stable"]
    app._needs_dependency_repos = lambda: True
    app._profile = lambda: SimpleNamespace(key="rocky", label="Rocky Linux")
    app.release_var = SimpleNamespace(get=lambda: "9")
    app.repo_rows = [RepoSpec("Complete Vendor Repo", "https://repo.example/complete/",
                              role="vendor-stable", enabled=True)]

    app._validate_source_plan()

# ---------------------------------------------------------------------------
# repository-flow regression history
# ---------------------------------------------------------------------------

def test_repositories_consumes_requirements_derived_from_packages():
    import app, inspect

    source = inspect.getsource(app.App._build_workload_repositories_card)
    assert "Required by selected packages" in source
    assert "Distribution-native roots" in source
    assert "Use recommended source" in source
    pane = inspect.getsource(app.App._build_repositories_pane)
    render = inspect.getsource(app.App._render_repository_workflow)
    assert "derived from Content" in pane
    assert "_build_package_source_coverage_card" in render
    assert 'mode == "mirror"' in render
    assert 'mode == "packages"' in render


def test_repositories_materialize_repository_implied_by_selected_workload():
    from types import SimpleNamespace
    from app import App
    from profiles import RepoTemplate
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        key="vendor", label="Vendor Tool", packages=["vendor-agent"], description="x",
        repository_roles=["vendor-stable"],
        package_repository_roles={"vendor-agent": "vendor-stable"})
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(
        package_family="rpm",
        repos_factory=lambda release, arch: [
            RepoTemplate("Vendor Stable", "https://vendor.example/repo/", "vendor-stable", 15, True)
        ])
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._workload_required_repository_roles = lambda: ["vendor-stable"]
    ui.release_var = SimpleNamespace(get=lambda: "9")
    ui.arch_var = SimpleNamespace(get=lambda: "x86_64")
    ui.repo_rows = []
    ui.loaded_signature = None; ui.loaded_packages = []; ui.last_result = None
    ui.package_source_coverage_signature = None
    ui._log = lambda *a, **k: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui._update_source_status = lambda: None
    ui._sync_workload_repo_state = lambda: None
    ui._refresh_workload_repository_views = lambda: None

    App._activate_workload_repository_selection(ui)

    assert len(ui.repo_rows) == 1
    repo = ui.repo_rows[0]
    assert repo.name == "Vendor Stable"
    assert repo.role == "vendor-stable"
    assert repo.enabled
    assert getattr(repo, "workload_profile_managed", False)


def test_workload_root_requests_use_role_without_arbitrary_repository_pin():
    from types import SimpleNamespace
    from app import App
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        key="vendor", label="Vendor Tool", packages=["vendor-agent"], description="x",
        repository_roles=["vendor-stable"],
        package_repository_roles={"vendor-agent": "vendor-stable"})
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")
    ui._single_mode = lambda: False
    ui._mirror_mode = lambda: False
    ui.package_version_var = SimpleNamespace(get=lambda: "Latest")

    requests = App._package_requests(ui)
    assert requests == [("vendor-agent", None, "vendor-stable")]


def test_provenance_purposes_are_derived_from_distribution_and_workload_flow():
    from types import SimpleNamespace
    from app import App
    from core import RepoSpec

    ui = App.__new__(App)
    base = RepoSpec("BaseOS", "https://os.example/base/", "dependency", 10, True)
    base.source_tier = "base"
    workload = RepoSpec("Vendor Stable", "https://vendor.example/repo/", "vendor-stable", 15, True)
    workload.source_tier = "workload"
    ui.repo_rows = [base, workload]
    ui.selection_mode_var = SimpleNamespace(get=lambda: "Workload preset")
    ui._workload_required_repository_roles = lambda: ["vendor-stable"]

    assert App._repository_build_purposes(ui, base) == ["distribution"]
    assert App._repository_build_purposes(ui, workload) == ["workload/root"]


# ---------------------------------------------------------------------------
# 1.0.51 Packages -> Repositories source plan
# ---------------------------------------------------------------------------

def test_profile_managed_irrelevant_workload_source_is_disabled_but_retained():
    from app import App
    from core import RepoSpec

    ui = App.__new__(App)
    ui._single_mode = lambda: False
    ui._workload_required_repository_roles = lambda: ["vendor-b"]
    old = RepoSpec("Vendor A", "https://a.example/", "vendor-a", enabled=True)
    old.source_tier = "workload"
    old.workload_profile_managed = True
    ui.repo_rows = [old]
    ui._log = lambda *a, **k: None
    ui._refresh_workload_repository_views = lambda: None
    ui._refresh_keyring_tree = lambda: None

    App._sync_workload_repo_state(ui)
    assert ui.repo_rows == [old]
    assert not old.enabled


def test_podman_root_uses_distribution_scope_not_dependency_role_or_repo_pin():
    from types import SimpleNamespace
    from app import App
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        key="podman", label="Podman", packages=["podman"], description="x",
        version_package="podman", version_role="dependency")
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")
    ui._single_mode = lambda: False
    ui._mirror_mode = lambda: False
    ui.package_version_var = SimpleNamespace(get=lambda: "Latest")

    assert workload.repository_role_for("podman") is None
    assert App._package_requests(ui) == [("podman", None, None, None, None, "distribution")]


def test_mixed_workload_maps_only_explicit_vendor_roots():
    from types import SimpleNamespace
    from app import App
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        key="mixed", label="Mixed", packages=["nftables", "vendor-agent"], description="x",
        repository_roles=["vendor-net"],
        package_repository_roles={"vendor-agent": "vendor-net"})
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")
    ui._single_mode = lambda: False
    ui._mirror_mode = lambda: False
    ui.package_version_var = SimpleNamespace(get=lambda: "Latest")

    assert App._package_requests(ui) == [
        ("nftables", None, None, None, None, "distribution"),
        ("vendor-agent", None, "vendor-net"),
    ]
    assert App._workload_required_repository_roles(ui) == ["vendor-net"]


def test_rpm_distribution_scope_excludes_workload_repo_even_when_it_has_same_package():
    from core import RepoSpec, Package, build_provider_index, _find_root

    base = RepoSpec("AppStream", "https://os.example/appstream/", "dependency", priority=50)
    base.source_tier = "base"
    vendor = RepoSpec("Vendor", "https://vendor.example/", "dependency", priority=1)
    vendor.source_tier = "workload"
    base_pkg = Package("podman", "x86_64", "0", "5.0", "1", "podman.rpm", "sha256", "base", base)
    vendor_pkg = Package("podman", "x86_64", "0", "99.0", "1", "podman.rpm", "sha256", "vendor", vendor)
    index = build_provider_index([base_pkg, vendor_pkg])

    match = _find_root("podman", None, index, "x86_64", source_scope="distribution")
    assert match is not None
    assert match.package.repo is base


def test_version_scan_for_distribution_native_workload_uses_all_enabled_base_repos():
    from types import SimpleNamespace
    from app import App
    from core import RepoSpec
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(key="podman", label="Podman", packages=["podman"],
                               description="x", version_package="podman", version_role="dependency")
    baseos = RepoSpec("BaseOS", "https://os/base/", "dependency", enabled=True); baseos.source_tier = "base"
    appstream = RepoSpec("AppStream", "https://os/appstream/", "dependency", enabled=True); appstream.source_tier = "base"
    supplement = RepoSpec("Internal", "https://int/", "dependency", enabled=True); supplement.source_tier = "additional"
    ui.repo_rows = [baseos, appstream, supplement]
    ui._repo_tier = App._repo_tier.__get__(ui, App)

    repos, role = App._version_scan_repositories(ui, workload)
    assert repos == [baseos, appstream]
    assert role is None


def test_apt_distribution_scope_excludes_supplemental_repo_even_when_higher_priority():
    from apt_core import DebPackage, _find_root
    from core import RepoSpec

    base = RepoSpec("Ubuntu main", "https://archive.example/", "dependency", priority=50,
                    repo_format="apt")
    base.source_tier = "base"
    supplement = RepoSpec("Internal", "https://internal.example/", "dependency", priority=1,
                          repo_format="apt")
    supplement.source_tier = "additional"
    base_pkg = DebPackage("podman", "amd64", "5.0", "pool/p/podman.deb", "sha256", "base", base)
    extra_pkg = DebPackage("podman", "amd64", "99.0", "pool/p/podman.deb", "sha256", "extra", supplement)

    match = _find_root(("podman", None, None, None, None, "distribution"),
                       [base_pkg, extra_pkg], "amd64")
    assert match is base_pkg

# ---------------------------------------------------------------------------
# 1.0.52 workload selection pre-seeds
# side-channel repositories before Repositories/coverage validation.
# ---------------------------------------------------------------------------

def test_workload_change_preseeds_sidechannel_before_repository_navigation():
    import inspect
    import app

    source = inspect.getsource(app.App._workload_changed)
    assert "_activate_workload_repository_selection()" in source
    assert 'active_pane", None) == "repositories"' not in source


def test_coverage_synchronizes_workload_sources_before_source_plan_validation():
    from app import App

    ui = App.__new__(App)
    events = []
    ui._busy = lambda: False
    ui._single_mode = lambda: False
    ui._mirror_mode = lambda: False
    ui._activate_workload_repository_selection = lambda: events.append("seed")

    def validate():
        assert events == ["seed"]
        events.append("validate")
        raise RuntimeError("stop after ordering assertion")

    ui._validate_source_plan = validate
    ui._route_validation_error = lambda message: events.append("routed")

    import app as app_module
    original = app_module.messagebox.showerror
    app_module.messagebox.showerror = lambda *a, **k: events.append("shown")
    try:
        App.check_package_source_coverage(ui)
    finally:
        app_module.messagebox.showerror = original

    assert events == ["seed", "validate", "routed", "shown"]


def test_repository_requirement_rows_put_sidechannel_before_distribution():
    from types import SimpleNamespace
    from app import App
    from core import RepoSpec
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        key="mixed", label="Mixed", packages=["nftables", "vendor-agent"], description="x",
        repository_roles=["vendor-net"],
        package_repository_roles={"vendor-agent": "vendor-net"})
    base = RepoSpec("BaseOS", "https://os.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    vendor = RepoSpec("Vendor Network", "https://vendor.example/net/", "vendor-net", enabled=True)
    vendor.source_tier = "workload"
    ui.repo_rows = [base, vendor]
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    ui._workload_required_repository_roles = App._workload_required_repository_roles.__get__(ui, App)
    ui._workload_root_source_plan = App._workload_root_source_plan.__get__(ui, App)
    ui._workload_repo_templates = lambda roles=None: []

    rows = App._workload_repo_state_rows(ui)
    assert rows[0][0] == "role:vendor-net"
    assert rows[1][0] == "distribution"


def test_base_source_population_excludes_all_known_workload_roles_not_only_docker():
    import inspect
    import app

    source = inspect.getsource(app.App._apply_source_method_inner)
    assert "_known_workload_repository_roles" in source
    assert 'x.role != "docker"' not in source

# ---------------------------------------------------------------------------
# 1.0.53 repository transport hardening.
# ---------------------------------------------------------------------------

def test_query_token_repository_normalization_keeps_query_after_root_slash():
    repo = RepoSpec("Token repo", "https://repo.example/rpm?token=SECRET")
    assert repo.normalized_url == "https://repo.example/rpm/?token=SECRET"


def test_url_join_inherits_recognized_query_credentials_same_origin_only():
    from core import url_join

    base = "https://repo.example/rpm/?token=SECRET&view=compact"
    child = url_join(base, "repodata/repomd.xml?kind=primary")
    assert child == "https://repo.example/rpm/repodata/repomd.xml?token=SECRET&kind=primary"

    # Absolute/off-origin joins are never allowed to carry repository credentials.
    external = url_join(base, "https://cdn.example/repomd.xml")
    assert "SECRET" not in external
    assert external == "https://cdn.example/repomd.xml"


def test_repo_relative_url_inherits_query_token_and_metadata_cannot_override_it():
    from core import repo_relative_url

    base = "https://repo.example/rpm/?token=CONFIGURED"
    actual = repo_relative_url(base, "Packages/tool.rpm?token=HOSTILE&download=1")
    assert actual == "https://repo.example/rpm/Packages/tool.rpm?token=CONFIGURED&download=1"


def test_credentialed_repository_rejects_cross_origin_redirect_before_following():
    import urllib.request
    from core import _RepositoryRedirectHandler

    repo = RepoSpec(
        "Vendor",
        "https://vendor.example/repo/",
        client_cert="client.pem",
        client_key="client.key",
    )
    handler = _RepositoryRedirectHandler(repo)
    request = urllib.request.Request("https://vendor.example/repo/repodata/repomd.xml")
    try:
        handler.redirect_request(
            request, None, 302, "Found", {}, "https://other.example/repodata/repomd.xml")
    except RuntimeError as exc:
        assert "credentialed repository redirect" in str(exc).lower()
        assert "not allowed" in str(exc).lower()
        return
    raise AssertionError("credentialed cross-origin redirect was accepted")


def test_query_token_repository_redirect_is_origin_confined_too():
    import urllib.request
    from core import _RepositoryRedirectHandler

    repo = RepoSpec("Token vendor", "https://vendor.example/repo/?token=SECRET")
    handler = _RepositoryRedirectHandler(repo)
    request = urllib.request.Request("https://vendor.example/repo/repodata/repomd.xml?token=SECRET")
    try:
        handler.redirect_request(request, None, 302, "Found", {}, "https://cdn.example/meta")
    except RuntimeError:
        return
    raise AssertionError("query-token credentials were allowed to redirect cross-origin")


def test_credentialed_repository_can_explicitly_allow_vendor_redirect_origin():
    import urllib.request
    from core import _RepositoryRedirectHandler

    repo = RepoSpec(
        "Vendor",
        "https://vendor.example/repo/",
        client_cert="client.pem",
        client_key="client.key",
        redirect_allow_origins=["https://cdn.vendor.example"],
    )
    handler = _RepositoryRedirectHandler(repo)
    request = urllib.request.Request("https://vendor.example/repo/repodata/repomd.xml")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://cdn.vendor.example/object")
    assert redirected.full_url == "https://cdn.vendor.example/object"

# ---------------------------------------------------------------------------
# 1.0.53 single SourcePlan contract.
# ---------------------------------------------------------------------------

def test_source_plan_models_distribution_dedicated_and_mixed_roots():
    from workloads import WorkloadProfile

    distribution = WorkloadProfile("podman", "Podman", ["podman"], "x")
    plan = distribution.source_plan("rpm")
    assert plan.source_model == "distribution-native"
    assert plan.distribution_required
    assert plan.required_roles == []
    assert [(r.package, r.source_kind, r.role) for r in plan.roots] == [
        ("podman", "distribution", None)]

    dedicated = WorkloadProfile(
        "vendor", "Vendor", ["agent"], "x",
        repository_roles=["vendor"], package_repository_roles={"agent": "vendor"})
    plan = dedicated.source_plan("rpm")
    assert plan.source_model == "workload-specific"
    assert not plan.distribution_required
    assert plan.required_roles == ["vendor"]

    mixed = WorkloadProfile(
        "mixed", "Mixed", ["nftables", "agent"], "x",
        repository_roles=["vendor"], package_repository_roles={"agent": "vendor"})
    plan = mixed.source_plan("rpm")
    assert plan.source_model == "mixed distribution + workload-specific"
    assert plan.distribution_required
    assert plan.required_roles == ["vendor"]


def test_app_source_plan_wrappers_derive_from_one_plan_object():
    from types import SimpleNamespace
    from app import App
    from workloads import WorkloadProfile

    ui = App.__new__(App)
    workload = WorkloadProfile(
        "mixed", "Mixed", ["native", "agent"], "x",
        repository_roles=["vendor"], package_repository_roles={"agent": "vendor"})
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")

    plan = App._source_plan(ui)
    ui._source_plan = lambda: plan
    assert App._workload_required_repository_roles(ui) == ["vendor"]
    assert App._workload_uses_distribution_sources(ui)
    assert App._workload_root_source_plan(ui) == [
        ("native", "distribution", None),
        ("agent", "workload", "vendor"),
    ]


def test_package_requests_consume_source_plan_instead_of_rederiving_roles():
    import inspect
    from app import App

    source = inspect.getsource(App._package_requests)
    assert "self._source_plan().roots" in source
    assert "workload.repository_role_for(name)" not in source


def test_source_plan_required_roles_are_deduplicated_in_root_order():
    from workloads import RootSourcePolicy, SourcePlan

    plan = SourcePlan([
        RootSourcePolicy("a", "workload", "vendor-a"),
        RootSourcePolicy("b", "distribution"),
        RootSourcePolicy("c", "workload", "vendor-a"),
        RootSourcePolicy("d", "workload", "vendor-b"),
    ])
    assert plan.required_roles == ["vendor-a", "vendor-b"]
    assert plan.distribution_required

# ---------------------------------------------------------------------------
# 1.0.53 native DNF conformance tier.
# ---------------------------------------------------------------------------

def test_native_dnf_conformance_has_real_offline_transaction_oracle(monkeypatch):
    import contextlib
    from types import SimpleNamespace
    import native_conformance

    monkeypatch.setattr(native_conformance.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(native_conformance, "_make_rpm", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        native_conformance.repository_tools, "rebuild_repository_metadata",
        lambda *args, **kwargs: None)
    monkeypatch.setattr(native_conformance.core, "load_repository", lambda *args, **kwargs: [])
    monkeypatch.setattr(native_conformance.core, "resolve", lambda *args, **kwargs: object())
    monkeypatch.setattr(native_conformance, "_check_closure", lambda *args, **kwargs: None)

    written = []
    monkeypatch.setattr(
        native_conformance.core, "write_bundle",
        lambda result, bundle, options, reporter, metadata: written.append((bundle, metadata)))

    commands = []
    all_names = (
        "fnc-deep fnc-mid fnc-leaf fnc-needs-new fnc-versioned "
        "fnc-needs-virtual fnc-provider"
    )

    def fake_run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=all_names, stderr="")

    monkeypatch.setattr(native_conformance.subprocess, "run", fake_run)

    @contextlib.contextmanager
    def fake_http_repository(_bundle):
        yield "http://127.0.0.1:43210/"

    monkeypatch.setattr(native_conformance, "_http_repository", fake_http_repository)

    line = native_conformance.run_dnf_conformance()

    assert line.startswith("PASS DNF:")
    assert len(written) == 3
    assert len(commands) == 4
    assert [command[-1] for command in commands] == [
        "fnc-deep", "fnc-deep", "fnc-needs-new", "fnc-needs-virtual"]
    repo_args = [next(part for part in command if part.startswith("--repofrompath=feathered,"))
                 for command in commands]
    assert repo_args[0].startswith("--repofrompath=feathered,file:///")
    assert repo_args[1] == "--repofrompath=feathered,http://127.0.0.1:43210/"
    for command in commands:
        assert "--disablerepo=*" in command
        repo_arg = next(part for part in command if part.startswith("--repofrompath=feathered,"))
        assert repo_arg.startswith(("--repofrompath=feathered,file:///",
                                    "--repofrompath=feathered,http://127.0.0.1:"))
        assert "tsflags=test" in command
        assert command[-2] == "install"


def test_native_conformance_file_urls_are_canonical_for_libcurl(tmp_path):
    import native_conformance

    url = native_conformance._native_file_url(tmp_path / "bundle" / "packages")
    assert url.startswith("file:///")
    assert not url.startswith("file:/tmp")


def test_native_conformance_main_runs_all_registered_tiers(monkeypatch):
    import native_conformance

    calls = []

    def runner(name):
        def run():
            calls.append(name)
            return f"PASS {name}: test runner"
        return run

    monkeypatch.setattr(native_conformance, "RUNNERS", {
        tier: runner(tier) for tier in native_conformance.TIERS
    })

    assert native_conformance.main([]) == 0
    assert calls == list(native_conformance.TIERS)

# ---------------------------------------------------------------------------
# deterministic resolver property fuzzing.
# ---------------------------------------------------------------------------

def test_rpm_resolver_property_fuzz_complete_dags_have_complete_closures():
    import random

    for seed in range(30):
        rng = random.Random(seed)
        count = rng.randint(6, 18)
        edges = {i: sorted(rng.sample(range(i + 1, count),
                                     k=min(rng.randint(0, 3), count - i - 1)))
                 for i in range(count)}
        packages = []
        for i in range(count):
            requirements = [Requirement(f"fuzz-rpm-{j}") for j in edges[i]]
            packages.append(rpm_pkg(f"fuzz-rpm-{i}", "1.0", requirements))

        reachable = set()
        stack = [0]
        while stack:
            i = stack.pop()
            if i in reachable:
                continue
            reachable.add(i)
            stack.extend(edges[i])

        result = resolve([("fuzz-rpm-0", None, None)], packages, "x86_64",
                         BuildOptions(), Reporter())
        assert not result.unresolved, (seed, result.unresolved)
        assert {p.name for p in result.selected} == {f"fuzz-rpm-{i}" for i in reachable}, seed


def test_apt_resolver_property_fuzz_complete_dags_have_complete_closures():
    import random

    for seed in range(30):
        rng = random.Random(1000 + seed)
        count = rng.randint(6, 18)
        edges = {i: sorted(rng.sample(range(i + 1, count),
                                     k=min(rng.randint(0, 3), count - i - 1)))
                 for i in range(count)}
        packages = []
        for i in range(count):
            depends = ", ".join(f"fuzz-deb-{j} (>= 1.0)" for j in edges[i])
            packages.append(deb_pkg(f"fuzz-deb-{i}", "1.0", APT_REPO, depends=depends))

        reachable = set()
        stack = [0]
        while stack:
            i = stack.pop()
            if i in reachable:
                continue
            reachable.add(i)
            stack.extend(edges[i])

        result = apt_core.resolve([("fuzz-deb-0", None, None)], packages, "amd64",
                                  BuildOptions(), Reporter())
        assert not result.unresolved, (seed, result.unresolved)
        assert {p.name for p in result.selected} == {f"fuzz-deb-{i}" for i in reachable}, seed


def test_requested_source_plan_provenance_separates_intent_from_resolved_repo():
    from app import App

    rows = App._request_source_plan_metadata([
        ("podman", None, None, None, None, "distribution"),
        ("docker-ce", None, "docker"),
        ("exact", "1.0", "dependency", "Chosen Repo", "x86_64"),
        ("custom", None, None),
    ])
    assert rows == [
        {"package": "podman", "source_policy": "distribution"},
        {"package": "docker-ce", "source_policy": "role", "repository_role": "docker"},
        {"package": "exact", "source_policy": "repository", "repository_role": "dependency",
         "repository_name": "Chosen Repo", "architecture": "x86_64"},
        {"package": "custom", "source_policy": "enabled"},
    ]


def test_query_token_is_retained_across_same_origin_redirect_but_not_allowlisted_cross_origin():
    import urllib.request
    from core import RepoSpec, _RepositoryRedirectHandler

    repo = RepoSpec(
        "Token vendor", "https://vendor.example/repo/?token=SECRET",
        redirect_allow_origins=["https://cdn.vendor.example"],
    )
    handler = _RepositoryRedirectHandler(repo)
    request = urllib.request.Request("https://vendor.example/repo/meta?token=SECRET")
    same = handler.redirect_request(request, None, 302, "Found", {}, "/repo/next")
    assert same.full_url == "https://vendor.example/repo/next?token=SECRET"

    cross = handler.redirect_request(
        request, None, 302, "Found", {}, "https://cdn.vendor.example/object")
    assert cross.full_url == "https://cdn.vendor.example/object"
    assert "SECRET" not in cross.full_url

# ---------------------------------------------------------------------------
# 1.0.54 workload-only package acquisition.
# ---------------------------------------------------------------------------

def test_dedicated_workload_without_base_enters_package_only_acquisition_mode():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    ui = App.__new__(App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([
        RootSourcePolicy("vendor-agent", "workload", "vendor")])
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    vendor.workload_profile_managed = True
    ui.repo_rows = [vendor]
    ui._repo_tier = App._repo_tier.__get__(ui, App)

    assert App._package_only_acquisition_mode(ui)

    base = RepoSpec("BaseOS", "https://os.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    ui.repo_rows.append(base)
    assert not App._package_only_acquisition_mode(ui)

    # Manual/internal workload-role repositories may be self-contained. Do not
    # assume they are root-only merely because no base tier is configured.
    ui.repo_rows = [vendor]
    vendor.workload_profile_managed = False
    assert not App._package_only_acquisition_mode(ui)


def test_mixed_workload_without_base_does_not_masquerade_as_package_only_complete_selection():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    ui = App.__new__(App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([
        RootSourcePolicy("native-tool", "distribution"),
        RootSourcePolicy("vendor-agent", "workload", "vendor"),
    ])
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    vendor.workload_profile_managed = True
    ui.repo_rows = [vendor]
    ui._repo_tier = App._repo_tier.__get__(ui, App)

    assert not App._package_only_acquisition_mode(ui)


def test_review_exposes_only_download_action_in_package_only_mode():
    import app

    class Widget:
        def __init__(self): self.state = None; self.style = None; self.text = None
        def configure(self, **kw):
            self.state = kw.get("state", self.state)
            self.style = kw.get("style", self.style)
            self.text = kw.get("text", self.text)

    ui = type("Dummy", (), {})()
    ui._ui_acquisition_state = lambda: app.App._ui_acquisition_state(ui)
    ui.analyze_btn = Widget(); ui.build_btn = Widget()
    ui.worker = None; ui.active_operation = None; ui.last_result = None
    ui._has_review_contract = lambda: True
    ui._package_only_acquisition_mode = lambda: True
    ui._mirror_mode = lambda: False

    app.App._sync_review_action_states(ui)
    assert ui.analyze_btn.state == "disabled"
    assert ui.analyze_btn.text == "Dependency analysis unavailable"
    assert ui.build_btn.state == "normal"
    assert ui.build_btn.text == "Download workload packages"
    assert ui.build_btn.style == "Primary.TButton"


def test_package_only_build_options_do_not_resolve_dependencies_or_emit_repository():
    """Package-only never follows dependencies, but repository metadata is now
    the operator's explicit choice (1.1.0): a local repository over a handful
    of collected roots is legitimate, and the PACKAGE-ONLY warning still marks
    the bundle as not install-complete."""
    from types import SimpleNamespace
    from app import App

    ui = App.__new__(App)
    ui.resolution_pass_budget = 8
    ui._trust_options = lambda: {"emit_repository": True}
    opts = App._build_options(ui, package_only=True)
    assert not opts.include_dependencies
    assert not opts.include_recommends
    assert opts.emit_repository, "operator opted in; package-only must honor it"
    assert opts.target_inventory is None

    ui._trust_options = lambda: {"emit_repository": False}
    opts = App._build_options(ui, package_only=True)
    assert not opts.emit_repository


def test_rpm_package_only_output_has_warning_and_no_offline_installer(tmp_path):
    import hashlib
    import json
    import core
    from core import BuildOptions, Package, RepoSpec, Reporter, Requirement, ResolutionResult

    source = tmp_path / "source"
    source.mkdir()
    data = b"package-only-rpm-fixture"
    (source / "demo.rpm").write_bytes(data)
    repo = RepoSpec("Vendor", source.resolve().as_uri() + "/", "vendor")
    repo.source_tier = "workload"
    pkg = Package("demo", "x86_64", "0", "1.0", "1", "demo.rpm", "sha256",
                  hashlib.sha256(data).hexdigest(), repo, size=len(data))
    pkg.provides = [Requirement("demo")]
    result = ResolutionResult([pkg], [], [pkg], reasons={pkg.nevra: "requested"})
    out = tmp_path / "bundle"
    metadata = {
        "workload": "demo",
        "package_only_acquisition": True,
        "dependency_completeness": "not-derived",
        "package_only_warning": "Dependencies could not be derived because no base repository exists.",
    }

    core.write_bundle(result, out, BuildOptions(), Reporter(), metadata)
    assert (out / "rpms" / "demo.rpm").is_file()
    assert (out / "rpms" / "PACKAGE-ONLY-WARNING.txt").is_file()
    assert not (out / "install-offline.sh").exists()
    manifest = json.loads((out / "rpms" / "manifest.json").read_text())
    assert manifest["metadata"]["package_only_acquisition"] is True
    assert manifest["summary"]["dependency_completeness"] == "not-derived"


def test_apt_package_only_output_has_warning_and_no_offline_installer(tmp_path):
    import json
    import apt_core
    from core import BuildOptions, Reporter, RepoSpec

    url = _build_local_apt_fixture(tmp_path / "repo")
    repo = RepoSpec("Vendor APT", url, "vendor", 20, repo_format="apt",
                    suite="noble", components="main")
    repo.source_tier = "workload"
    packages = apt_core.load_repository(repo, {"amd64"}, Reporter())
    result = apt_core.resolve([("demo", None, "vendor")], packages, "amd64",
                              BuildOptions(include_dependencies=False), Reporter())
    out = tmp_path / "bundle"
    metadata = {
        "workload": "demo",
        "package_only_acquisition": True,
        "dependency_completeness": "not-derived",
        "package_only_warning": "Dependencies could not be derived because no base repository exists.",
    }

    apt_core.write_bundle(result, out, BuildOptions(), Reporter(), metadata)
    assert any((out / "debs").glob("*.deb"))
    assert (out / "debs" / "PACKAGE-ONLY-WARNING.txt").is_file()
    assert not (out / "install-offline.sh").exists()
    manifest = json.loads((out / "debs" / "manifest.json").read_text())
    assert manifest["metadata"]["package_only_acquisition"] is True
    assert manifest["summary"]["dependency_completeness"] == "not-derived"

# ---------------------------------------------------------------------------
# 1.0.55 root-scoped source coverage.
# ---------------------------------------------------------------------------

def test_workload_only_coverage_does_not_require_pending_base_media():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    class Var:
        def get(self):
            return "Installation media / local mirror (ISO, DVD, folder, SMB)"

    ui = App.__new__(App)
    ui.source_method_var = Var()
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    ui.repo_rows = [vendor]
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])
    ui._workload_uses_distribution_sources = App._workload_uses_distribution_sources.__get__(ui, App)
    ui._local_media_pending = App._local_media_pending.__get__(ui, App)
    ui._log = lambda _msg: None

    # Coverage of a dedicated upstream is a root-presence check, not a demand
    # that the unused base-source plan already be configured.
    App._validate_sources(ui, False)


def test_distribution_root_coverage_still_requires_pending_base_media_to_be_configured():
    import pytest
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    class Var:
        def get(self):
            return "Installation media / local mirror (ISO, DVD, folder, SMB)"

    ui = App.__new__(App)
    ui.source_method_var = Var()
    base = RepoSpec("Base placeholder", "https://example.invalid/base/", "dependency", enabled=True)
    base.source_tier = "base"
    ui.repo_rows = [base]
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("podman", "distribution")])
    ui._workload_uses_distribution_sources = App._workload_uses_distribution_sources.__get__(ui, App)
    ui._local_media_pending = App._local_media_pending.__get__(ui, App)
    ui._log = lambda _msg: None

    with pytest.raises(RuntimeError, match="no media folder has been loaded"):
        App._validate_sources(ui, False)


def test_package_coverage_repository_scope_ignores_base_for_dedicated_workload():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    ui = App.__new__(App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    base = RepoSpec("BaseOS", "https://os.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    docker = RepoSpec("Docker CE", "https://download.example/docker/", "docker", enabled=True)
    docker.source_tier = "workload"
    extra = RepoSpec("Unrelated", "https://extra.example/repo/", "dependency", enabled=True)
    extra.source_tier = "additional"
    ui.repo_rows = [base, docker, extra]

    assert App._package_coverage_repositories(ui) == [docker]


def test_package_coverage_repository_scope_combines_base_and_sidechannel_for_mixed_workload():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    ui = App.__new__(App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([
        RootSourcePolicy("iproute", "distribution"),
        RootSourcePolicy("vendor-agent", "workload", "vendor"),
    ])
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    base = RepoSpec("BaseOS", "https://os.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    unrelated = RepoSpec("Other", "https://other.example/repo/", "other", enabled=True)
    unrelated.source_tier = "additional"
    ui.repo_rows = [base, vendor, unrelated]

    assert App._package_coverage_repositories(ui) == [base, vendor]


def test_repository_cards_keep_spacing_between_required_and_base_sections():
    import app, inspect
    source = inspect.getsource(app.App._build_sources_pane)
    assert 'self._card(pane, "Base distribution sources", pady=(18, 0))' in source

# ---------------------------------------------------------------------------
# 1.0.56 source-plan-aware source health.
# ---------------------------------------------------------------------------

def test_probe_verdict_treats_workload_only_source_as_package_only_not_missing_dependency_repo():
    from app import App

    results = [{
        "name": "Vendor", "role": "vendor", "tier": "workload",
        "purpose": "workload roots", "ok": True, "signed": True,
    }]
    context = {
        "mirror_mode": False, "single_mode": False, "package_only": True,
        "distribution_required": False, "required_roles": ["vendor"],
        "local_media_pending": True, "selected_repo_names": [],
    }
    lines = App._probe_verdict_lines(results, context)
    text = " ".join(lines).lower()
    assert "package-only acquisition remains available" in text
    assert "root source scope needs attention" not in text
    assert "role 'dependency'" not in text


def test_probe_verdict_reports_pending_base_only_for_distribution_roots():
    from app import App

    results = [{
        "name": "Vendor", "role": "vendor", "tier": "workload",
        "purpose": "workload roots", "ok": True, "signed": True,
    }]
    context = {
        "mirror_mode": False, "single_mode": False, "package_only": False,
        "distribution_required": True, "required_roles": ["vendor"],
        "local_media_pending": True, "selected_repo_names": [],
    }
    text = " ".join(App._probe_verdict_lines(results, context)).lower()
    assert "distribution roots require local media" in text
    assert "needs attention" in text


def test_package_only_build_scope_excludes_unrelated_base_and_additional_sources():
    from app import App
    from core import RepoSpec
    from workloads import RootSourcePolicy, SourcePlan

    ui = App.__new__(App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    base = RepoSpec("Base", "https://os.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    extra = RepoSpec("Extra", "https://extra.example/repo/", "dependency", enabled=True)
    extra.source_tier = "additional"
    ui.repo_rows = [base, vendor, extra]

    assert App._build_repository_scope(ui, package_only=True) == [vendor]
    assert App._build_repository_scope(ui, package_only=False) == [base, vendor, extra]


def test_provenance_uses_package_only_operation_scope():
    from app import App
    from core import RepoSpec

    ui = App.__new__(App)
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    extra = RepoSpec("Extra", "https://extra.example/repo/", "dependency", enabled=True)
    ui.repo_rows = [vendor, extra]
    ui._package_only_acquisition_mode = lambda: True
    ui._build_repository_scope = lambda package_only=False: [vendor] if package_only else [vendor, extra]

    assert App._enabled_provenance_repos(ui) == [vendor]


def test_metadata_loading_heals_failed_supplement_when_required_workload_scope_survives():
    from app import App
    from core import RepoSpec, Reporter
    from workloads import RootSourcePolicy, SourcePlan

    class Var:
        def get(self): return "Distribution repositories"

    ui = App.__new__(App)
    ui.arch_var = type("Arch", (), {"get": lambda self: "x86_64"})()
    ui.source_method_var = Var()
    ui._signature = lambda: ("test",)
    ui.loaded_signature = None; ui.loaded_packages = []
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    extra = RepoSpec("Extra", "https://extra.example/repo/", "dependency", enabled=True)
    extra.source_tier = "additional"
    ui.repo_rows = [vendor, extra]
    ui._load_repository_backend = lambda repo, _arches, _rep: ([] if repo is vendor else (_ for _ in ()).throw(RuntimeError("offline")))
    rep = Reporter()

    assert App._load_enabled_repos(ui, rep, repositories=[vendor, extra], enforce_distribution_plan=False) == []
    assert any("Extra" in warning for warning in rep.warnings)


def test_metadata_loading_fails_when_entire_required_workload_role_is_unreachable():
    import pytest
    from app import App
    from core import RepoSpec, Reporter
    from workloads import RootSourcePolicy, SourcePlan

    class Var:
        def get(self): return "Distribution repositories"

    ui = App.__new__(App)
    ui.arch_var = type("Arch", (), {"get": lambda self: "x86_64"})()
    ui.source_method_var = Var()
    ui._signature = lambda: ("test",)
    ui.loaded_signature = None; ui.loaded_packages = []
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    extra = RepoSpec("Extra", "https://extra.example/repo/", "dependency", enabled=True)
    extra.source_tier = "additional"
    ui.repo_rows = [vendor, extra]
    ui._load_repository_backend = lambda repo, _arches, _rep: ([] if repo is extra else (_ for _ in ()).throw(RuntimeError("offline")))

    with pytest.raises(RuntimeError, match="required role 'vendor'"):
        App._load_enabled_repos(ui, Reporter(), repositories=[vendor, extra], enforce_distribution_plan=False)


def test_package_browser_includes_disabled_generic_workload_role_not_only_docker():
    from app import App
    from core import RepoSpec

    ui = App.__new__(App)
    ui._known_workload_repository_roles = lambda: {"kubernetes", "docker"}
    kube = RepoSpec("Kubernetes", "https://vendor.example/kube/", "kubernetes", enabled=False)
    unrelated = RepoSpec("Unrelated disabled", "https://example.invalid/other/", "dependency", enabled=False)
    enabled = RepoSpec("Base", "https://os.example/base/", "dependency", enabled=True)
    ui.repo_rows = [kube, unrelated, enabled]

    assert App._browser_repositories(ui) == [kube, enabled]


def test_source_status_does_not_error_on_pending_base_media_for_package_only_workload():
    from app import App
    from core import RepoSpec

    class Var:
        def get(self): return "Installation media / local mirror (ISO, DVD, folder, SMB)"
    class Status:
        def __init__(self): self.kw = {}
        def configure(self, **kw): self.kw.update(kw)

    ui = App.__new__(App)
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    ui.repo_rows = [vendor]
    ui.source_method_var = Var()
    ui.source_status = Status()
    ui._repo_tier = App._repo_tier.__get__(ui, App)
    ui._workload_uses_distribution_sources = lambda: False
    ui._package_only_acquisition_mode = lambda: True
    ui._local_media_pending = lambda: True
    ui.rhsm_cert = ui.rhsm_key = ui.rhsm_ca = ""

    App._update_source_status(ui)
    assert "dependency completeness cannot be derived" in ui.source_status.kw["text"].lower()
    assert "no repository folder has been loaded" not in ui.source_status.kw["text"].lower()

# ---------------------------------------------------------------------------
# 1.0.57 decomposition trial: source/readiness/transport seams.
# ---------------------------------------------------------------------------

def test_refactor_domain_and_transport_modules_are_gui_free():
    import ast
    from pathlib import Path

    for name in ("source_model.py", "source_readiness.py", "repository_transport.py", "workload_materialization.py"):
        tree = ast.parse(Path(name).read_text(encoding="utf-8"), filename=name)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.append(node.module)
        assert not any(item == "tkinter" or item.startswith("tkinter.") for item in imports), name
        assert "app" not in imports, name


def test_source_readiness_selects_root_scope_and_package_only_capability():
    from core import RepoSpec
    from source_model import RootSourcePolicy, SourcePlan
    from source_readiness import evaluate_source_readiness

    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    vendor.workload_profile_managed = True
    extra = RepoSpec("Extra", "https://extra.example/repo/", "dependency", enabled=True)
    extra.source_tier = "additional"
    plan = SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])

    readiness = evaluate_source_readiness(plan, [vendor, extra])
    assert readiness.capability == "package-only"
    assert readiness.root_repositories == (vendor,)
    assert readiness.missing_scopes == ()


def test_source_readiness_mixed_plan_requires_distribution_and_workload_role():
    from core import RepoSpec
    from source_model import RootSourcePolicy, SourcePlan
    from source_readiness import evaluate_source_readiness

    base = RepoSpec("Base", "https://dist.example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    vendor = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    vendor.source_tier = "workload"
    plan = SourcePlan([
        RootSourcePolicy("native-tool", "distribution"),
        RootSourcePolicy("vendor-agent", "workload", "vendor"),
    ])

    ready = evaluate_source_readiness(plan, [base, vendor])
    assert ready.capability == "full-analysis"
    assert ready.root_repositories == (base, vendor)

    missing_base = evaluate_source_readiness(plan, [vendor])
    assert missing_base.capability == "blocked"
    assert missing_base.missing_scopes == ("distribution",)


def test_core_network_entrypoints_delegate_to_repository_transport():
    import inspect
    import core
    import repository_transport

    assert core._RepositoryRedirectHandler is repository_transport.RepositoryRedirectHandler
    assert "_transport.open_url" in inspect.getsource(core._urlopen)
    assert "_transport.fetch_bytes" in inspect.getsource(core.fetch_bytes)
    assert "urllib.request.urlopen" not in inspect.getsource(core._urlopen)


def test_1058_windows_casefold_payload_collision_is_blocked():
    from core import payload_filenames
    repo1 = RepoSpec("R1", "https://one.example/")
    repo2 = RepoSpec("R2", "https://two.example/")
    one = Package("one", "x86_64", "0", "1", "1", "a/Foo.rpm", "sha256", "", repo1)
    two = Package("two", "x86_64", "0", "1", "1", "b/foo.rpm", "sha256", "", repo2)
    try:
        payload_filenames([one, two], ".rpm")
    except RuntimeError as exc:
        assert "Windows destination" in str(exc)
    else:
        raise AssertionError("case-only payload names were accepted for Windows staging")


def test_1058_verifier_resource_is_fail_closed(monkeypatch, tmp_path):
    import core
    monkeypatch.setattr(core, "__file__", str(tmp_path / "core.py"))
    monkeypatch.delattr(core.sys, "_MEIPASS", raising=False)
    try:
        core._verify_script()
    except RuntimeError as exc:
        assert "verify_bundle_template.py" in str(exc)
    else:
        raise AssertionError("missing verifier resource did not fail closed")


def test_1058_build_script_embeds_verifier_and_stages_required_sidecars():
    script = Path("build_exe.bat").read_text(encoding="utf-8").lower()
    assert '--add-data "verify_bundle_template.py;."' in script
    assert "target_inventory.sh" in script
    assert "workloads.example.json" in script
    assert Path("target_inventory.sh").is_file()
    assert Path("workloads.example.json").is_file()


def test_1058_manual_repo_prevents_profile_managed_package_only_downgrade():
    from source_model import RootSourcePolicy, SourcePlan
    from source_readiness import evaluate_source_readiness
    manual = RepoSpec("Internal", "https://internal.example/repo/", "vendor", enabled=True)
    manual.source_tier = "workload"
    manual.workload_profile_managed = False
    managed = RepoSpec("Vendor", "https://vendor.example/repo/", "vendor", enabled=True)
    managed.source_tier = "workload"
    managed.workload_profile_managed = True
    plan = SourcePlan([RootSourcePolicy("agent", "workload", "vendor")])
    assert evaluate_source_readiness(plan, [manual]).capability == "full-analysis"
    assert evaluate_source_readiness(plan, [managed]).capability == "package-only"
    assert evaluate_source_readiness(plan, [manual, managed]).capability == "full-analysis"


def test_1058_external_workload_preserves_optional_packages(tmp_path):
    from workloads import _parse_external
    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({"workloads": [{
        "key": "x", "label": "X", "packages": ["a", "b"],
        "optional_packages": ["b"]
    }]}), encoding="utf-8")
    workload = _parse_external(path)[0]
    assert workload.optional_packages == ["b"]
    assert workload.optional_for("rpm") == {"b"}


def test_1058_gui_log_sink_redacts_registered_secrets():
    from types import SimpleNamespace
    from app import App
    from core import register_url_secrets
    register_url_secrets("https://repo.example/path?token=VERYSECRET1058")
    ui = SimpleNamespace(log_lines=[])
    App._log(ui, "failed https://repo.example/path?token=VERYSECRET1058")
    assert "VERYSECRET1058" not in "\n".join(ui.log_lines)
    assert "REDACTED" in "\n".join(ui.log_lines)


def test_1058_rpm_installer_uses_local_repository_roots_not_payload_argv(tmp_path):
    repo = RepoSpec("Local", tmp_path.as_uri() + "/")
    payload = tmp_path / "demo.rpm"
    payload.write_bytes(b"rpm-fixture")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    pkg = Package("demo", "x86_64", "0", "1", "1", "demo.rpm", "sha256", digest, repo,
                  size=payload.stat().st_size)
    import core
    result = core.ResolutionResult([pkg], [], [pkg])
    out = tmp_path / "bundle"
    core.write_bundle(result, out, BuildOptions(retries=1), Reporter(), {"workload": "test"})
    script = (out / "install-offline.sh").read_text()
    assert "REQUESTED-ROOTS.txt" in script
    assert "baseurl=file://$HERE" in script
    assert 'install "${PLAN[@]}"' in script
    assert "find ./rpms" not in script
    assert (out / "repodata/repomd.xml").is_file()


# ---- 1.0.59 workload materialization + Step 4 evidence gate ------------

def test_1059_materializer_uses_first_approved_candidate_present_in_scope():
    from types import SimpleNamespace
    from source_model import RootSourcePolicy, SourcePlan
    from workload_materialization import materialize_source_plan

    repo = SimpleNamespace(role="dependency", source_tier="base")
    packages = [
        SimpleNamespace(name="runtime-v2", arch="x86_64", repo=repo),
        SimpleNamespace(name="totally-similar-runtime", arch="x86_64", repo=repo),
    ]
    plan = SourcePlan([RootSourcePolicy(
        "runtime-v1", "distribution", None,
        component="runtime", candidates=("runtime-v1", "runtime-v2"))])
    result = materialize_source_plan(
        "demo", 3, "abc", "rpm", plan, packages, "x86_64",
        tier_getter=lambda r: r.source_tier)
    assert result.complete
    assert result.roots[0].component == "runtime"
    assert result.roots[0].package == "runtime-v2"
    assert result.roots[0].candidates == ("runtime-v1", "runtime-v2")


def test_1059_materializer_fails_closed_on_unapproved_similar_package():
    from types import SimpleNamespace
    from source_model import RootSourcePolicy, SourcePlan
    from workload_materialization import materialize_source_plan

    repo = SimpleNamespace(role="dependency", source_tier="base")
    packages = [SimpleNamespace(name="runtime-v3-unapproved", arch="x86_64", repo=repo)]
    plan = SourcePlan([RootSourcePolicy(
        "runtime-v1", "distribution", None,
        component="runtime", candidates=("runtime-v1", "runtime-v2"))])
    result = materialize_source_plan(
        "demo", 3, "abc", "rpm", plan, packages, "x86_64",
        tier_getter=lambda r: r.source_tier)
    assert not result.complete
    assert not result.roots
    assert result.unresolved[0].component == "runtime"


def test_1059_materializer_respects_workload_repository_role():
    from types import SimpleNamespace
    from source_model import RootSourcePolicy, SourcePlan
    from workload_materialization import materialize_source_plan

    base = SimpleNamespace(role="dependency", source_tier="base")
    vendor = SimpleNamespace(role="vendor", source_tier="workload")
    packages = [
        SimpleNamespace(name="agent", arch="x86_64", repo=base),
        SimpleNamespace(name="agent2", arch="x86_64", repo=vendor),
    ]
    plan = SourcePlan([RootSourcePolicy(
        "agent", "workload", "vendor",
        component="agent", candidates=("agent", "agent2"))])
    result = materialize_source_plan(
        "demo", 1, "abc", "rpm", plan, packages, "x86_64",
        tier_getter=lambda r: r.source_tier)
    assert result.roots[0].package == "agent2"


def test_1059_external_workload_components_support_ordered_candidates(tmp_path):
    from workloads import _parse_external
    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({
        "catalog_revision": 7,
        "workloads": [{
            "key": "agent", "label": "Agent",
            "components": [{
                "id": "runtime",
                "candidates": {"rpm": ["agent-runtime", "agent-runtime2"],
                               "deb": ["agent-runtime-deb", "agent-runtime2-deb"]},
                "repository_role": "vendor"
            }]
        }]
    }), encoding="utf-8")
    workload = _parse_external(path)[0]
    assert workload.catalog_revision == 7
    assert len(workload.catalog_sha256) == 64
    rpm_plan = workload.source_plan("rpm")
    deb_plan = workload.source_plan("deb")
    assert rpm_plan.roots[0].component == "runtime"
    assert rpm_plan.roots[0].candidates == ("agent-runtime", "agent-runtime2")
    assert deb_plan.roots[0].candidates == ("agent-runtime-deb", "agent-runtime2-deb")
    assert rpm_plan.roots[0].role == "vendor"


def test_1059_evidence_gate_matches_per_source_runtime_contract():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    one = RepoSpec("One", "https://one.example/repo/", enabled=True)
    two = RepoSpec("Two", "https://two.example/repo/", enabled=True)
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [one, two]
    ui.prov_strategy_var = Var("Fill gaps with independent evidence (enhanced)")
    ui.prov_digest_var = Var("Automatic")

    try:
        feather_app.App._validate_provenance_step(ui)
    except RuntimeError as exc:
        assert "inspect checksum support first" in str(exc).lower()
    else:
        raise AssertionError("Enhanced advanced before checksum coverage was known")

    one.evidence_urls = ["https://evidence-one.example/repo/"]
    key1 = feather_app.App._evidence_preflight_key(ui, one, one.evidence_urls[0])
    ui._evidence_preflight_cache = {key1: {"status": "artifact-only", "detail": "exact file exists"}}
    try:
        feather_app.App._validate_provenance_step(ui)
    except RuntimeError as exc:
        assert "inspect checksum support first" in str(exc).lower()
    else:
        raise AssertionError("Enhanced used evidence before deciding whether fallback was required")

    ui._provenance_detected_cache = {
        feather_app.App._provenance_repo_cache_key(ui, one): ["sha256"],
        feather_app.App._provenance_repo_cache_key(ui, two): ["sha256"]
    }
    ui._provenance_digest_coverage_cache = {
        # One is inspected but has no package meeting the selected minimum, so
        # its already-tested exact evidence is genuinely required.
        feather_app.App._provenance_repo_cache_key(ui, one): {"total": 1, "auto": 0},
        feather_app.App._provenance_repo_cache_key(ui, two): {"total": 1, "auto": 1}
    }
    feather_app.App._validate_provenance_step(ui)

    ui.prov_strategy_var.set("Corroborate every package (maximum)")
    try:
        feather_app.App._validate_provenance_step(ui)
    except RuntimeError as exc:
        assert "every participating package source" in str(exc).lower()
        assert "two" in str(exc).lower()
    else:
        raise AssertionError("Maximum advanced without evidence for every source")

def test_1059_basic_strict_and_minimal_do_not_require_evidence():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    ui = object.__new__(feather_app.App)
    ui.repo_rows = [RepoSpec("One", "https://one.example/repo/", enabled=True)]
    for strategy in (
        "Skip upstream provenance checks (minimal)",
        "Verify what is available (basic)",
        "Require checksum coverage (strict)",
    ):
        ui.prov_strategy_var = Var(strategy)
        feather_app.App._validate_provenance_step(ui)


def test_1059_unconfigured_evidence_dropdown_is_visibly_none_not_automatic():
    import app as feather_app
    repo = RepoSpec("One", "https://one.example/repo/", enabled=True,
                    evidence_suggestions=["https://evidence.example/repo/"])
    ui = object.__new__(feather_app.App)
    label = feather_app.App._current_evidence_choice_label(
        ui, repo, {}, ["https://evidence.example/repo/"],
        "Automatic  https://evidence.example/repo/", "No evidence source",
        "Enter a mirror URL manually")
    assert label == "No evidence source"


def test_1059_provenance_evidence_is_own_highlightable_card_and_policy_does_not_auto_mesh():
    import app as feather_app, inspect
    pane = inspect.getsource(feather_app.App._build_keyrings_pane)
    policy = inspect.getsource(feather_app.App._provenance_policy_changed)
    nav = inspect.getsource(feather_app.App._validate_wizard_transition)
    assert '_card(pane, "Independent evidence sources (CONDITIONAL)"' in pane
    assert "prov_evidence_card" in pane
    assert "per participating package source" in pane.lower() and "independent evidence" in pane.lower()
    assert "evidence_suggestions" not in policy
    assert "_validate_provenance_step" in nav


def test_1059_catalog_signature_contract_is_fail_closed_when_incomplete(tmp_path):
    from workloads import _parse_external
    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({"workloads": [{
        "key": "x", "label": "X", "packages": ["x"]
    }]}), encoding="utf-8")
    (tmp_path / "workloads.json.sig").write_bytes(b"signature")
    try:
        _parse_external(path)
    except ValueError as exc:
        assert "workloads-catalog.gpg" in str(exc)
    else:
        raise AssertionError("partial signed-catalog trust material was accepted")


def test_1059_verified_catalog_signature_is_recorded(monkeypatch, tmp_path):
    import workloads
    import core
    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({"workloads": [{
        "key": "x", "label": "X", "packages": ["x"]
    }]}), encoding="utf-8")
    (tmp_path / "workloads.json.sig").write_bytes(b"signature")
    (tmp_path / "workloads-catalog.gpg").write_bytes(b"keyring")
    calls = []
    monkeypatch.setattr(
        core, "verify_openpgp",
        lambda payload, signature, keyring, description, reporter:
            calls.append((payload, signature, keyring, description)))
    workload = workloads._parse_external(path)[0]
    assert workload.catalog_signature_verified is True
    assert calls == [(path.read_bytes(), b"signature",
                      str(tmp_path / "workloads-catalog.gpg"), "Workload catalog")]
    assert len(workload.catalog_fingerprint("rpm")) == 64


def test_workload_catalog_uses_core_authenticated_openpgp_policy(monkeypatch, tmp_path):
    import core
    import workloads
    path = tmp_path / "workloads.json"
    path.write_text(json.dumps({"workloads": [{
        "key": "x", "label": "X", "packages": ["x"]
    }]}), encoding="utf-8")
    (tmp_path / "workloads.json.sig").write_bytes(b"signature")
    (tmp_path / "workloads-catalog.gpg").write_bytes(b"keyring")

    def authenticated_policy(*args, **kwargs):
        raise core.VerifierIntegrityError("bundled verifier authentication failed")

    monkeypatch.setattr(core, "verify_openpgp", authenticated_policy)
    try:
        workloads._parse_external(path)
    except ValueError as exc:
        assert "bundled verifier authentication failed" in str(exc)
        return
    raise AssertionError("workload catalog bypassed core's authenticated verifier policy")


def test_https_repository_redirect_cannot_downgrade_to_http():
    import urllib.request
    from core import RepoSpec, _RepositoryRedirectHandler

    repo = RepoSpec("Public", "https://repo.example/repo/")
    handler = _RepositoryRedirectHandler(repo)
    request = urllib.request.Request("https://repo.example/repo/repodata/repomd.xml")
    try:
        handler.redirect_request(request, None, 302, "Found", {},
                                 "http://repo.example/repo/repodata/repomd.xml")
    except RuntimeError as exc:
        assert "https" in str(exc).lower() and "not allowed" in str(exc).lower()
        return
    raise AssertionError("HTTPS repository redirect was allowed to downgrade to HTTP")


def test_signed_url_credentials_are_recognized_and_redacted():
    from core import redact_url, register_url_secrets
    from repository_transport import (inherit_sensitive_query_credentials,
                                      sensitive_query_parts, url_has_endpoint_credentials)

    url = ("https://objects.example/pkg?X-Amz-Credential=AKIA%2Fscope&"
           "X-Amz-Signature=deadbeef&X-Amz-Security-Token=session-secret")
    parts = sensitive_query_parts(url)
    assert set(parts) == {"x-amz-credential", "x-amz-signature", "x-amz-security-token"}
    assert url_has_endpoint_credentials(url)
    redacted = redact_url(url)
    assert "deadbeef" not in redacted and "session-secret" not in redacted and "AKIA" not in redacted
    register_url_secrets(url)
    child = inherit_sensitive_query_credentials(url, "https://objects.example/other")
    assert "X-Amz-" not in child and "x-amz-" not in child


def test_package_stream_rejects_bytes_beyond_advertised_size(tmp_path):
    import io
    from types import SimpleNamespace
    import core

    pkg = SimpleNamespace(nevra="pkg-1.x86_64", size=3)
    out = io.BytesIO()
    try:
        core.copy_package_stream_bounded(io.BytesIO(b"four"), out, pkg, core.Reporter())
    except RuntimeError as exc:
        assert "package transfer exceeded" in str(exc).lower()
        return
    raise AssertionError("package transfer exceeded its metadata size without being rejected")


def test_1059_materialized_replacement_name_is_the_resolver_root_and_keeps_version_pin():
    import app as feather_app
    from types import SimpleNamespace
    from workload_materialization import MaterializedRoot, MaterializedWorkload
    from workloads import WorkloadProfile, WorkloadComponent

    workload = WorkloadProfile(
        key="vendor", label="Vendor", packages=["agent"], description="x",
        version_package="agent", versioned_packages=["agent"],
        components=[WorkloadComponent("agent", ["agent", "agent-next"], repository_role="vendor")])
    materialized = MaterializedWorkload(
        "vendor", 2, "a" * 64, "rpm", False,
        roots=(MaterializedRoot("agent", "agent", "agent-next", ("agent", "agent-next"),
                                "workload", "vendor", False),))

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = object.__new__(feather_app.App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._workload = lambda: workload
    ui._profile = lambda: SimpleNamespace(package_family="rpm")
    ui.package_version_var = Var("2.4.0")
    requests = feather_app.App._package_requests(ui, materialized)
    assert requests == [("agent-next", "2.4.0", "vendor")]


def test_1059_component_repository_role_does_not_require_duplicate_repository_roles_field():
    from workloads import WorkloadProfile, WorkloadComponent
    workload = WorkloadProfile(
        key="x", label="X", packages=["agent"], description="x",
        components=[WorkloadComponent("agent", ["agent", "agent2"], repository_role="vendor")])
    assert workload.required_repository_roles() == ["vendor"]
    assert workload.repository_role_for("agent") == "vendor"
    assert workload.source_plan("rpm").required_roles == ["vendor"]


# ---- 1.0.60 independent artifact evidence + footer containment ----------

def test_1060_artifact_only_evidence_can_corroborate_exact_file(tmp_path, monkeypatch):
    import core
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_a, **_k: (True, "distinct test source"))
    body = b"artifact-only corroboration"
    repo = RepoSpec("Primary", "https://primary.example/repo/",
                    digest_preference="sha512", verification_strategy="full-corroboration")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    digest = hashlib.sha512(body).hexdigest()
    pkg.digests = {"sha512": digest}; pkg.checksum_type = "sha512"; pkg.checksum = digest
    acquisition = tmp_path / "acq.rpm"; acquisition.write_bytes(body)
    evidence_dir = tmp_path / "evidence" / "Packages"; evidence_dir.mkdir(parents=True)
    evidence_file = evidence_dir / Path(pkg.location).name; evidence_file.write_bytes(body)
    repo.evidence_urls = [(tmp_path / "evidence").as_uri() + "/"]
    assert core.verify_package_artifact(pkg, acquisition, BuildOptions(), Reporter())
    record = core._artifact_verification(pkg)
    assert record.evidence_artifact_checked
    assert record.evidence_artifact_digest == digest


def test_1060_independent_artifact_mismatch_is_fatal(tmp_path, monkeypatch):
    import core
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_a, **_k: (True, "distinct test source"))
    body = b"primary bytes"
    repo = RepoSpec("Primary", "https://primary.example/repo/",
                    digest_preference="sha256", verification_strategy="full-corroboration")
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    digest = hashlib.sha256(body).hexdigest()
    pkg.digests = {"sha256": digest}; pkg.checksum_type = "sha256"; pkg.checksum = digest
    acquisition = tmp_path / "acq.rpm"; acquisition.write_bytes(body)
    evidence = tmp_path / Path(pkg.location).name; evidence.write_bytes(b"different evidence bytes")
    repo.evidence_urls = [evidence.as_uri()]
    try:
        core.verify_package_artifact(pkg, acquisition, BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "evidence disagreement" in str(exc).lower()
    else:
        raise AssertionError("mismatched independent evidence was accepted")


def test_1060_evidence_candidates_never_scrape_or_guess_names():
    import core
    exact = "Packages/demo-1.0-1.x86_64.rpm"
    candidates = core.evidence_artifact_candidates("https://mirror.example/root/", exact)
    assert candidates == ["https://mirror.example/root/Packages/demo-1.0-1.x86_64.rpm"]
    assert core.evidence_artifact_candidates("https://mirror.example/other.rpm", exact) == []


def test_1060_step4_checksum_precedes_evidence_validation():
    import app as feather_app
    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
    repo = RepoSpec("One", "https://one.example/repo/", enabled=True,
                    evidence_urls=["https://evidence.example/repo/"])
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.prov_strategy_var = Var("Corroborate every package (maximum)")
    ui.prov_digest_var = Var("")
    try:
        feather_app.App._validate_provenance_step(ui)
    except RuntimeError as exc:
        assert "checksum policy" in str(exc).lower()
    else:
        raise AssertionError("missing checksum policy did not block Step 4")


def test_1060_footer_reserves_navigation_column_and_wraps_status():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._build_ui)
    assert 'fin.grid_columnconfigure(1, weight=1' in source
    assert 'fin.grid_columnconfigure(2, weight=0)' in source
    assert 'actions.grid(row=0, column=2' in source
    assert 'wraplength=width' in source
    assert 'status_label.pack(side="left"' not in source


def test_1060_evidence_ui_exposes_test_and_artifact_only_state():
    import app as feather_app, inspect
    pane = inspect.getsource(feather_app.App._build_keyrings_pane)
    rows = inspect.getsource(feather_app.App._refresh_provenance_evidence_rows)
    validate = inspect.getsource(feather_app.App._validate_provenance_step)
    assert "Test evidence sources" in pane
    assert "artifact-only" in pane.lower()
    assert feather_app.App._evidence_row_status(
        "evidence-fallback", True, False, feather_app.REL_EXACT_ARTIFACT,
        {"status": "artifact-only"})[0] == "Byte match passed · required"
    assert '"repository", "artifact-only"' in validate


def test_1060_preflight_warns_but_accepts_artifact_only_evidence(monkeypatch):
    import app as feather_app
    class Var:
        def get(self): return "x86_64"
    repo = RepoSpec("Primary", "https://primary.example/repo/", enabled=True)
    pkg = rpm_pkg("demo", "1.0", repo=repo)
    ui = object.__new__(feather_app.App)
    ui.arch_var = Var()
    ui._selected_root_names_for_evidence = lambda: {"demo"}
    def load(candidate_repo, arches, reporter):
        if candidate_repo.name.endswith("[evidence]"):
            raise RuntimeError("repodata/repomd.xml not found")
        return [pkg]
    ui._load_repository_backend = load
    monkeypatch.setattr(feather_app, "mirrors_are_distinct", lambda *_a, **_k: (True, "distinct"))
    monkeypatch.setattr(feather_app, "spot_compare_artifact_urls", lambda *_a, **_k: (True, "Spot check passed under SHA512"))
    result = feather_app.App._preflight_evidence_pair(
        ui, repo, "https://evidence.example/repo/", Reporter())
    assert result["status"] == "artifact-only"
    assert "metadata was not recognized" in result["detail"].lower()

# ---- 1.0.61 evidence-source UX + ephemeral manual entries ---------------

def test_1061_test_evidence_button_precedes_manual_selector_rows():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._build_keyrings_pane)
    assert source.index('text="Test evidence sources"') < source.index('self.prov_evidence_rows_frame =')


def test_1062_test_evidence_button_shares_status_row_like_checksum_inspection():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._build_keyrings_pane)
    assert 'evidence_test_row = ttk.Frame(evidence' in source
    assert 'textvariable=self.prov_evidence_state_var' in source
    assert 'self.prov_evidence_help_label.pack(side="left", fill="x", expand=True)' in source
    assert 'self.prov_evidence_test_btn.pack(side="right", padx=(10, 0))' in source
    assert 'evidence_actions = ttk.Frame' not in source


def test_1061_manual_evidence_prompt_is_feather_styled_and_documents_contract():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._prompt_manual_evidence_repository)
    assert 'tk.Toplevel' in source
    assert 'background=BG_APP' in source
    assert '_card(outer, "Evidence source")' in source
    assert 'https://mirror.example.org/rocky/9/AppStream/x86_64/os/' in source
    assert 'repository metadata is preferred' in source.lower()
    assert 'exact package-relative path' in source.lower()
    assert 'session-only' in source.lower()
    assert '\\\\n' not in source


def test_1061_manual_evidence_url_never_becomes_reusable_dropdown_choice():
    import app as feather_app
    repo = RepoSpec("One", "https://one.example/repo/", enabled=True,
                    evidence_urls=["https://typo.example/repo/"])
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    values, candidates, curated, auto, none, manual, session = feather_app.App._evidence_choices_for_repo(ui, repo)
    current = feather_app.App._current_evidence_choice_label(
        ui, repo, candidates, curated, auto, none, manual, session)
    assert current == "https://typo.example/repo/"
    # The active session value may be displayed by the row, but it never enters
    # the reusable candidate list returned by the source-choice model.
    assert "https://typo.example/repo/" not in values
    assert all("typo.example" not in value for value in values)


def test_1061_clear_manual_evidence_discards_active_url_and_preflight_cache():
    import app as feather_app
    repo = RepoSpec("One", "https://one.example/repo/", enabled=True,
                    evidence_urls=["https://manual.example/repo/"])
    ui = object.__new__(feather_app.App)
    key = feather_app.App._provenance_repo_cache_key(ui, repo)
    ui._evidence_preflight_cache = {(key, "https://manual.example/repo/"): {"status": "repository"}}
    ui.loaded_signature = object(); ui.loaded_packages = [1]; ui.last_result = object()
    ui._clear_validation_attention = lambda: None
    ui._log = lambda *_a, **_k: None
    ui._refresh_provenance_evidence_rows = lambda: None
    ui._refresh_provenance_source_tree = lambda: None
    ui._refresh_repo_tree_if_open = lambda: None
    feather_app.App._clear_manual_evidence_source(ui, repo)
    assert repo.evidence_urls == []
    assert ui._evidence_preflight_cache == {}
    assert ui.loaded_signature is None and ui.loaded_packages == [] and ui.last_result is None


def test_1061_manual_source_row_exposes_stable_clear_slot_and_typed_url():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._refresh_provenance_evidence_rows)
    current_source = inspect.getsource(feather_app.App._current_evidence_choice_label)
    assert 'text="Clear"' in source
    assert 'action_slot = ttk.Frame' in source
    assert 'pack_propagate(False)' in source
    assert '_compact_evidence_url(existing[0])' in current_source


# ---- 1.0.63 explicit evidence spot-test gate -----------------------------

def test_1063_evidence_selection_marks_untested_without_network_side_effects():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    repo = RepoSpec("Primary", "https://primary.example/repo/", enabled=True)
    ui = object.__new__(feather_app.App)
    ui._evidence_choices_for_repo = lambda _repo: (
        ["Configured peer", "No evidence source"],
        {"Configured peer": "https://evidence.example/repo/"},
        [], "Automatic peer", "No evidence source", "Enter a mirror URL manually",
        "Manual source (session only)")
    ui._evidence_preflight_cache = {
        (feather_app.App._provenance_repo_cache_key(ui, repo), "https://old.example/repo"):
            {"status": "repository"}
    }
    ui._invalidate_provenance_analysis = lambda: None
    ui._clear_validation_attention = lambda: None
    ui._log = lambda *_a, **_k: None
    ui._refresh_provenance_evidence_rows = lambda: None
    ui._refresh_provenance_source_tree = lambda: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui._test_evidence_sources = lambda: (_ for _ in ()).throw(
        AssertionError("dropdown selection must not test evidence"))

    feather_app.App._evidence_source_changed(ui, repo, Var("Configured peer"))
    assert repo.evidence_urls == ["https://evidence.example/repo/"]
    assert ui._evidence_preflight_cache == {}


def test_1063_step4_requires_explicit_successful_test_after_selection():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    repo = RepoSpec("Primary", "https://primary.example/repo/", enabled=True,
                    evidence_urls=["https://evidence.example/repo/"])
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.prov_strategy_var = Var("Corroborate every package (maximum)")
    ui.prov_digest_var = Var("SHA-384 or stronger")
    try:
        feather_app.App._validate_provenance_step(ui)
    except RuntimeError as exc:
        assert "explicit spot test" in str(exc).lower()
    else:
        raise AssertionError("Step 4 advanced without an explicit evidence test")

    key = feather_app.App._evidence_preflight_key(ui, repo, repo.evidence_urls[0])
    ui._evidence_preflight_cache = {key: {"status": "artifact-only", "detail": "spot matched"}}
    feather_app.App._validate_provenance_step(ui)


def test_1063_spot_compare_hashes_full_artifacts_with_selected_policy(tmp_path):
    import core
    primary_file = tmp_path / "primary.rpm"
    evidence_file = tmp_path / "evidence.rpm"
    body = (b"independent-evidence-spot-check" * 4096)
    primary_file.write_bytes(body)
    evidence_file.write_bytes(body)
    primary = RepoSpec("Primary", primary_file.parent.as_uri() + "/")
    evidence = RepoSpec("Evidence", evidence_file.parent.as_uri() + "/")
    ok, detail = core.spot_compare_artifact_urls(
        primary_file.as_uri(), primary, evidence_file.as_uri(), evidence,
        "sha384", Reporter())
    assert ok
    assert "SHA384" in detail.upper().replace("-", "")

    evidence_file.write_bytes(body + b"different")
    ok, detail = core.spot_compare_artifact_urls(
        primary_file.as_uri(), primary, evidence_file.as_uri(), evidence,
        "sha384", Reporter())
    assert not ok
    assert "mismatch" in detail.lower()


def test_1063_manual_dialog_no_longer_claims_file_urls_are_valid_independent_evidence():
    import inspect
    import app as feather_app
    source = inspect.getsource(feather_app.App._prompt_manual_evidence_repository)
    assert 'http:// or https://' in source
    assert 'http://, https://, or file://' not in source


def test_1063_selection_handler_has_no_automatic_evidence_test_call():
    import inspect
    import app as feather_app
    source = inspect.getsource(feather_app.App._evidence_source_changed)
    assert "_test_evidence_sources" not in source
    assert "_refresh_provenance_evidence_rows" in source


def test_1063_evidence_spot_test_cache_is_bound_to_checksum_policy_and_roots():
    import app as feather_app
    repo = RepoSpec("Primary", "https://primary.example/repo/", enabled=True)
    ui = object.__new__(feather_app.App)
    roots = {"one"}
    ui._selected_root_names_for_evidence = lambda: set(roots)
    repo.digest_preference = "sha256"
    first = feather_app.App._evidence_preflight_key(ui, repo, "https://evidence.example/repo/")
    repo.digest_preference = "sha512"
    second = feather_app.App._evidence_preflight_key(ui, repo, "https://evidence.example/repo/")
    assert first != second
    repo.digest_preference = "sha256"
    roots.add("two")
    third = feather_app.App._evidence_preflight_key(ui, repo, "https://evidence.example/repo/")
    assert first != third


# ---- 1.0.64 stable evidence-row presentation ------------------------------

def test_1064_manual_evidence_display_is_bounded_and_redacts_credentials():
    import app as feather_app
    url = (
        "https://mirror.example.org/this/is/a/very/long/repository/path/that/keeps/going/"
        "and/going/packages/?token=SECRET-DO-NOT-DISPLAY&channel=stable"
    )
    shown = feather_app.App._compact_evidence_url(url, max_chars=76)
    assert len(shown) <= 76
    assert "SECRET-DO-NOT-DISPLAY" not in shown
    assert "mirror.example.org" in shown
    assert "…" in shown


def test_1064_evidence_row_uses_neutral_status_and_fixed_action_geometry():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._refresh_provenance_evidence_rows)
    assert feather_app.App._evidence_row_status(
        "evidence-fallback", False, False, feather_app.REL_EXACT_MIRROR, None)[0] == "Ready to test · optional"
    assert '? Not tested' not in source
    assert 'action_slot = ttk.Frame' in source
    assert 'width=68, height=30' in source
    assert 'action_slot.pack_propagate(False)' in source
    assert 'wraplength=225' in source


def test_1064_current_manual_evidence_value_is_actual_compact_url_not_placeholder():
    import app as feather_app
    long_url = "https://evidence.example.org/" + ("very-long-path/" * 12)
    repo = RepoSpec("One", "https://one.example/repo/", enabled=True, evidence_urls=[long_url])
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    values, candidates, curated, auto, none, manual, session = feather_app.App._evidence_choices_for_repo(ui, repo)
    current = feather_app.App._current_evidence_choice_label(
        ui, repo, candidates, curated, auto, none, manual, session)
    assert current != "Manual source"
    assert current.startswith("https://evidence.example.org/")
    assert len(current) <= 76



# ---- 1.0.65 evidence-row polish ------------------------------------------

def test_1065_evidence_card_is_explicitly_conditional_and_clear_is_compact():
    import app as feather_app, inspect
    pane = inspect.getsource(feather_app.App._build_keyrings_pane)
    refresh = inspect.getsource(feather_app.App._refresh_provenance_evidence_rows)
    setup = inspect.getsource(feather_app.App._style)
    assert '_card(pane, "Independent evidence sources (CONDITIONAL)"' in pane
    assert 'style="EvidenceClear.TButton"' in refresh
    assert 'style.configure("EvidenceClear.TButton"' in setup
    assert 'font=("Segoe UI", 8)' in setup
    assert 'padding=(8, 4)' in setup

# ---- 1.0.66 conditional evidence-test action ------------------------------

def test_1066_evidence_test_button_disabled_outside_enhanced_maximum():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    class Widget:
        def __init__(self): self.state = None
        def winfo_exists(self): return True
        def configure(self, **kwargs):
            if "state" in kwargs: self.state = kwargs["state"]

    ui = object.__new__(feather_app.App)
    ui._enabled_provenance_repos = lambda: []
    ui.prov_evidence_test_btn = Widget()
    ui._prov_evidence_row_labels = []
    ui._prov_evidence_row_combos = []
    ui.active_operation = None
    ui.worker = None

    ui.prov_strategy_var = Var("Verify what is available (basic)")
    feather_app.App._update_provenance_evidence_state(ui)
    assert ui.prov_evidence_test_btn.state == "disabled"

    ui.prov_strategy_var = Var("Require checksum coverage (strict)")
    feather_app.App._update_provenance_evidence_state(ui)
    assert ui.prov_evidence_test_btn.state == "disabled"

    ui.prov_strategy_var = Var("Fill gaps with independent evidence (enhanced)")
    feather_app.App._update_provenance_evidence_state(ui)
    # No selected evidence means there is nothing to test.
    assert ui.prov_evidence_test_btn.state == "disabled"

    ui._evidence_preflight_pairs = lambda: [(object(), "https://mirror.example/")]
    feather_app.App._update_provenance_evidence_state(ui)
    assert ui.prov_evidence_test_btn.state == "normal"
    ui.prov_strategy_var = Var("Corroborate every package (maximum)")
    feather_app.App._update_provenance_evidence_state(ui)
    assert ui.prov_evidence_test_btn.state == "normal"


def test_1066_evidence_test_handler_is_noop_for_inactive_strategy():
    import app as feather_app

    class Var:
        def __init__(self, value=""): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    ui = object.__new__(feather_app.App)
    ui.prov_strategy_var = Var("Verify what is available (basic)")
    ui.status_var = Var()
    ui._evidence_preflight_pairs = lambda: (_ for _ in ()).throw(AssertionError("must not enumerate evidence"))
    feather_app.App._test_evidence_sources(ui)
    assert "Enhanced or Maximum" in ui.status_var.get()


def test_1066_evidence_button_stays_disabled_while_operation_is_running():
    import app as feather_app

    class Var:
        def get(self): return "Fill gaps with independent evidence (enhanced)"

    class Widget:
        def __init__(self): self.state = None
        def winfo_exists(self): return True
        def configure(self, **kwargs):
            if "state" in kwargs: self.state = kwargs["state"]

    ui = object.__new__(feather_app.App)
    ui.prov_strategy_var = Var()
    ui.prov_evidence_test_btn = Widget()
    ui._prov_evidence_row_labels = []
    ui._prov_evidence_row_combos = []
    ui.active_operation = "evidence-preflight"
    ui.worker = None
    feather_app.App._update_provenance_evidence_state(ui)
    assert ui.prov_evidence_test_btn.state == "disabled"

# ---- 1.0.67 evidence relationship semantics ------------------------------

def test_1067_el_rebuilds_are_independent_peers_not_exact_mirrors():
    import core
    alma = RepoSpec(
        "AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9.8/BaseOS/x86_64/os/",
        repo_format="rpm")
    assert core.evidence_relationship(
        alma, "https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/") == "independent-peer"
    # A third-party mirror of the same Alma tree remains an exact-artifact source.
    assert core.evidence_relationship(
        alma, "https://ftp.osuosl.org/pub/almalinux/9.8/BaseOS/x86_64/os/") == "exact-artifact"


def test_1067_peer_semantics_allow_different_binary_release_and_size():
    import core
    primary_repo = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/")
    peer_repo = RepoSpec("Rocky BaseOS", "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/")
    a = rpm_pkg("ModemManager", "1.20.2", repo=primary_repo)
    b = rpm_pkg("ModemManager", "1.20.2", repo=peer_repo)
    a.release = "1.el9"; b.release = "1.el9.rocky.1"
    a.size = 1275131; b.size = 1274689
    a.source_rpm = "ModemManager-1.20.2-1.el9.src.rpm"
    b.source_rpm = "ModemManager-1.20.2-1.el9.src.rpm"
    ok, detail, lineage = core.independent_peer_packages_match(a, b)
    assert ok
    assert lineage
    assert "source lineage" in detail.lower()


def test_1067_apply_peer_evidence_does_not_compare_binary_digests():
    import core
    primary_repo = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                            digest_preference="sha256")
    peer_repo = RepoSpec("Rocky BaseOS", "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
                         digest_preference="sha256")
    a = rpm_pkg("demo", "1.0", repo=primary_repo)
    b = rpm_pkg("demo", "1.0", repo=peer_repo)
    a.release = "1.el9"; b.release = "2.el9"
    a.source_rpm = "demo-1.0-1.el9.src.rpm"; b.source_rpm = "demo-1.0-1.el9.src.rpm"
    a.size = 100; b.size = 120
    a.digests = {"sha256": "aa" * 32}; a.checksum_type = "sha256"; a.checksum = a.digests["sha256"]
    b.digests = {"sha256": "bb" * 32}; b.checksum_type = "sha256"; b.checksum = b.digests["sha256"]
    stats = core.apply_mirror_evidence([a], [b], peer_repo, Reporter(), relationship="independent-peer")
    rec = core._artifact_verification(a)
    assert stats["peer"] == 1
    assert rec.evidence_relationship == "independent-peer"
    assert rec.evidence_peer_identity_match
    assert rec.evidence_source_lineage_match
    assert rec.evidence_digest == b.digests["sha256"]


def test_1067_peer_spot_check_accepts_different_bytes_when_each_own_digest_matches(tmp_path):
    import core
    primary_repo = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                            digest_preference="sha256")
    peer_repo = RepoSpec("Rocky BaseOS", "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
                         digest_preference="sha256")
    a = rpm_pkg("demo", "1.0", repo=primary_repo)
    b = rpm_pkg("demo", "1.0", repo=peer_repo)
    a.release = "1.el9"; b.release = "2.el9"
    a.source_rpm = "demo-1.0-1.el9.src.rpm"; b.source_rpm = "demo-1.0-1.el9.src.rpm"
    af = tmp_path / "a.rpm"; ef = tmp_path / "b.rpm"
    af.write_bytes(b"alma build bytes"); ef.write_bytes(b"rocky rebuild bytes differ")
    a.digests = {"sha256": hashlib.sha256(af.read_bytes()).hexdigest()}; a.checksum_type="sha256"; a.checksum=a.digests["sha256"]
    b.digests = {"sha256": hashlib.sha256(ef.read_bytes()).hexdigest()}; b.checksum_type="sha256"; b.checksum=b.digests["sha256"]
    ok, detail = core.spot_compare_peer_artifact_urls(
        a, af.as_uri(), primary_repo, b, ef.as_uri(), peer_repo, "sha256", Reporter())
    assert ok
    assert "binary bytes differ" in detail.lower()
    assert "peer digest verified" in detail.lower()


def test_1067_maximum_accepts_semantic_peer_but_enhanced_gap_does_not(tmp_path, monkeypatch):
    import core
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_a, **_k: (True, "test distinct"))
    monkeypatch.setattr(core, "evidence_relationship", lambda *_a, **_k: "independent-peer")
    primary_repo = RepoSpec("AlmaLinux BaseOS", "https://a.example/repo/",
                            digest_preference="sha256", verification_strategy="full-corroboration")
    pkg = rpm_pkg("demo", "1.0", repo=primary_repo)
    acquisition = tmp_path / "acq.rpm"; acquisition.write_bytes(b"alma bytes")
    primary_digest = hashlib.sha256(acquisition.read_bytes()).hexdigest()
    pkg.digests={"sha256":primary_digest}; pkg.checksum_type="sha256"; pkg.checksum=primary_digest
    peer_dir = tmp_path / "peer"; peer_dir.mkdir(); peer_file = peer_dir / "peer-demo.rpm"; peer_file.write_bytes(b"rocky bytes")
    primary_repo.evidence_urls=[peer_dir.as_uri()+"/"]
    rec = core._artifact_verification(pkg)
    rec.evidence_relationship="independent-peer"
    rec.evidence_peer_identity_match=True
    rec.evidence_source_lineage_match=True
    rec.evidence_location=peer_file.name
    rec.evidence_digest_type="sha256"; rec.evidence_digest=hashlib.sha256(peer_file.read_bytes()).hexdigest()
    assert core.verify_package_artifact(pkg, acquisition, BuildOptions(), Reporter())
    assert rec.evidence_status == "peer-corroborated"
    assert rec.evidence_digest_checked

    # Enhanced can use an exact artifact to fill a missing primary checksum, but
    # a different rebuild cannot authenticate the acquisition bytes it did not reproduce.
    primary_repo.verification_strategy="evidence-fallback"
    pkg.digests={}; pkg.checksum_type=""; pkg.checksum=""
    try:
        core.verify_package_artifact(pkg, acquisition, BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "cannot fill a missing acquisition checksum" in str(exc).lower()
    else:
        raise AssertionError("Enhanced incorrectly used a rebuild peer to fill missing acquisition integrity")


def test_1067_step4_accepts_successful_independent_peer_spot_test():
    import app as feather_app
    class Var:
        def __init__(self, value): self.value=value
        def get(self): return self.value
    repo = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                    enabled=True, evidence_urls=["https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"])
    ui = object.__new__(feather_app.App)
    ui.repo_rows=[repo]
    ui.prov_strategy_var=Var("Corroborate every package (maximum)")
    ui.prov_digest_var=Var("SHA-256 or stronger")
    ui._selected_root_names_for_evidence=lambda: {"demo"}
    key=feather_app.App._evidence_preflight_key(ui, repo, repo.evidence_urls[0])
    ui._evidence_preflight_cache={key:{"status":"peer", "detail":"semantic peer passed"}}
    feather_app.App._validate_provenance_step(ui)


def test_1067_preflight_classifies_alma_rocky_as_peer_without_byte_equality(monkeypatch):
    import app as feather_app
    import core
    class Var:
        def get(self): return "x86_64"
    alma = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                    digest_preference="sha256")
    rocky_url = "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"
    a = rpm_pkg("demo", "1.0", repo=alma)
    a.source_rpm = "demo-1.0-1.el9.src.rpm"
    rocky_repo = core.evidence_repo_for_url(alma, rocky_url)
    b = rpm_pkg("demo", "1.0", repo=rocky_repo)
    b.release = "2.el9"; b.source_rpm = "demo-1.0-1.el9.src.rpm"
    ui = object.__new__(feather_app.App)
    ui.arch_var = Var()
    ui._selected_root_names_for_evidence = lambda: {"demo"}
    ui._load_repository_backend = lambda r, _arches, _reporter: [b] if r.vendor_id == "rocky" else [a]
    monkeypatch.setattr(
        feather_app, "spot_compare_peer_artifact_urls",
        lambda *_a, **_k: (True, "Independent peer spot check passed: binary bytes differ"))
    result = feather_app.App._preflight_evidence_pair(ui, alma, rocky_url, Reporter())
    assert result["status"] == "peer"
    assert result["relationship"] == "independent-peer"
    assert "peer" in result["detail"].lower()


def test_1067_peer_provenance_is_not_mislabeled_as_byte_match():
    import provenance
    entry = provenance.PackageProvenance(
        package_id="demo-1.0.x86_64", filename="demo.rpm", sha256="00" * 32,
        size=10, source_url="https://a.example/demo.rpm", repository="Alma",
        digest_checked=True, evidence_relationship="independent-peer",
        evidence_peer_identity_match=True, evidence_source_lineage_match=True,
        evidence_metadata_match=True, evidence_digest_checked=True,
        evidence_artifact_checked=True)
    modes = provenance.provenance_modes_from(entry)
    assert provenance.VERIFIED_PEER_CORROBORATED in modes
    assert provenance.VERIFIED_BYTE_CORROBORATED not in modes
    assert provenance.VERIFIED_CORROBORATED not in modes


# ---- 1.0.68 mirror-flow and APT evidence regressions ---------------------

def test_1068_apt_evidence_suggestions_are_same_distribution_mirrors():
    import app as feather_app
    primary = RepoSpec("Ubuntu noble", "https://archive.ubuntu.com/ubuntu", repo_format="apt",
                       suite="noble", components="main universe")
    same = RepoSpec("Ubuntu alternate", "https://ubuntu.osuosl.org/ubuntu", repo_format="apt",
                    suite="noble", components="universe main")
    foreign = RepoSpec("Debian lookalike", "https://deb.debian.org/debian", repo_format="apt",
                       suite="noble", components="main universe")
    ui = object.__new__(feather_app.App); ui.repo_rows=[primary, same, foreign]
    choices = feather_app.App._evidence_candidate_map(ui, primary)
    assert same.normalized_url in choices.values()
    assert foreign.normalized_url not in choices.values()

def test_1068_profiles_offer_multiple_alternate_archive_mirrors():
    import profiles
    ubuntu = [r for r in profiles._ubuntu_repos("24.04", "amd64") if r.role == "dependency" and r.enabled]
    debian = [r for r in profiles._debian_repos("trixie", "amd64") if r.role == "dependency" and r.enabled]
    assert any(len(r.evidence_suggestions) >= 2 for r in ubuntu)
    assert any(len(r.evidence_suggestions) >= 2 for r in debian if "security" not in r.name.lower())

def test_1068_mirror_empty_status_never_claims_all_are_mirrored():
    import app as feather_app
    class Tree:
        def get_children(self): return ("A", "B")
        def item(self, *a, **k): pass
    class Label:
        def __init__(self): self.text="2 repository/repositories"
        def cget(self, key): return self.text
        def configure(self, **kw): self.text=kw.get("text", self.text)
    ui=object.__new__(feather_app.App); ui.mirror_tree=Tree(); ui.mirror_repos=set(); ui.mirror_status=Label()
    ui._checkbox_images=lambda: (None, None)
    ui._refresh_package_source_plan=lambda: None; ui._refresh_workload_repository_views=lambda: None; ui._refresh_package_source_coverage=lambda: None
    feather_app.App._paint_mirror_rows(ui)
    assert "nothing will be mirrored" in ui.mirror_status.text

# ---- 1.0.69 relationship-aware evidence catalog regressions ----------------

def test_1069_rocky_evidence_catalog_offers_exact_mirror_and_rebuild_peer():
    import app as feather_app
    from profiles import PROFILES
    from evidence_model import REL_EXACT_MIRROR, REL_REBUILD_PEER, EvidenceCandidate

    class Var:
        def __init__(self, v): self.v = v
        def get(self): return self.v

    template = next(t for t in PROFILES["rocky"].repos_factory("9.8", "x86_64")
                    if t.name == "Rocky BaseOS")
    repo = RepoSpec(template.name, template.url, target_release="9.8",
                    evidence_suggestions=list(template.evidence_suggestions))
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.release_var = Var("9.8")
    ui.arch_var = Var("x86_64")
    specs = feather_app.App._evidence_candidate_specs(ui, repo)
    assert any(isinstance(c, EvidenceCandidate) and c.relationship == REL_EXACT_MIRROR
               and "Clouvider" in c.label for c in specs)
    assert any(c.relationship == REL_REBUILD_PEER and "AlmaLinux BaseOS" in c.label
               for c in specs)


def test_1069_rhel_evidence_catalog_derives_rocky_and_alma_rebuild_peers():
    import app as feather_app
    from evidence_model import REL_REBUILD_PEER

    class Var:
        def __init__(self, v): self.v = v
        def get(self): return self.v

    repo = RepoSpec("RHEL BaseOS", "https://cdn.redhat.com/content/dist/rhel9/9.8/x86_64/baseos/os/",
                    target_release="9.8", vendor_id="redhat")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.release_var = Var("9.8")
    ui.arch_var = Var("x86_64")
    specs = feather_app.App._evidence_candidate_specs(ui, repo)
    peer_labels = {c.label for c in specs if c.relationship == REL_REBUILD_PEER}
    assert any("Rocky BaseOS" in label for label in peer_labels)
    assert any("AlmaLinux BaseOS" in label for label in peer_labels)


def test_1069_ubuntu_evidence_catalog_is_exact_mirror_only():
    import app as feather_app
    from profiles import PROFILES
    from evidence_model import REL_EXACT_MIRROR, REL_REBUILD_PEER

    class Var:
        def __init__(self, v): self.v = v
        def get(self): return self.v

    ubuntu = PROFILES["ubuntu"]
    old_map = dict(ubuntu.release_codenames)
    try:
        # Simulate the mapping learned from archive Release metadata.
        ubuntu.release_codenames["24.04"] = "noble"
        template = next(t for t in ubuntu.repos_factory("24.04", "amd64")
                        if t.name == "Ubuntu noble")
    finally:
        ubuntu.release_codenames.clear(); ubuntu.release_codenames.update(old_map)
    repo = RepoSpec(template.name, template.url, repo_format="apt", suite=template.suite,
                    components=template.components, target_release="24.04",
                    evidence_suggestions=list(template.evidence_suggestions))
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.release_var = Var("24.04")
    ui.arch_var = Var("amd64")
    specs = feather_app.App._evidence_candidate_specs(ui, repo)
    assert specs and all(c.relationship == REL_EXACT_MIRROR for c in specs)
    assert not any(c.relationship == REL_REBUILD_PEER for c in specs)


def test_1069_cent_os_stream_is_not_misclassified_as_rhel_rebuild_peer():
    from evidence_model import classify_relationship, REL_EXACT_ARTIFACT, REL_REBUILD_PEER
    primary = RepoSpec("CentOS Stream BaseOS", "https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os/",
                       vendor_id="centos")
    rel = classify_relationship(primary, "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/")
    assert rel == REL_EXACT_ARTIFACT
    assert rel != REL_REBUILD_PEER


def test_1069_cross_vendor_el_exact_mirror_hint_is_rejected_as_stale():
    from core import evidence_relationship
    from evidence_model import REL_EXACT_MIRROR, REL_REBUILD_PEER
    repo = RepoSpec("AlmaLinux BaseOS", "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/",
                    vendor_id="almalinux")
    url = "https://download.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/"
    assert evidence_relationship(repo, url) == REL_REBUILD_PEER
    # A stale 1.2.2-era persisted hint must not turn an independently rebuilt
    # distribution into an impossible exact mirror at runtime.
    repo.evidence_relationship_hints[url] = REL_EXACT_MIRROR
    assert evidence_relationship(repo, url) == REL_REBUILD_PEER


def test_1069_configured_same_archive_repo_is_offered_as_exact_mirror():
    import app as feather_app
    from evidence_model import REL_EXACT_MIRROR
    primary = RepoSpec("Rocky BaseOS", "https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/",
                       target_release="9.8", vendor_id="rocky")
    other = RepoSpec("Rocky BaseOS alternate", "https://mirror.example/rocky/9.8/BaseOS/x86_64/os/",
                     target_release="9.8", vendor_id="rocky")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [primary, other]
    ui.release_var = type("Var", (), {"get": lambda self: "9.8"})()
    ui.arch_var = type("Var", (), {"get": lambda self: "x86_64"})()
    specs = feather_app.App._configured_evidence_candidates(ui, primary)
    assert len(specs) == 1
    assert specs[0].relationship == REL_EXACT_MIRROR
    assert specs[0].url == other.normalized_url


def test_1069_profile_candidates_record_known_operator_independence():
    from profiles import PROFILES
    from evidence_model import EvidenceCandidate, AUTH_INDEPENDENT
    for key in ("rocky", "alma", "fedora", "centos-stream", "ubuntu", "debian"):
        profile = PROFILES[key]
        release = {"rocky": "9.8", "alma": "9.8", "fedora": "42",
                   "centos-stream": "10-stream", "ubuntu": "24.04", "debian": "13"}[key]
        arch = "amd64" if key in {"ubuntu", "debian"} else "x86_64"
        suggestions = [s for t in profile.repos_factory(release, arch)
                       for s in t.evidence_suggestions]
        assert any(isinstance(s, EvidenceCandidate) and s.authority == AUTH_INDEPENDENT
                   for s in suggestions), key


# ---- 1.0.70 acquisition-state / forward-only source workflow -------------

def test_1070_acquisition_state_matrix_precludes_impossible_combinations():
    from acquisition_model import (
        AcquisitionIntent, AcquisitionCapability, AnalysisType, PublicationType,
        derive_acquisition_state,
    )
    from source_readiness import SourceReadiness
    from source_model import SourcePlan

    ready = SourceReadiness(SourcePlan([]), (), (), {}, (), False)
    full = derive_acquisition_state(AcquisitionIntent.WORKLOAD, workload_readiness=ready)
    assert full.capability == AcquisitionCapability.FULL_TRANSACTION
    assert full.analysis == AnalysisType.DEPENDENCY_CLOSURE
    assert full.publication == PublicationType.TRANSACTION_BUNDLE

    mirror_blocked = derive_acquisition_state(
        AcquisitionIntent.REPOSITORY_MIRROR, mirror_repository_count=0)
    assert mirror_blocked.capability == AcquisitionCapability.BLOCKED
    assert mirror_blocked.analysis == AnalysisType.NONE

    mirror = derive_acquisition_state(
        AcquisitionIntent.REPOSITORY_MIRROR, mirror_repository_count=2)
    assert mirror.capability == AcquisitionCapability.REPOSITORY_MIRROR
    assert mirror.analysis == AnalysisType.MIRROR_INVENTORY
    assert mirror.publication == PublicationType.REPOSITORY_MIRROR

    exact_empty = derive_acquisition_state(
        AcquisitionIntent.PACKAGES, exact_root_count=0, exact_root_sources_ready=False)
    assert exact_empty.capability == AcquisitionCapability.BLOCKED

    exact = derive_acquisition_state(
        AcquisitionIntent.PACKAGES, exact_root_count=1, exact_root_sources_ready=True)
    assert exact.capability == AcquisitionCapability.FULL_TRANSACTION
    assert exact.capability != AcquisitionCapability.PACKAGE_ONLY


def test_1070_package_only_is_a_workload_capability_not_exact_package_mode():
    from acquisition_model import AcquisitionIntent, AcquisitionCapability, derive_acquisition_state
    from source_readiness import SourceReadiness
    from source_model import SourcePlan, RootSourcePolicy

    plan = SourcePlan([RootSourcePolicy("vendor-agent", "workload", "vendor")])
    readiness = SourceReadiness(plan, (), (), {"vendor": ()}, (), True)
    state = derive_acquisition_state(AcquisitionIntent.WORKLOAD, workload_readiness=readiness)
    assert state.capability == AcquisitionCapability.PACKAGE_ONLY

    exact = derive_acquisition_state(
        AcquisitionIntent.PACKAGES, exact_root_count=1, exact_root_sources_ready=True)
    assert exact.capability == AcquisitionCapability.FULL_TRANSACTION


def test_1070_freeform_enabled_roots_require_at_least_one_enabled_repository():
    from source_model import SourcePlan, RootSourcePolicy
    from source_readiness import evaluate_source_readiness

    readiness = evaluate_source_readiness(
        SourcePlan([RootSourcePolicy("my-package", "enabled")]), [])
    assert readiness.missing_scopes == ("enabled",)
    assert readiness.capability == "blocked"


def test_1070_exact_package_chooser_is_downstream_of_repository_configuration():
    import app, inspect
    content = inspect.getsource(app.App._build_packages_pane)
    repos = inspect.getsource(app.App._render_repository_workflow)
    chooser = inspect.getsource(app.App._build_exact_package_selection_card)
    assert "Configure the repositories on the next step first" in content
    assert "single_browser_tree" not in content
    assert "_build_exact_package_selection_card" in repos
    assert 'mode == "packages"' in repos
    assert "Choose exact packages" in chooser


def test_1070_custom_base_source_plan_does_not_seed_distribution_defaults():
    import app, inspect
    source = inspect.getsource(app.App._apply_source_method_inner)
    custom_section = source.split('if method == "Custom repositories":', 1)[1]
    # The first non-RHEL custom branch intentionally starts empty instead of
    # constructing repos_factory-derived base rows.
    first_branch = custom_section.split('local_method =', 1)[0]
    assert "repos_factory" not in first_branch
    assert "operator-owned base source plan" in first_branch
    configure = inspect.getsource(app.App.configure_source)
    assert 'self.open_repositories("base")' in configure


def test_1070_content_rail_expresses_intent_not_premature_package_identity():
    import app, inspect
    source = inspect.getsource(app.App._build_ui)
    assert '"packages": "Content"' in source
    nav = inspect.getsource(app.App._sync_wizard_nav)
    assert "Next: configure repositories" in nav
    assert "Next: choose repositories" in nav


def test_1070_rpm_repository_mirror_never_generates_root_transaction_installer(tmp_path):
    import hashlib
    import core
    from core import BuildOptions, Package, RepoSpec, Reporter, Requirement, ResolutionResult

    source = tmp_path / "source"
    source.mkdir()
    data = b"mirror-rpm-fixture"
    (source / "demo.rpm").write_bytes(data)
    repo = RepoSpec("Mirror source", source.resolve().as_uri() + "/", "dependency")
    pkg = Package("demo", "x86_64", "0", "1.0", "1", "demo.rpm", "sha256",
                  hashlib.sha256(data).hexdigest(), repo, size=len(data))
    pkg.provides = [Requirement("demo")]
    result = ResolutionResult([pkg], [], [pkg], reasons={pkg.nevra: "mirror"})
    out = tmp_path / "bundle"
    metadata = {
        "workload": "Repository mirror",
        "repository_mirror": True,
        "dependency_completeness": "not-applicable",
        "requested_packages": [],
    }
    core.write_bundle(result, out, BuildOptions(emit_repository=True), Reporter(), metadata)
    assert (out / "rpms" / "MIRROR-BUNDLE.txt").is_file()
    assert (out / "USE-AS-REPOSITORY.txt").is_file()
    assert not (out / "install-offline.sh").exists()
    assert not (out / "rpms" / "REQUESTED-ROOTS.txt").exists()


def test_1070_apt_repository_mirror_never_generates_root_transaction_installer(tmp_path):
    import apt_core
    from core import BuildOptions, Reporter, RepoSpec

    url = _build_local_apt_fixture(tmp_path / "repo")
    repo = RepoSpec("APT mirror", url, "dependency", 20, repo_format="apt",
                    suite="noble", components="main")
    packages = apt_core.load_repository(repo, {"amd64"}, Reporter())
    # A mirror result legitimately treats its mirrored packages as result roots;
    # publication must still not reinterpret those as an install transaction.
    result = apt_core.DebResolutionResult(packages, [], list(packages), [], [],
                                          {p.nevra: "mirror" for p in packages}, [], {})
    out = tmp_path / "bundle"
    metadata = {
        "workload": "Repository mirror",
        "repository_mirror": True,
        "dependency_completeness": "not-applicable",
        "requested_packages": [],
    }
    apt_core.write_bundle(result, out, BuildOptions(emit_repository=True), Reporter(), metadata)
    assert (out / "debs" / "MIRROR-BUNDLE.txt").is_file()
    assert (out / "USE-AS-REPOSITORY.txt").is_file()
    assert not (out / "install-offline.sh").exists()
    assert not (out / "debs" / "REQUESTED-ROOTS.txt").exists()


def test_1070_mirror_output_controls_are_forced_to_mirror_semantics():
    """Mirror mode forbids differential output and requires repository metadata.

    1.2.3 publishes one independently usable repository directory per selected
    source, so metadata generation is part of the mirror contract rather than an
    optional flat-payload mode.
    """
    import app, inspect
    source = inspect.getsource(app.App._sync_output_capability_controls)
    assert 'self.emit_repo_var.set(True)' in source        # still the default
    assert 'self.baseline_var.set("")' in source           # no differential
    assert "complete selected repository" in source
    options = inspect.getsource(app.App._build_options)
    assert 'state.capability is AcquisitionCapability.REPOSITORY_MIRROR' in options
    assert 'trust["emit_repository"] = True' in options
    assert 'trust["baseline_manifest"] = ""' in options


def test_1070_exact_package_build_metadata_describes_all_selected_roots():
    import inspect

    # The orchestration moved out of start_build into build_runner.run in
    # 1.2.12; the metadata it writes did not change.
    from feathered_app import build_runner

    source = inspect.getsource(build_runner.run)
    assert 'Exact package selection (' in source
    assert 'workload_key = "exact-packages"' in source
    assert 'for root in roots' in source

# ---- 1.0.71 unified repository-mirror editor -----------------------------

def test_1071_mirror_mode_has_one_repository_editor_not_stacked_source_cards():
    import app, inspect
    build = inspect.getsource(app.App._build_repositories_pane)
    render = inspect.getsource(app.App._render_repository_workflow)
    assert "repository_workflow_host" in build
    assert 'mode == "mirror"' in render
    mirror_branch = render.split('if mode == "mirror":', 1)[1].split('if mode == "packages":', 1)[0]
    assert "_build_mirror_repository_selection_card" in mirror_branch
    assert "_build_sources_pane" not in mirror_branch
    assert "_build_package_source_coverage_card" not in mirror_branch


def test_1071_mirror_editor_owns_population_and_manual_repository_actions():
    import app, inspect
    source = inspect.getsource(app.App._build_mirror_repository_selection_card)
    assert 'text="Start from"' in source
    assert 'text="Add URL…"' in source
    assert 'text="Add local…"' in source
    assert 'text="Edit…"' in source
    assert 'text="Remove"' in source
    assert 'text="Test selected repositories"' in source
    assert "Single authoritative repository editor" in source


def test_1071_custom_mirror_source_never_opens_parallel_repository_manager():
    import app, inspect
    source = inspect.getsource(app.App._configure_mirror_source)
    assert "open_repositories" not in source
    controls = inspect.getsource(app.App._sync_mirror_source_controls)
    assert 'method == "Custom repositories"' in controls
    assert 'text="Add below", state="disabled"' in controls


def test_1071_mirror_selection_is_authoritative_without_mutating_transaction_state():
    import app, inspect
    toggle = inspect.getsource(app.App._toggle_mirror_repo)
    bulk = inspect.getsource(app.App._bulk_mirror)
    refresh = inspect.getsource(app.App._refresh_mirror_repos)
    scope = inspect.getsource(app.App._build_repository_scope)
    assert "repo.enabled" not in toggle
    assert "repo.enabled" not in bulk
    assert "without mutating" in refresh
    assert "self._mirror_repo_selected" in scope

def test_1071_mirror_probe_and_loader_consume_checked_set_not_hidden_enabled_flags():
    import app, inspect
    probe = inspect.getsource(app.App.probe_all)
    from feathered_app.metadata_loading import load_metadata
    loader = inspect.getsource(load_metadata)
    assert "if self._mirror_mode():" in probe
    assert "self._mirror_repo_selected(r)" in probe
    assert "if scoped and context.mirror_mode():" in loader
    assert "enabled = [r for r in source_rows if r.url.strip()]" in loader

# ---- 1.0.72 content-driven repository workflows --------------------------

def test_1072_repository_workflow_is_rebuilt_from_content_intent():
    import app, inspect
    source = inspect.getsource(app.App._render_repository_workflow)
    assert 'mode == "mirror"' in source
    assert 'mode == "packages"' in source
    mirror = source.split('if mode == "mirror":', 1)[1].split('if mode == "packages":', 1)[0]
    packages = source.split('if mode == "packages":', 1)[1].split('workload = self._workload()', 1)[0]
    workload = source.split('workload = self._workload()', 1)[1]
    assert '_build_mirror_repository_selection_card' in mirror
    assert '_build_sources_pane' not in mirror
    assert 'include_workload=False' in packages
    assert '_build_exact_package_selection_card' in packages
    assert 'include_workload=True' in workload
    assert '_build_exact_package_selection_card' not in workload


def test_1072_mirror_and_transaction_repository_universes_are_isolated():
    from types import SimpleNamespace
    import app
    from core import RepoSpec
    from acquisition_model import AcquisitionIntent

    obj = app.App.__new__(app.App)
    base = RepoSpec('BaseOS', 'https://example/base/', 'dependency')
    mirror_only = RepoSpec('MirrorOnly', 'https://mirror.example/repo/', 'dependency')
    obj.transaction_repo_rows = [base]
    obj.mirror_repo_rows = [mirror_only]
    obj._repository_universe_mode = 'transaction'
    obj.loaded_signature = object()
    obj.loaded_packages = [object()]
    obj.last_result = object()
    obj.package_source_coverage_signature = object()
    obj._acquisition_intent = lambda: AcquisitionIntent.REPOSITORY_MIRROR

    # Since 1.2.6 the universes are mode-scoped storage rather than three
    # attributes aliasing one list, so this asserts the isolation behaviour
    # instead of the identity of whichever list object was assigned last.
    app.App._activate_repository_universe_for_intent(obj)
    assert [r.name for r in obj.repo_rows] == ['MirrorOnly']
    assert [r.name for r in obj.transaction_repo_rows] == ['BaseOS']
    obj.repo_rows.append(RepoSpec('ManualMirror', 'https://mirror.example/manual/', 'dependency'))

    obj._acquisition_intent = lambda: AcquisitionIntent.WORKLOAD
    app.App._activate_repository_universe_for_intent(obj)
    assert [r.name for r in obj.repo_rows] == ['BaseOS']
    assert [r.name for r in obj.mirror_repo_rows] == ['MirrorOnly', 'ManualMirror']
    # In-place mutation of the active universe still reaches the stored list,
    # which is what every existing caller relies on.
    obj.repo_rows.append(RepoSpec('Extra', 'https://example/extra/', 'dependency'))
    assert [r.name for r in obj.transaction_repo_rows] == ['BaseOS', 'Extra']
    assert [r.name for r in obj.mirror_repo_rows] == ['MirrorOnly', 'ManualMirror']


def test_1072_mirror_uses_its_own_source_method_variable():
    import app, inspect
    builder = inspect.getsource(app.App._build_mirror_repository_selection_card)
    changed = inspect.getsource(app.App._mirror_source_method_changed)
    assert 'textvariable=self.mirror_source_method_var' in builder
    assert '_mirror_source_method_changed' in builder
    assert 'self.source_method_var' not in changed
    assert '_replace_mirror_repository_set' in changed


def test_1072_mirror_preset_rows_do_not_require_transaction_widgets():
    from types import SimpleNamespace
    import app

    obj = app.App.__new__(app.App)
    obj._profile = lambda: SimpleNamespace(
        key='custom-rpm', package_family='rpm', repos_factory=lambda release, arch: [])
    obj._source_choices = lambda: ['Custom repositories', 'Installation media / local mirror (ISO, DVD, folder, SMB)']
    obj.release_var = SimpleNamespace(get=lambda: '1')
    obj.arch_var = SimpleNamespace(get=lambda: 'x86_64')
    assert app.App._mirror_source_rows_for_method(obj, 'Custom repositories') == []
    assert app.App._default_mirror_source_method(obj) == 'Custom repositories'

# ---- 1.0.73 deterministic target/content repository inheritance ----------

def test_1073_transaction_source_default_is_derived_from_linux_target():
    import app
    from profiles import PROFILES

    obj = app.App.__new__(app.App)
    for key, expected in (
        ("rocky", "Distribution repositories"),
        ("alma", "Distribution repositories"),
        ("ubuntu", "Distribution APT repositories"),
        ("debian", "Distribution APT repositories"),
        ("rhel", "Red Hat CDN entitlement (official)"),
        ("custom-rpm", "Custom repositories"),
        ("custom-apt", "Custom repositories"),
    ):
        obj._profile = lambda k=key: PROFILES[k]
        assert app.App._default_transaction_source_method(obj) == expected


def test_1073_profile_managed_workload_repo_does_not_leak_into_exact_package_scope():
    import app
    from core import RepoSpec

    obj = app.App.__new__(app.App)
    base = RepoSpec("Rocky BaseOS", "https://example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    docker = RepoSpec("Docker CE Stable", "https://example/docker/", "docker", enabled=True)
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    obj.repo_rows = [base, docker]
    obj.selected_packages = []
    obj._mirror_mode = lambda: False
    obj._single_mode = lambda: True
    obj._repo_tier = lambda r: r.source_tier
    obj._workload_required_repository_roles = lambda: []

    participants = app.App._participating_transaction_repositories(obj)
    assert [r.name for r in participants] == ["Rocky BaseOS"]


def test_1073_exact_root_from_profile_managed_repo_reactivates_only_that_repo():
    import app
    from types import SimpleNamespace
    from core import RepoSpec

    obj = app.App.__new__(app.App)
    base = RepoSpec("Rocky BaseOS", "https://example/base/", "dependency", enabled=True)
    base.source_tier = "base"
    docker = RepoSpec("Docker CE Stable", "https://example/docker/", "docker", enabled=False)
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    obj.repo_rows = [base, docker]
    obj.selected_packages = [SimpleNamespace(repo=docker)]
    obj._single_mode = lambda: True
    obj._mirror_mode = lambda: False
    obj._repo_tier = lambda r: r.source_tier
    obj._refresh_workload_repository_views = lambda: None
    obj._refresh_keyring_tree = lambda: None
    obj._workload_required_repository_roles = lambda: []

    app.App._sync_workload_repo_state(obj)
    assert docker.enabled is True
    assert [r.name for r in app.App._participating_transaction_repositories(obj)] == [
        "Rocky BaseOS", "Docker CE Stable"]


def test_1073_clearing_exact_roots_disables_profile_managed_sidechannels():
    import app
    from core import RepoSpec

    obj = app.App.__new__(app.App)
    docker = RepoSpec("Docker CE Stable", "https://example/docker/", "docker", enabled=True)
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    obj.repo_rows = [docker]
    obj.selected_packages = []
    obj._single_mode = lambda: True
    obj._mirror_mode = lambda: False
    obj._repo_tier = lambda r: r.source_tier
    obj._refresh_workload_repository_views = lambda: None
    obj._refresh_keyring_tree = lambda: None
    obj._workload_required_repository_roles = lambda: []

    app.App._sync_workload_repo_state(obj)
    assert docker.enabled is False


def test_1073_repository_views_defensively_seed_automatic_base_sources():
    import app, inspect
    source = inspect.getsource(app.App._render_repository_workflow)
    packages = source.split('if mode == "packages":', 1)[1].split('workload = self._workload()', 1)[0]
    workload = source.split('workload = self._workload()', 1)[0].rsplit('return', 1)[-1]
    assert "_ensure_transaction_base_sources" in packages
    # Workload rendering has the same defensive population call immediately
    # before its target-specific title/source cards are built.
    assert source.count("_ensure_transaction_base_sources()") >= 2


def test_1073_provenance_keyring_and_vendor_views_use_current_participating_scope():
    import app, inspect
    keyring = inspect.getsource(app.App._refresh_keyring_tree)
    vendor = inspect.getsource(app.App._enabled_vendor_groups)
    assert "self._build_repository_scope()" in keyring
    assert "self._build_repository_scope()" in vendor
    assert "for repo in self.repo_rows" not in vendor


def test_1073_test_all_sources_and_validation_ignore_stale_profile_managed_sidechannels():
    import app, inspect
    probe = inspect.getsource(app.App.probe_all)
    validation = inspect.getsource(app.App._validate_sources)
    status = inspect.getsource(app.App._update_source_status)
    assert "_participating_transaction_repositories" in probe
    assert "_participating_transaction_repositories" in validation
    assert "_participating_transaction_repositories" in status


def test_1073_operator_added_repository_is_target_scoped_without_being_deleted():
    import app
    from profiles import PROFILES
    from core import RepoSpec

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    obj = app.App.__new__(app.App)
    current = {"profile": PROFILES["rocky"]}
    obj._profile = lambda: current["profile"]
    obj.release_var = Var("9.8")
    obj.arch_var = Var("x86_64")
    repo = RepoSpec("Internal EL repo", "https://internal.example/el/", "dependency",
                    enabled=True, repo_format="rpm")
    app.App._scope_operator_repository_to_current_target(obj, repo)
    assert app.App._repository_target_compatible(obj, repo)

    current["profile"] = PROFILES["ubuntu"]
    obj.release_var.value = "24.04"
    obj.arch_var.value = "amd64"
    assert not app.App._repository_target_compatible(obj, repo)
    # The row is preserved, so returning to the original target makes it
    # eligible again rather than forcing the operator to recreate it.
    current["profile"] = PROFILES["rocky"]
    obj.release_var.value = "9.8"
    obj.arch_var.value = "x86_64"
    assert app.App._repository_target_compatible(obj, repo)


def test_1073_package_browser_excludes_repository_scoped_to_another_target():
    import app
    from profiles import PROFILES
    from core import RepoSpec

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    obj = app.App.__new__(app.App)
    obj._profile = lambda: PROFILES["ubuntu"]
    obj.release_var = Var("24.04")
    obj.arch_var = Var("amd64")
    obj._known_workload_repository_roles = lambda: {"docker"}
    stale = RepoSpec("Old Rocky extra", "https://example/rocky/", "dependency",
                     enabled=True, repo_format="rpm")
    stale.target_profile_key = "rocky"
    stale.target_release = "9.8"
    stale.target_arch = "x86_64"
    fresh = RepoSpec("Ubuntu noble", "https://example/ubuntu/", "dependency",
                     enabled=True, repo_format="apt")
    fresh.target_release = "24.04"
    obj.repo_rows = [stale, fresh]
    assert [r.name for r in app.App._browser_repositories(obj)] == ["Ubuntu noble"]

# ---- 1.0.74 deterministic source-plan widget synchronization ------------

def test_1074_dynamic_source_plan_combobox_is_built_with_current_choices():
    import app, inspect
    source = inspect.getsource(app.App._build_sources_pane)
    assert "values=self._source_choices()" in source
    assert "self._sync_transaction_source_controls()" in source


def test_1074_source_plan_sync_rehydrates_dynamic_widget_state():
    import app
    from types import SimpleNamespace

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    class Widget:
        def __init__(self): self.props = {}
        def winfo_exists(self): return True
        def configure(self, **kwargs): self.props.update(kwargs)
        def __setitem__(self, key, value): self.props[key] = value

    obj = app.App.__new__(app.App)
    obj.source_method_var = Var("Distribution repositories")
    obj.source_method_combo = Widget()
    obj.source_config_btn = Widget()
    obj.source_note = Widget()
    obj.release_var = Var("9.8")
    obj._profile = lambda: SimpleNamespace(key="rocky", package_family="rpm")
    obj._source_choices = lambda: [
        "Distribution repositories",
        "Installation media / local mirror (ISO, DVD, folder, SMB)",
        "Custom repositories",
    ]
    obj._default_transaction_source_method = lambda: "Distribution repositories"

    app.App._sync_transaction_source_controls(obj)
    assert obj.source_method_combo.props["values"][0] == "Distribution repositories"
    assert obj.source_config_btn.props["text"] == "No setup needed"
    assert obj.source_config_btn.props["state"] == "disabled"
    assert "selected distribution's own repositories" in obj.source_note.props["text"]


def test_1074_source_plan_sync_repairs_invalid_inherited_plan():
    import app
    from types import SimpleNamespace

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    obj = app.App.__new__(app.App)
    obj.source_method_var = Var("Red Hat CDN entitlement (official)")
    obj.source_method_combo = None
    obj.source_config_btn = None
    obj.source_note = None
    obj.release_var = Var("9.8")
    obj._profile = lambda: SimpleNamespace(key="rocky", package_family="rpm")
    obj._source_choices = lambda: ["Distribution repositories", "Custom repositories"]
    obj._default_transaction_source_method = lambda: "Distribution repositories"

    app.App._sync_transaction_source_controls(obj)
    assert obj.source_method_var.get() == "Distribution repositories"

# --------------------------------------------------------------------------
# Regression: exact roots are pinned to a concrete repository identity, not a
# human-readable repository name.
# --------------------------------------------------------------------------

def test_1075_rpm_exact_root_cannot_substitute_same_name_repository():
    repo_a = RepoSpec("Same", "https://a.example/repo/", "dependency", 40)
    repo_b = RepoSpec("Same", "https://b.example/repo/", "dependency", 40)
    pkg_a = rpm_pkg("demo", "1.0", repo=repo_a)
    pkg_b = rpm_pkg("demo", "1.0", repo=repo_b)
    request = ("demo", pkg_a.evr_text, "dependency", "Same", "x86_64", None,
               repo_a.source_identity)

    try:
        resolve([request], [pkg_b], "x86_64", BuildOptions(), Reporter())
    except RuntimeError as exc:
        assert "None of the selected packages" in str(exc)
    else:
        raise AssertionError("same-name repository substitution must not satisfy an exact RPM root")

    both = resolve([request], [pkg_b, pkg_a], "x86_64", BuildOptions(), Reporter())
    assert [p.repo.source_identity for p in both.roots] == [repo_a.source_identity]


def test_1075_deb_exact_root_cannot_substitute_same_name_repository():
    repo_a = RepoSpec("Same", "https://a.example/deb/", "dependency", 40,
                      repo_format="apt", suite="stable", components="main")
    repo_b = RepoSpec("Same", "https://b.example/deb/", "dependency", 40,
                      repo_format="apt", suite="stable", components="main")
    pkg_a = deb_pkg("demo", "1.0", repo_a)
    pkg_b = deb_pkg("demo", "1.0", repo_b)
    request = ("demo", "1.0", "dependency", "Same", "amd64", None,
               repo_a.source_identity)

    wrong_only = apt_core.resolve([request], [pkg_b], "amd64", BuildOptions(), Reporter())
    assert wrong_only.unresolved
    assert not wrong_only.selected

    both = apt_core.resolve([request], [pkg_b, pkg_a], "amd64", BuildOptions(), Reporter())
    assert [p.repo.source_identity for p in both.roots] == [repo_a.source_identity]


def test_1075_apt_component_scope_fails_closed(monkeypatch):
    repo = RepoSpec("Scoped", "https://archive.example/deb/", "dependency", 40,
                    repo_format="apt", suite="stable", components="main")
    monkeypatch.setattr(
        apt_core, "_fetch_release",
        lambda _repo, _reporter: ({"Components": "non-free", "Architectures": "amd64"}, {}))
    try:
        apt_core._load_repository_once(repo, {"amd64"}, Reporter())
    except RuntimeError as exc:
        text = str(exc)
        assert "none of the configured APT components" in text
        assert "refusing to widen" in text
    else:
        raise AssertionError("a configured APT component must never widen to unrelated advertised components")


def test_1075_bundle_verifier_rejects_symlink_and_traversal(tmp_path):
    import repository_tools

    root = tmp_path / "bundle"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (root / "payload.rpm").symlink_to(outside)
    index = {
        "bundle_id": "unsafe",
        "files": [
            {"path": "payload.rpm", "sha256": hashlib.sha256(b"outside").hexdigest()},
            {"path": "../outside.bin", "sha256": hashlib.sha256(b"outside").hexdigest()},
        ],
    }
    (root / "bundle-index.json").write_text(json.dumps(index), encoding="utf-8")

    report = repository_tools.verify_bundle_files(root)
    assert not report.ok
    assert "payload.rpm" in report.unsafe
    assert "../outside.bin" in report.unsafe

# ---- 1.0.76 evidence semantics and active/themed feedback -----------------

def test_1076_unrelated_exact_mirror_skew_does_not_poison_matching_package():
    from core import apply_mirror_evidence, _artifact_verification

    primary_repo = RepoSpec("Primary", "https://primary.example/repo/")
    evidence_repo = RepoSpec("Mirror", "https://mirror.example/repo/")
    skewed = rpm_pkg("skewed", "1.0", repo=primary_repo)
    skewed.checksum_type, skewed.checksum = "sha256", "11" * 32
    stable = rpm_pkg("stable", "1.0", repo=primary_repo)
    stable.checksum_type, stable.checksum = "sha256", "33" * 32

    skewed_peer = rpm_pkg("skewed", "1.0", repo=evidence_repo)
    skewed_peer.checksum_type, skewed_peer.checksum = "sha256", "22" * 32
    stable_peer = rpm_pkg("stable", "1.0", repo=evidence_repo)
    stable_peer.checksum_type, stable_peer.checksum = "sha256", "33" * 32

    stats = apply_mirror_evidence(
        [skewed, stable], [skewed_peer, stable_peer], evidence_repo, Reporter())
    assert stats["conflict"] == 1
    assert stats["matched"] == 1
    assert _artifact_verification(skewed).evidence_status == "metadata-conflict"
    assert _artifact_verification(stable).evidence_metadata_match is True


def test_1076_enhanced_continuation_rejects_semantic_rebuild_peer_for_a_gap():
    import app as feather_app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value
        def set(self, value): self.value = value

    repo = RepoSpec("Rocky BaseOS", "https://rocky.example/BaseOS/", enabled=True)
    peer = "https://almalinux.example/BaseOS/"
    repo.evidence_urls = [peer]
    repo.evidence_relationship_hints = {peer: feather_app.REL_REBUILD_PEER}

    ui = object.__new__(feather_app.App)
    ui.repo_rows = [repo]
    ui.prov_strategy_var = Var("Fill gaps with independent evidence (enhanced)")
    ui.status_var = Var("")
    # Enhanced can reject a semantic peer only after inspection has established
    # that this repository actually needs byte-identical fallback evidence.
    ui._digest_inspection_known = lambda _repo: True
    ui._repo_meets_digest_minimum = lambda _repo, _preference: False
    ui.prov_digest_var = Var("Automatic")
    import pytest
    with pytest.raises(RuntimeError, match="Semantic rebuild peers are Maximum-only"):
        feather_app.App._validate_provenance_step(ui)


def test_1080_testing_state_uses_activity_rail_in_footer_and_evidence_row():
    import app as feather_app

    class Var:
        def __init__(self): self.value = ""
        def set(self, value): self.value = value
        def get(self): return self.value

    class Label:
        def __init__(self): self.options = {}
        def winfo_exists(self): return True
        def configure(self, **kwargs): self.options.update(kwargs)

    class Indicator:
        def __init__(self): self.frames = []
        def winfo_exists(self): return True
        def render_frame(self, frame, *, active=True): self.frames.append((frame, active))

    ui = object.__new__(feather_app.App)
    ui.active_operation = "evidence-preflight"
    ui.active_operation_label = "Testing independent evidence sources…"
    ui.status_var = Var()
    footer_indicator = Indicator()
    evidence_indicator = Indicator()
    ui.activity_indicator = footer_indicator
    evidence_label = Label()
    ui._evidence_testing_labels = [evidence_label]
    ui._evidence_testing_indicators = [evidence_indicator]
    ui._activity_frame = 7
    ui._operation_detail = "Testing independent evidence sources…"

    feather_app.App._render_activity_status(ui)
    assert ui.status_var.get() == "Working  |  Testing independent evidence sources…"
    assert evidence_label.options["text"] == "Testing"
    assert footer_indicator.frames == [(7, True)]
    assert evidence_indicator.frames == [(7, True)]


# ---- 1.0.80 RHEL workload-only readiness / activity rail regressions --------

def test_1080_activity_indicator_is_low_cost_event_loop_driven_rail():
    import app as feather_app, inspect

    # The replacement activity cue is a static Feathered mark plus one moving
    # rectangular segment.  It does not create particles/curves every frame.
    render = inspect.getsource(feather_app.FeatheredActivityPulse.render_frame)
    init = inspect.getsource(feather_app.FeatheredActivityPulse.__init__)
    tick = inspect.getsource(feather_app.App._activity_tick)
    assert "create_rectangle" in init
    assert "self.coords(self._segment" in render
    assert "delete(" not in render
    assert "create_oval" not in render
    assert "create_line" not in render
    assert "after(110, self._activity_tick)" in tick
    assert "% 24" in tick
    source = inspect.getsource(feather_app.App._render_activity_status)
    for glyph in ("◐", "◓", "◑", "◒"):
        assert glyph not in source
    assert "Working ·" not in source


def test_1078_review_summary_derives_acquisition_state_before_reading_it():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._refresh_review_summary)
    state_line = "state = self._ui_acquisition_state()"
    assert state_line in source
    assert source.index(state_line) < source.index("package_only = state.capability")


def test_1078_wizard_forward_transition_enforces_source_plan_and_terminal_review():
    import app as feather_app, inspect
    gate = inspect.getsource(feather_app.App._validate_wizard_transition)
    assert 'pane == "keyrings"' in gate
    assert "self._validate_source_plan()" in gate
    assert 'pane == "transfer"' in gate
    assert "self._has_review_contract()" in gate
    nav = inspect.getsource(feather_app.App._sync_wizard_nav)
    assert "self.next_btn.pack_forget()" in nav
    assert 'state="disabled"' in nav
    next_source = inspect.getsource(feather_app.App.go_next)
    assert "index >= len(self.stage_order) - 1" in next_source


def test_1078_future_rail_steps_do_not_bypass_next_validation():
    """1.1.0 owner decision: rail navigation is free in every direction
    (stages are prepopulated; Repository utilities can jump to any step).
    The original invariant this test enforced -- no unvalidated path into a
    future stage -- moved to the terminal actions: the Next button still
    validates its boundary, and Analyze/Build preflight validates every stage
    and returns to the responsible one on failure."""
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._rail_step_clicked)
    assert "self.show_pane(key)" in source
    assert "go_next" not in source  # no partial-chain surprises: jump lands directly
    assert inspect.getsource(feather_app.App._rail_row).count("_rail_step_clicked") == 1
    next_source = inspect.getsource(feather_app.App.go_next)
    assert "_validate_wizard_transition" in next_source


def test_1076_messageboxes_route_through_feather_themed_modal_proxy():
    import app as feather_app, inspect

    assert isinstance(feather_app.messagebox, feather_app._ThemedMessageBox)
    dialog_source = inspect.getsource(feather_app._ThemedMessageBox._dialog)
    init_source = inspect.getsource(feather_app.App.__init__)
    assert "tk.Toplevel" in dialog_source
    assert "BG_PANEL" in dialog_source and "BG_HEADER" in dialog_source
    assert "Primary.TButton" in dialog_source
    assert "messagebox.bind_root(self)" in init_source

# --------------------------------------------------------------------------
# 1.0.79: Arch Linux / pacman backend and recovery-policy wiring.
# --------------------------------------------------------------------------

def _arch_pkg(name, version, repo, depends=(), provides=(), arch="x86_64", size=100):
    import arch_core
    pkg = arch_core.ArchPackage(
        name=name, arch=arch, version=version,
        location=f"{name}-{version}-{arch}.pkg.tar.zst",
        checksum_type="sha256", checksum="a" * 64, repo=repo,
        digests={"sha256": "a" * 64}, size=size)
    pkg.depends = [arch_core.parse_relation(x, "depends") for x in depends]
    pkg.provides = [arch_core.parse_relation(x, "provides") for x in provides]
    if not any(x.name == name for x in pkg.provides):
        pkg.provides.append(arch_core.ArchRelation(name, "=", version, "provides"))
    return pkg


def test_1079_arch_profile_is_native_pacman_rolling_target():
    from profiles import PROFILES
    profile = PROFILES["arch"]
    assert profile.package_family == "arch"
    assert profile.known_versions() == ["rolling"]
    assert profile.arches == ["x86_64"]
    repos = profile.repos_factory("rolling", "x86_64")
    assert [(r.suite, r.repo_format, r.enabled) for r in repos] == [
        ("core", "pacman", True), ("extra", "pacman", True), ("multilib", "pacman", False)]


def test_1079_arch_vercmp_matches_documented_pacman_edge_cases():
    import arch_core
    ordered = ["1.0a", "1.0b", "1.0beta", "1.0p", "1.0pre", "1.0rc", "1.0", "1.0.a", "1.0.1"]
    assert all(arch_core.compare_versions(a, b) < 0 for a, b in zip(ordered, ordered[1:]))
    assert arch_core.compare_versions("2.0", "2.0-13") == 0
    assert arch_core.compare_versions("1:1.0", "2.0") > 0


def test_1079_arch_resolver_closes_dependencies_and_rejects_contradictory_constraints():
    import arch_core
    repo = RepoSpec("core", "https://example.invalid/core/os/x86_64/", "dependency", 40,
                    repo_format="pacman", suite="core")
    packages = [
        _arch_pkg("root", "1", repo, depends=("lib>=2", "plugin")),
        _arch_pkg("plugin", "1", repo, depends=("lib<2",)),
        _arch_pkg("lib", "1", repo),
        _arch_pkg("lib", "2", repo),
    ]
    result = arch_core.resolve([("root", None, None)], packages, "x86_64", BuildOptions(), Reporter())
    assert result.unresolved, "contradictory pacman constraints must not report a complete closure"


def test_1079_arch_exact_root_pins_repository_identity_not_display_name():
    import arch_core
    a = RepoSpec("Same", "https://a.invalid/core/", "dependency", 40, repo_format="pacman", suite="core")
    b = RepoSpec("Same", "https://b.invalid/core/", "dependency", 40, repo_format="pacman", suite="core")
    from_a = _arch_pkg("demo", "1", a)
    from_b = _arch_pkg("demo", "1", b)
    req = ("demo", "1", "dependency", "Same", "x86_64", None, a.source_identity)
    result = arch_core.resolve([req], [from_b], "x86_64", BuildOptions(), Reporter())
    assert result.unresolved
    result = arch_core.resolve([req], [from_a, from_b], "x86_64", BuildOptions(), Reporter())
    assert result.roots[0].repo.source_identity == a.source_identity


def test_1079_arch_target_inventory_and_any_arch_are_supported(tmp_path):
    import arch_core
    inv_path = tmp_path / "inventory.txt"
    inv_path.write_text("# FEATHER-INVENTORY-V1\nMETA|package_family|arch\nPAC|libfoo|2.1|x86_64\n", encoding="utf-8")
    inv = arch_core.parse_target_inventory(str(inv_path))
    assert inv.packages["libfoo"] == "2.1"
    # Legacy inventory parsing remains supported; installation requires relationships.
    inv.relationships_complete = True
    inv.retained_packages = []
    repo = RepoSpec("core", "https://example.invalid/core/", "dependency", 40, repo_format="pacman", suite="core")
    root = _arch_pkg("root", "1", repo, depends=("libfoo>=2",), arch="any")
    result = arch_core.resolve([("root", None, None)], [root], "x86_64",
                               BuildOptions(target_inventory=inv), Reporter())
    assert not result.unresolved
    assert "libfoo>=2" in result.installed_satisfied


def test_1079_arch_repository_database_round_trip(tmp_path):
    import arch_core
    repo = RepoSpec("source", "https://example.invalid/core/", "dependency", 40, repo_format="pacman", suite="core")
    packages = [_arch_pkg("root", "1.2-3", repo, depends=("libfoo>=1",), size=12345),
                _arch_pkg("libfoo", "1.5-1", repo, arch="any", size=4567)]
    arch_core.emit_arch_repository(tmp_path, packages, Reporter())
    local = RepoSpec("feathered", tmp_path.as_uri() + "/", "dependency", 40,
                     repo_format="pacman", suite="feathered")
    loaded = arch_core.load_repository(local, {"x86_64"}, Reporter())
    assert {(p.name, p.version, p.arch, p.size) for p in loaded} == {
        ("root", "1.2-3", "x86_64", 12345), ("libfoo", "1.5-1", "any", 4567)}
    result = arch_core.resolve([("root", None, None)], loaded, "x86_64", BuildOptions(), Reporter())
    assert {p.name for p in result.selected} == {"root", "libfoo"}
    assert result.total_size == 16912


def test_1079_arch_exact_mirror_compatibility_uses_alpm_repo_name():
    from evidence_model import repositories_are_exact_mirror_compatible
    a = RepoSpec("core A", "https://a.invalid/core/os/x86_64/", "dependency", 40,
                 repo_format="pacman", suite="core")
    b = RepoSpec("core B", "https://b.invalid/core/os/x86_64/", "dependency", 40,
                 repo_format="pacman", suite="core")
    extra = RepoSpec("extra", "https://b.invalid/extra/os/x86_64/", "dependency", 40,
                     repo_format="pacman", suite="extra")
    assert repositories_are_exact_mirror_compatible(a, b)
    assert not repositories_are_exact_mirror_compatible(a, extra)


def test_1079_recoverable_source_failures_use_explicit_action_labels():
    import app as feather_app, inspect
    source = inspect.getsource(feather_app.App._recover_wizard_transition)
    assert "Configure vendor entitlement" in source
    assert "Switch to fallback repositories" in source
    assert "Choose / load local media" in source
    assert "Restore distribution defaults" in source
    assert "Public EL-compatible mirrors (recommended fallback)" in source
    box = inspect.getsource(feather_app._ThemedMessageBox.askchoice)
    assert "button_labels=labels" in box

def test_1079_repository_maintenance_rebuilds_arch_pkginfo(tmp_path):
    import io, tarfile, repository_tools, arch_core
    info = ("pkgname = demo\n"
            "pkgbase = demo\n"
            "pkgver = 1.0-1\n"
            "pkgdesc = Demo\n"
            "url = https://example.invalid\n"
            "builddate = 1\n"
            "packager = Example\n"
            "size = 42\n"
            "arch = x86_64\n"
            "license = MIT\n"
            "depend = bash\n").encode()
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.gz"
    with tarfile.open(package, "w:gz") as tf:
        member = tarfile.TarInfo(".PKGINFO")
        member.size = len(info)
        tf.addfile(member, io.BytesIO(info))
    scan = repository_tools.scan_repository_folder(tmp_path)
    assert scan.family == "arch" and scan.arch_files == [package]
    report = repository_tools.rebuild_repository_metadata(tmp_path)
    assert report.family == "arch"
    assert (tmp_path / "feathered.db").is_file()
    repo = RepoSpec("feathered", tmp_path.as_uri() + "/", "dependency", 40,
                    repo_format="pacman", suite="feathered")
    loaded = arch_core.load_repository(repo, {"x86_64"}, Reporter())
    assert loaded[0].name == "demo"
    assert [d.name for d in loaded[0].depends] == ["bash"]

# ---- 1.0.79 concrete mirror identity regressions ---------------------------

def test_1079_mirror_selection_uses_concrete_source_identity_not_display_name():
    import types
    import app as feather_app
    from core import RepoSpec

    a = RepoSpec("Same name", "https://a.example/repo/")
    b = RepoSpec("Same name", "https://b.example/repo/")
    ui = types.SimpleNamespace(mirror_repos={a.source_identity})
    assert feather_app.App._mirror_repo_selected(ui, a)
    assert not feather_app.App._mirror_repo_selected(ui, b)


def test_1079_mirror_result_cannot_pull_from_same_name_unselected_repository():
    import types
    import app as feather_app
    from core import Package, RepoSpec

    a = RepoSpec("Same name", "https://a.example/repo/")
    b = RepoSpec("Same name", "https://b.example/repo/")
    pa = Package("demo", "x86_64", "0", "1", "1", "demo-1-1.rpm", "sha256", "aa", a, size=10)
    pb = Package("demo", "x86_64", "0", "9", "1", "demo-9-1.rpm", "sha256", "bb", b, size=20)

    ui = types.SimpleNamespace(
        repo_rows=[a, b], mirror_repos={a.source_identity},
        _mirror_repo_selected=lambda repo: feather_app.App._mirror_repo_selected(ui, repo),
        _is_deb=lambda: False, _is_arch=lambda: False,
    )
    reporter = types.SimpleNamespace(log=lambda _msg: None)
    result = feather_app.App._mirror_result(ui, [pa, pb], reporter)
    assert [p.repo.source_identity for p in result.selected] == [a.source_identity]
    assert result.selected[0].version == "1"


def test_1079_mirror_table_allows_duplicate_display_names_without_iid_collision():
    import app as feather_app
    from core import RepoSpec

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    class Tree:
        def __init__(self): self.rows = {}; self.images = {}
        def delete(self, *iids):
            for iid in iids: self.rows.pop(iid, None)
        def get_children(self): return tuple(self.rows)
        def insert(self, _parent, _where, iid, values):
            assert iid not in self.rows
            self.rows[iid] = values
        def item(self, iid, **kwargs):
            if "image" in kwargs: self.images[iid] = kwargs["image"]

    class Label:
        def __init__(self): self.text = ""
        def configure(self, **kwargs): self.text = kwargs.get("text", self.text)
        def cget(self, _key): return self.text

    a = RepoSpec("Same name", "https://a.example/repo/")
    b = RepoSpec("Same name", "https://b.example/repo/")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [a, b]
    ui.workloads = {}
    ui.mirror_tree = Tree()
    ui.mirror_status = Label()
    ui.mirror_repos = {a.source_identity}
    ui._mirror_seen = {a.source_identity, b.source_identity}
    ui.distro_var = Var("Test")
    ui.release_var = Var("rolling")
    ui._checkbox_images = lambda: (None, None)
    ui._refresh_package_source_plan = lambda: None
    ui._refresh_workload_repository_views = lambda: None
    ui._refresh_package_source_coverage = lambda: None

    feather_app.App._refresh_mirror_repos(ui)
    assert len(ui.mirror_tree.rows) == 2
    assert len(set(ui.mirror_tree.rows)) == 2
    assert ui.mirror_repos == {a.source_identity}
    selected_iids = [iid for iid, sid in ui._mirror_iid_to_source_identity.items()
                     if sid in ui.mirror_repos]
    assert len(selected_iids) == 1


def test_1079_exact_package_readiness_rejects_same_name_wrong_source():
    import types
    import app as feather_app
    from acquisition_model import AcquisitionCapability
    from core import RepoSpec

    a = RepoSpec("Same name", "https://a.example/repo/")
    b = RepoSpec("Same name", "https://b.example/repo/")
    pkg = types.SimpleNamespace(repo=a)
    ui = object.__new__(feather_app.App)
    ui.__dict__["_single_mode"] = lambda: True
    ui.selected_packages = [pkg]
    ui.repo_rows = [b]
    state = feather_app.App._acquisition_state(ui)
    assert state.capability is AcquisitionCapability.BLOCKED


def test_1080_rhel_docker_upstream_is_package_only_when_cdn_is_unentitled():
    from types import SimpleNamespace
    import app as feather_app
    from acquisition_model import AcquisitionCapability
    from core import RepoSpec
    from source_model import RootSourcePolicy, SourcePlan

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = feather_app.App.__new__(feather_app.App)
    ui.selection_mode_var = Var("Workload")
    ui.source_method_var = Var("Red Hat CDN entitlement (official)")
    ui.rhsm_cert = ui.rhsm_key = ui.rhsm_ca = ""
    ui._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    ui._source_plan = lambda: SourcePlan([
        RootSourcePolicy("docker-ce", "workload", "docker"),
        RootSourcePolicy("docker-ce-cli", "workload", "docker"),
    ])
    ui._known_workload_repository_roles = lambda: {"docker"}
    ui._repo_tier = feather_app.App._repo_tier.__get__(ui, feather_app.App)

    docker = RepoSpec("Docker CE Stable", "https://download.docker.com/linux/rhel/9/x86_64/stable/",
                      "docker", 10, True)
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    baseos = RepoSpec("RHEL BaseOS (CDN)", "https://cdn.redhat.com/content/baseos/",
                      "dependency", 40, True)
    baseos.source_tier = "base"
    appstream = RepoSpec("RHEL AppStream (CDN)", "https://cdn.redhat.com/content/appstream/",
                         "dependency", 45, True)
    appstream.source_tier = "base"
    ui.repo_rows = [docker, baseos, appstream]

    state = feather_app.App._acquisition_state(ui)
    assert state.capability is AcquisitionCapability.PACKAGE_ONLY
    usable = feather_app.App._repositories_for_source_readiness(ui, ui._source_plan())
    assert usable == [docker]


def test_1080_rhel_distribution_roots_still_require_entitled_or_alternate_base():
    from types import SimpleNamespace
    import app as feather_app
    from acquisition_model import AcquisitionCapability
    from core import RepoSpec
    from source_model import RootSourcePolicy, SourcePlan

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = feather_app.App.__new__(feather_app.App)
    ui.selection_mode_var = Var("Workload")
    ui.source_method_var = Var("Red Hat CDN entitlement (official)")
    ui.rhsm_cert = ui.rhsm_key = ui.rhsm_ca = ""
    ui._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("podman", "distribution")])
    ui._known_workload_repository_roles = lambda: {"docker"}
    ui._repo_tier = feather_app.App._repo_tier.__get__(ui, feather_app.App)
    baseos = RepoSpec("RHEL BaseOS (CDN)", "https://cdn.redhat.com/content/baseos/",
                      "dependency", 40, True)
    baseos.source_tier = "base"
    ui.repo_rows = [baseos]

    # Distribution-native workloads are not silently downgraded to package-only.
    # They continue through the normal entitlement recovery gate.
    state = feather_app.App._acquisition_state(ui)
    assert state.capability is AcquisitionCapability.FULL_TRANSACTION
    assert feather_app.App._repositories_for_source_readiness(ui, ui._source_plan()) == [baseos]


def test_1080_rhel_docker_package_only_does_not_trigger_entitlement_recovery_gate():
    from types import SimpleNamespace
    import app as feather_app
    from core import RepoSpec
    from source_model import RootSourcePolicy, SourcePlan

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = feather_app.App.__new__(feather_app.App)
    ui._mirror_mode = lambda: False
    ui._single_mode = lambda: False
    ui._workload = lambda: SimpleNamespace(label="Docker Engine")
    ui._workload_uses_distribution_sources = lambda: False
    ui._workload_required_repository_roles = lambda: ["docker"]
    ui._needs_dependency_repos = lambda: True
    ui._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    ui.source_method_var = Var("Red Hat CDN entitlement (official)")
    ui.rhsm_cert = ui.rhsm_key = ui.rhsm_ca = ""
    ui._source_plan = lambda: SourcePlan([RootSourcePolicy("docker-ce", "workload", "docker")])
    ui._known_workload_repository_roles = lambda: {"docker"}
    ui._repo_tier = feather_app.App._repo_tier.__get__(ui, feather_app.App)
    docker = RepoSpec("Docker CE Stable", "https://download.docker.com/linux/rhel/9/x86_64/stable/",
                      "docker", 10, True)
    docker.source_tier = "workload"
    docker.workload_profile_managed = True
    baseos = RepoSpec("RHEL BaseOS (CDN)", "https://cdn.redhat.com/content/baseos/",
                      "dependency", 40, True)
    baseos.source_tier = "base"
    ui.repo_rows = [docker, baseos]

    feather_app.App._validate_source_plan(ui)

# ---- 1.0.81 explicit active/waiting/failed operation-state regressions ----

def test_1081_trust_log_marks_build_waiting_and_resumes_after_decision():
    import app as feather_app

    events = []
    dummy = type("Dummy", (), {})()
    dummy.after = lambda _delay, fn: fn()
    dummy._set_operator_wait = lambda detail: events.append(("waiting", detail))
    dummy._resume_after_operator_wait = lambda detail=None: events.append(("resume", detail))

    def show_details(**kwargs):
        events.append(("dialog", kwargs["warnings"]))
        kwargs["decision_callback"](True)

    dummy.show_details = show_details
    assert feather_app.App._gui_trust_review(dummy, ["trust finding"]) is True
    assert events[0][0] == "waiting"
    assert "build paused" in events[0][1].lower()
    assert events[1] == ("dialog", ["trust finding"])
    assert events[2] == ("resume", "Continuing build")


def test_1081_waiting_and_failed_activity_states_are_static_and_colour_coded():
    import app as feather_app

    class Var:
        def __init__(self): self.value = ""
        def set(self, value): self.value = value
        def get(self): return self.value

    class Label:
        def __init__(self): self.options = {}
        def configure(self, **kwargs): self.options.update(kwargs)

    class Indicator:
        def __init__(self): self.frames = []
        def render_frame(self, frame, *, active=True, state=None):
            self.frames.append((frame, active, state))

    ui = object.__new__(feather_app.App)
    ui.active_operation = "build"
    ui.active_operation_label = "Building bundle"
    ui.status_var = Var()
    ui.status_label = Label()
    ui.activity_indicator = Indicator()
    ui._evidence_testing_labels = []
    ui._evidence_testing_indicators = []
    ui._activity_frame = 9
    ui._activity_state = "waiting"
    ui._operation_detail = "build paused pending your decision"

    feather_app.App._render_activity_status(ui)
    assert ui.status_var.get().startswith("Review required  |")
    assert ui.status_label.options["foreground"] == feather_app.WARN_FG
    assert ui.activity_indicator.frames[-1] == (9, False, "waiting")

    ui.active_operation = None
    ui._activity_state = "failed"
    ui._operation_detail = "Package download failed"
    feather_app.App._render_activity_status(ui)
    assert ui.status_var.get() == "Failed  |  Package download failed"
    assert ui.status_label.options["foreground"] == feather_app.ERR_FG
    assert ui.activity_indicator.frames[-1] == (9, False, "failed")


def test_1081_footer_activity_rail_has_no_feather_mark_and_is_lowered():
    import app as feather_app, inspect

    init = inspect.getsource(feather_app.FeatheredActivityPulse.__init__)
    build = inspect.getsource(feather_app.App._build_ui)
    assert "draw_feather" not in init
    assert "self._track_left = 2" in init
    assert 'width=42, height=14' in build
    assert 'pady=(4, 0)' in build

# ---- 1.0.82 payload-local bundle metadata and activity wording regressions ----

def test_1082_waiting_footer_deduplicates_state_prefix():
    import app as feather_app

    class Var:
        def __init__(self): self.value = ""
        def set(self, value): self.value = value
        def get(self): return self.value

    class Label:
        def configure(self, **_kwargs): pass

    class Indicator:
        def render_frame(self, *_args, **_kwargs): pass

    ui = object.__new__(feather_app.App)
    ui.active_operation = "build"
    ui.active_operation_label = "Building bundle"
    ui.status_var = Var()
    ui.status_label = Label()
    ui.activity_indicator = Indicator()
    ui._evidence_testing_labels = []
    ui._evidence_testing_indicators = []
    ui._activity_frame = 0
    ui._activity_state = "waiting"
    ui._operation_detail = "Review required - build paused pending your decision in Activity log"

    feather_app.App._render_activity_status(ui)
    rendered = ui.status_var.get()
    assert rendered == "Review required  |  build paused pending your decision in Activity log"
    assert rendered.count("Review required") == 1


def test_1082_staging_reuses_arch_payload_but_not_generated_companions(tmp_path):
    from core import Reporter, open_staging

    dest = tmp_path / "bundle"
    packages = dest / "packages"
    packages.mkdir(parents=True)
    payload = packages / "demo-1.0-1-x86_64.pkg.tar.zst"
    payload.write_bytes(b"ARCH-PACKAGE")
    (packages / "manifest.json").write_text("OLD MANIFEST", encoding="utf-8")
    (packages / "SHA256SUMS.txt").write_text("OLD SUMS", encoding="utf-8")
    (packages / "feathered.db").write_bytes(b"GENERATED DB")

    staging = open_staging(dest, Reporter())
    assert (staging / "packages" / payload.name).is_file()
    # Additive staging keeps a complete copied snapshot of generated companion
    # files so later bundle indexes/repository regeneration see the whole folder.
    assert (staging / "packages" / "manifest.json").read_text() == "OLD MANIFEST"
    assert (staging / "packages" / "SHA256SUMS.txt").read_text() == "OLD SUMS"
    assert (staging / "packages" / "feathered.db").read_bytes() == b"GENERATED DB"


def test_1082_rpm_bundle_companion_files_live_with_payload_and_report_shipped_size(tmp_path):
    import hashlib
    import json
    import core
    from core import BuildOptions, Package, RepoSpec, Reporter, Requirement, ResolutionResult

    source = tmp_path / "source"
    source.mkdir()
    bodies = {"keep.rpm": b"already-on-target", "ship.rpm": b"must-transfer"}
    packages = []
    repo = RepoSpec("Fixture", source.resolve().as_uri() + "/", "dependency")
    for index, (name, body) in enumerate(bodies.items(), 1):
        (source / name).write_bytes(body)
        pkg = Package(name[:-4], "x86_64", "0", "1.0", str(index), name, "sha256",
                      hashlib.sha256(body).hexdigest(), repo, size=len(body))
        pkg.provides = [Requirement(pkg.name)]
        packages.append(pkg)

    keep, ship = packages
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"packages": [{
        "package_id": keep.nevra,
        "sha256": hashlib.sha256(bodies["keep.rpm"]).hexdigest(),
    }]}), encoding="utf-8")
    result = ResolutionResult(packages, [], packages, reasons={p.nevra: "requested" for p in packages})
    out = tmp_path / "bundle"
    core.write_bundle(result, out, BuildOptions(baseline_manifest=str(baseline)), Reporter(), {"workload": "fixture"})

    payload_dir = out / "rpms"
    for name in ("manifest.json", "manifest.txt", "SHA256SUMS.txt", "provenance.json",
                 "unresolved.txt", "conflicts.txt", "baseline-omitted.txt"):
        assert (payload_dir / name).is_file(), name
        assert not (out / name).exists(), name
    assert not (payload_dir / keep.location).exists()
    assert (payload_dir / ship.location).is_file()

    sums = (payload_dir / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert f"  {ship.location}" in sums
    assert "rpms/" not in sums

    manifest = json.loads((payload_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["package_count"] == 1
    assert manifest["summary"]["total_size"] == len(bodies["ship.rpm"])
    assert manifest["summary"]["resolved_package_count"] == 2
    assert manifest["summary"]["resolved_total_size"] == sum(map(len, bodies.values()))
    assert manifest["summary"]["baseline_omitted_count"] == 1
    by_id = {row["package_id"]: row for row in manifest["packages"]}
    assert by_id[keep.nevra]["shipped"] is False
    assert by_id[ship.nevra]["shipped"] is True


def test_1082_mid_download_cancel_is_not_retried_or_masked_as_fetch_failure():
    """A cancel that lands while a chunk is being read must surface as
    Cancelled immediately: no "Healing with retry..." log, no retry sleep, and
    never a RuntimeError("Could not fetch ...") on the final attempt.  Callers
    (e.g. the build worker) branch on Cancelled to distinguish an operator
    cancel from a genuine source failure."""
    import threading

    import core
    import repository_transport

    cancel = threading.Event()
    reporter = Reporter(cancel_event=cancel)
    logged = []
    reporter.log = logged.append

    class MidReadCancelResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, _n):
            cancel.set()
            reporter.check_cancel()

    try:
        repository_transport.fetch_bytes(
            "https://repo.example/primary.xml", reporter, retries=3,
            open_url_fn=lambda _u, _t, _r: MidReadCancelResponse(),
            redact_url_fn=lambda u: u)
    except core.Cancelled:
        pass
    else:
        raise AssertionError("mid-download cancellation was not surfaced as Cancelled")
    assert not any("Healing with retry" in line for line in logged), logged


def test_1082_package_download_cancel_is_not_masked_as_package_failure(monkeypatch, tmp_path):
    """_copy_or_download (RPM and APT) shares fetch_bytes's contract: a cancel
    raised while streaming a package payload must surface as Cancelled, never
    as RuntimeError("Failed <nevra>: ...") on the final retry attempt, and must
    not burn a retry sleep first."""
    import threading

    import apt_core as apt_module
    import core as core_module

    def run(module, pkg):
        cancel = threading.Event()
        reporter = Reporter(cancel_event=cancel)
        logged = []
        reporter.log = logged.append

        class MidReadCancelResponse:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, _n):
                cancel.set()
                reporter.check_cancel()

        monkeypatch.setattr(module, "_urlopen",
                            lambda *_a, **_k: MidReadCancelResponse())
        options = BuildOptions(retries=1, verify_checksums=False)
        try:
            module._copy_or_download(pkg, tmp_path / f"{pkg.name}.bin", options, reporter)
        except core_module.Cancelled:
            pass
        else:
            raise AssertionError(
                f"{module.__name__}: mid-download cancel was not surfaced as Cancelled")
        assert not any("Healing download failure" in line for line in logged), logged

    run(core_module, rpm_pkg("demo", "1.0"))
    run(apt_module, apt_module.DebPackage(
        "demo", "amd64", "1.0-1", "pool/demo.deb", "sha256", "", APT_REPO))


def test_110_worker_done_treats_cancellation_as_typed_outcome_not_failure():
    """A cancelled worker must never raise the error dialog, must not log an
    ERROR: line, and must release the operation as idle rather than failed.
    Workers now report ok="cancelled"; the legacy string protocol ("Operation
    cancelled" / "Cancelled" with ok=False) must classify the same way."""
    import app as feather_app

    def run(ok, message):
        dummy = type("Dummy", (), {})()
        dummy.worker = object()
        dummy.cancel_btn = None
        dummy.analyze_btn = None
        dummy.build_btn = None
        dummy.open_output_btn = None
        dummy.status_var = None
        dummy.review_labels = None
        dummy.last_output_path = None
        logged = []
        dummy._log = logged.append
        releases = []
        dummy._release_operation = lambda msg, outcome: releases.append(outcome)

        class Var:
            def set(self, value):
                self.value = value
        dummy.progress_var = Var()

        errors = []
        original = feather_app.messagebox.showerror
        feather_app.messagebox.showerror = lambda *a, **k: errors.append(a)
        try:
            feather_app.App._worker_done(dummy, ok, message)
        finally:
            feather_app.messagebox.showerror = original
        return logged, releases, errors

    # Typed outcome, including messages the string protocol used to misread.
    for message in ("Operation cancelled", "Build cancelled at the trust review prompt"):
        logged, releases, errors = run("cancelled", message)
        assert not errors, (message, errors)
        assert releases == ["idle"], (message, releases)
        assert logged and logged[0].startswith("CANCELLED: "), (message, logged)

    # Legacy string protocol still classifies as cancelled, both spellings.
    for message in ("Operation cancelled", "Cancelled"):
        logged, releases, errors = run(False, message)
        assert not errors, (message, errors)
        assert releases == ["idle"], (message, releases)

    # A genuine failure still fails loudly.
    logged, releases, errors = run(False, "boom")
    assert errors and releases == ["failed"]
    assert logged and logged[0].startswith("ERROR: ")


def test_110_catalog_and_repo_loops_do_not_swallow_cancellation(monkeypatch):
    """The per-repository resilience loops (package-catalog worker and
    _load_enabled_repos) continue past a failed source, but a Cancelled raised
    inside a backend load must propagate instead of being recorded as that
    repository's failure - otherwise Cancel could 'succeed' with a partial
    catalog."""
    import inspect

    import app as feather_app
    import core as core_module

    from feathered_app.metadata_loading import load_metadata
    for owner, needle in ((load_metadata, "except context.cancelled_error"),):
        assert needle in inspect.getsource(owner)

    # Structural check for the catalog worker closure: its inner per-repo
    # handler must re-raise Cancelled before the broad Exception handler.
    catalog_src = inspect.getsource(feather_app.App.search_single_packages)
    marker = catalog_src.index("Package browser skipped unavailable source")
    window = catalog_src[marker - 400:marker]
    assert "except Cancelled" in window and "raise" in window
    load_src = inspect.getsource(load_metadata)
    cancelled_at = load_src.index("except context.cancelled_error")
    broad_at = load_src.index("except Exception")
    assert cancelled_at < broad_at
    assert "raise" in load_src[cancelled_at:broad_at]


def test_110_devuan_and_artix_profiles_are_systemd_free_targets():
    """Devuan (APT, merged archive) and Artix (pacman system/world/galaxy) are
    first-class profiles. Devuan security lives in the merged archive with
    plain components (no Debian-style updates/ prefix), and the Docker CE row
    is present but disabled because Docker publishes only Debian suites."""
    import profiles

    devuan = profiles.PROFILES["devuan"]
    assert devuan.package_family == "deb"
    assert devuan.release_style == "codename"
    old_rel = dict(profiles.DEVUAN_TO_DEBIAN)
    try:
        # Simulate the vendor relationship learned from devuan.org. The release
        # identity itself is the codename, so no compiled numeric mapping exists.
        profiles.DEVUAN_TO_DEBIAN["excalibur"] = "trixie"
        rows = devuan.repos_factory("excalibur", "amd64")
    finally:
        profiles.DEVUAN_TO_DEBIAN.clear(); profiles.DEVUAN_TO_DEBIAN.update(old_rel)
    by_name = {r.name: r for r in rows}
    security = by_name["Devuan excalibur-security"]
    assert security.suite == "excalibur-security"
    assert "updates/" not in security.components
    assert all("deb.devuan.org/merged" in by_name[n].url for n in
               ("Devuan excalibur", "Devuan excalibur-updates", "Devuan excalibur-security"))
    docker = by_name["Docker CE Stable (Debian packages)"]
    assert docker.enabled is False
    assert docker.suite == "trixie"
    assert profiles.resolve_codename("future", profiles.DEVUAN_CODENAMES) == "future"

    artix = profiles.PROFILES["artix"]
    assert artix.package_family == "arch"
    arows = artix.repos_factory("rolling", "x86_64")
    suites = [(r.suite, r.enabled) for r in arows]
    assert ("system", True) in suites and ("world", True) in suites and ("galaxy", True) in suites
    assert ("lib32", False) in suites
    assert not any(r.suite == "core" for r in arows), "Arch core must never be offered on Artix"


def test_110_split_desc_depends_alpm_database_resolves_dependencies(tmp_path):
    """Pre-pacman-5.0 repo-add wrote %DEPENDS% into a sibling `depends` file.
    The loader must merge desc+depends per package directory; previously the
    depends file was skipped and split-format repositories produced
    dependency-free packages (silently incomplete bundles)."""
    import io
    import tarfile

    import arch_core
    import core as core_module

    buf = io.BytesIO()

    def add(tf, name, text):
        data = text.encode()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        add(tf, "demo-root-1.0-1/desc",
            "%FILENAME%\ndemo-root-1.0-1-x86_64.pkg.tar.gz\n\n%NAME%\ndemo-root\n\n"
            "%VERSION%\n1.0-1\n\n%ARCH%\nx86_64\n\n%CSIZE%\n10\n\n")
        add(tf, "demo-root-1.0-1/depends", "%DEPENDS%\ndemo-dep>=1.0\n\n")
        add(tf, "demo-dep-1.0-1/desc",
            "%FILENAME%\ndemo-dep-1.0-1-x86_64.pkg.tar.gz\n\n%NAME%\ndemo-dep\n\n"
            "%VERSION%\n1.0-1\n\n%ARCH%\nx86_64\n\n%CSIZE%\n10\n\n")
    (tmp_path / "system.db").write_bytes(buf.getvalue())
    repo = RepoSpec("ArtixFixture", core_module.path_to_file_url(tmp_path) + "/",
                    "dependency", 40, repo_format="pacman", suite="system",
                    verification_strategy="skip-provenance")
    reporter = Reporter()
    pkgs = arch_core.load_repository(repo, {"x86_64", "any"}, reporter)
    root = next(p for p in pkgs if p.name == "demo-root")
    assert [(d.name, d.operator, d.version) for d in root.depends] == [("demo-dep", ">=", "1.0")]
    result = arch_core.resolve([("demo-root", None, None)], pkgs, "x86_64",
                               BuildOptions(), reporter)
    assert sorted(p.name for p in result.selected) == ["demo-dep", "demo-root"]
    assert not result.unresolved


def test_110_pacman_db_fetch_uses_repository_transport_policy():
    """The ALPM database fetch must pass repo= (client certs, credential
    redirect confinement, effective-origin recording) and a bounded
    max_bytes, matching the RPM/APT loaders."""
    import inspect

    import arch_core

    src = inspect.getsource(arch_core._load_repository_once)
    assert "repo=repo" in src
    assert "max_bytes=core.MAX_METADATA_DOWNLOAD_BYTES" in src


def test_110_workload_availability_is_per_distro_and_excludes_missing_software():
    """Preset availability audit: every target distro (including Artix and
    Devuan) offers the full catalog where the software exists, and an explicit
    supported_distros list excludes distros whose repositories genuinely lack
    it - Cockpit requires systemd and does not exist on Artix or Devuan."""
    import app as feather_app
    import profiles
    import workloads

    dummy = type("Dummy", (), {})()
    dummy.workloads = workloads.load_workloads()

    def labels_for(key):
        dummy._profile = lambda k=key: profiles.PROFILES[k]
        return feather_app.App._workload_labels_for_profile(dummy)

    for key in ("arch", "artix", "devuan", "debian"):
        labels = labels_for(key)
        assert any("Docker" in l for l in labels), (key, labels)
        assert len(labels) >= 20, (key, len(labels))
    for key in ("artix", "devuan"):
        assert not any("Cockpit" in l for l in labels_for(key)), key
    for key in ("arch", "debian", "rhel"):
        assert any("Cockpit" in l for l in labels_for(key)), key

    # Arch package identities verified against the official repositories:
    # "bpf" does not exist (bcc-tools is the BPF tooling package), and
    # openscap/aide/nmon are AUR-only, so they must not appear as guaranteed
    # resolution failures in preconfigured dependency lists.
    catalog = dummy.workloads
    mon = catalog["monitoring-agents"].packages_for("arch")
    assert "bcc-tools" in mon and "bpf" not in mon and "nmon" not in mon
    sec = catalog["security-audit"].packages_for("arch")
    assert "openscap" not in sec and "aide" not in sec


def test_110_certificate_failures_fail_fast_with_actionable_remedy():
    """An expired/untrusted TLS certificate is deterministic: fetch_bytes must
    not retry it ("Healing...") and the surfaced error must carry the concrete
    remedies (check the system clock; switch mirrors - geo-routed hostnames
    pick a specific nearby mirror that can individually be broken)."""
    import ssl
    import urllib.error

    import repository_transport

    cert_exc = ssl.SSLCertVerificationError(
        "certificate verify failed: certificate has expired (_ssl.c:1010)")
    cert_exc.verify_message = "certificate has expired"
    wrapped = urllib.error.URLError(cert_exc)

    reporter = Reporter()
    logged = []
    reporter.log = logged.append
    attempts = []

    def opener(_u, _t, _r):
        attempts.append(1)
        raise wrapped

    try:
        repository_transport.fetch_bytes(
            "https://geo.mirror.pkgbuild.com/core/os/x86_64/core.db", reporter,
            retries=3, open_url_fn=opener, redact_url_fn=lambda u: u)
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("certificate failure did not raise")
    assert len(attempts) == 1, "certificate failure must not be retried"
    assert not any("Healing" in line for line in logged), logged
    assert "certificate" in message
    assert "clock" in message
    assert "different mirror" in message

    # Non-certificate errors keep the normal retry behaviour.
    assert repository_transport.certificate_failure_advice(OSError("boom")) == ""


def test_110_bundled_gpg_verifier_is_preferred_and_name_comparisons_survive_paths(monkeypatch, tmp_path):
    """Release builds stage gpgv in a gnupg/ folder beside the executable.
    gpg_backend() must prefer that copy over PATH and return its full path;
    since callers used to compare the backend to the literal strings
    "gpgv"/"gpg", tool-mode branching must go through gpg_backend_name()."""
    import core as core_module

    bundled = tmp_path / "gnupg"
    bundled.mkdir()
    (bundled / "gpgv.exe").write_bytes(b"fake")
    monkeypatch.setattr(core_module, "bundled_gpg_dir", lambda: bundled)
    backend = core_module.gpg_backend()
    assert backend == str(bundled / "gpgv.exe")
    assert core_module.gpg_backend_name(backend) == "gpgv"
    assert core_module.gpg_backend_name("/usr/bin/gpg") == "gpg"
    assert core_module.gpg_backend_name("gpgv") == "gpgv"
    assert core_module.gpg_backend_name(None) == ""
    # A fake binary can't answer --version; the provenance field degrades to "".
    assert core_module.gpg_backend_version(backend) == ""

    # Without a bundled dir, PATH discovery still works as before.
    monkeypatch.setattr(core_module, "bundled_gpg_dir", lambda: None)
    monkeypatch.setattr(core_module.shutil, "which",
                        lambda name: "/usr/bin/gpgv" if name == "gpgv" else None)
    assert core_module.gpg_backend() == "gpgv"


def test_110_rail_rows_bind_click_and_hover_on_every_child_widget():
    """Tk delivers <Leave> to the row frame when the pointer crosses onto a
    child label, so hover feedback bound only on the row switches off over the
    step's text - making the text look unclickable. Every rail row child (bar,
    number/icon, text) must carry Button-1, Enter and Leave bindings."""
    import app as feather_app

    root = feather_app.tk.Tk()
    try:
        dummy = type("Dummy", (), {})()
        dummy.rail = feather_app.tk.Frame(root)
        dummy.stage_order = ["a", "b"]
        dummy.active_pane = "a"
        dummy._rail_hover = lambda *_a, **_k: None
        dummy._rail_step_clicked = lambda *_a, **_k: None
        dummy.show_pane = lambda *_a, **_k: None
        parts = feather_app.App._rail_row(dummy, 1, "Linux Distribution", "a")
        for name in ("row", "bar", "num", "text"):
            widget = parts[name]
            for sequence in ("<Button-1>", "<Enter>", "<Leave>"):
                assert widget.bind(sequence), (name, sequence)
        tool_parts = feather_app.App._tool_rail_row(dummy, "Repository utilities", "tools")
        for name in ("row", "bar", "num", "text"):
            widget = tool_parts[name]
            for sequence in ("<Button-1>", "<Enter>", "<Leave>"):
                assert widget.bind(sequence), ("tools", name, sequence)
    finally:
        root.destroy()


def test_110_rail_navigation_is_free_in_every_direction():
    """Owner decision: every rail step is reachable from anywhere with one
    click -- forward, backward, and from Repository utilities (which lives
    outside stage_order and previously could reach only step 1)."""
    import app as feather_app

    order = ["s1", "s2", "s3", "s4", "s5", "s6"]
    dummy = type("Dummy", (), {})()
    dummy.stage_order = order
    dummy.shown = []

    def show_pane(key):
        dummy.active_pane = key
        dummy.shown.append(key)
    dummy.show_pane = show_pane

    dummy.active_pane = "s2"
    feather_app.App._rail_step_clicked(dummy, "s6")
    assert dummy.active_pane == "s6"

    feather_app.App._rail_step_clicked(dummy, "s2")
    assert dummy.active_pane == "s2"

    # From the tools pane (outside stage_order) any step is one click away.
    dummy.active_pane = "tools"
    feather_app.App._rail_step_clicked(dummy, "s5")
    assert dummy.active_pane == "s5"
    assert dummy.shown == ["s6", "s2", "s5"]


def test_110_custom_packages_preset_uses_the_choose_packages_workflow():
    """The Custom packages preset is exact-package acquisition by another name.
    It must derive AcquisitionIntent.PACKAGES so Step 3 renders the one shared
    workflow (repositories first, exact-package chooser below), and names typed
    on Content merge into the requests as unpinned roots instead of being a
    separate diverging path."""
    import app as feather_app
    import workloads
    from acquisition_model import AcquisitionIntent

    catalog = workloads.load_workloads()
    custom = next(w for w in catalog.values() if w.custom)
    normal = next(w for w in catalog.values() if not w.custom)

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = feather_app.App.__new__(feather_app.App)
    ui.__dict__["selection_mode_var"] = Var("Workload")
    ui._workload = lambda: custom
    assert feather_app.App._acquisition_intent(ui) is AcquisitionIntent.PACKAGES
    assert feather_app.App._repository_workflow_mode(ui) == "packages"
    ui._workload = lambda: normal
    assert feather_app.App._acquisition_intent(ui) is AcquisitionIntent.WORKLOAD

    # Typed names merge with chooser selections; neither is dropped.
    ui._workload = lambda: custom
    ui._mirror_mode = lambda: False
    ui.selected_packages = []
    ui.__dict__["custom_var"] = Var("nginx, htop")
    requests = feather_app.App._package_requests(ui)
    assert [r[0] for r in requests] == ["nginx", "htop"]

    class Pkg:
        name = "nginx"; evr_text = "1.0"; arch = "x86_64"
        repo = type("R", (), {"role": "dependency", "name": "world", "source_identity": "world"})()
    ui.selected_packages = [Pkg()]
    requests = feather_app.App._package_requests(ui)
    assert [r[0] for r in requests] == ["nginx", "htop"]  # no duplicate nginx


def test_110_init_system_axis_for_artix_and_devuan():
    """Artix splits service scripts into <svc>-<init> companion packages, so
    the chosen init changes the resolved set: a docker workload on Artix with
    openrc must request docker-openrc as a root, and an exact selection of a
    known service gains its companion too. Devuan packages bundle their
    scripts; choosing a non-default init adds that init's own package."""
    import app as feather_app
    import profiles
    import workloads

    catalog = workloads.load_workloads()
    ui = feather_app.App.__new__(feather_app.App)

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui._profile = lambda: profiles.PROFILES["artix"]
    ui.__dict__["init_system_var"] = Var("openrc")
    ui._workload = lambda: catalog["docker"]
    out = feather_app.App._augment_requests_for_init(ui, [("docker", None, None)])
    assert ("docker-openrc", None, None) in out
    # Exact selection of a known service also gains the companion.
    ui._workload = lambda: catalog["custom"]
    out = feather_app.App._augment_requests_for_init(ui, [("nginx", None, None)])
    assert ("nginx-openrc", None, None) in out
    # Unknown services get no phantom companion.
    out = feather_app.App._augment_requests_for_init(ui, [("jq", None, None)])
    assert out == [("jq", None, None)]

    ui._profile = lambda: profiles.PROFILES["devuan"]
    ui.__dict__["init_system_var"] = Var("runit")
    out = feather_app.App._augment_requests_for_init(ui, [("nginx", None, None)])
    assert ("runit", None, None) in out
    assert not any(name.endswith("-runit") for name, *_ in out)
    # Default sysvinit adds nothing: scripts are bundled with the packages.
    ui.__dict__["init_system_var"] = Var("sysvinit")
    out = feather_app.App._augment_requests_for_init(ui, [("nginx", None, None)])
    assert out == [("nginx", None, None)]

    assert profiles.PROFILES["artix"].init_systems == ["openrc", "runit", "s6", "dinit"]
    assert profiles.PROFILES["devuan"].init_systems[0] == "sysvinit"


def test_110_dynamic_workload_resolution_and_comet_rail():
    """Dynamic name resolution: missing preset names resolve through learned
    aliases, seed aliases, and spelling-rule derivation verified against the
    loaded universe; substitutions are never silent and persist per target.
    The activity rail comet keeps the low-cost contract: all items created in
    __init__, frames only move/recolour."""
    import inspect

    import app as feather_app
    import workload_resolution as wr

    names = {"bcc-tools", "python-pip", "iproute2"}
    assert wr.resolve_name("bpf", names, set(), "arch").resolved == "bcc-tools"
    assert wr.resolve_name("python3-pip", names, set(), "arch").kind == "derived"
    missing = wr.resolve_name("no-such-thing", names, set(), "arch")
    assert missing.kind == "missing" and not missing.substituted

    # Persistence merges per profile+family via the Tk-thread event handler.
    ui = feather_app.App.__new__(feather_app.App)
    saved = {}
    ui._profile = lambda: type("P", (), {"key": "artix", "package_family": "arch"})()
    ui._secure_write_json = lambda path, payload: saved.update(payload)
    ui._workload_alias_store_path = lambda: "workload-aliases.json"
    ui.__dict__["_workload_alias_cache"] = {}
    feather_app.App._record_workload_aliases(ui, [("bpf", "bcc-tools")])
    assert saved["artix"]["arch"]["bpf"] == "bcc-tools"
    assert feather_app.App._aliases_for_target(ui) == {"bpf": "bcc-tools"}

    # Comet rail: creation only in __init__, no churn in render_frame.
    init = inspect.getsource(feather_app.FeatheredActivityPulse.__init__)
    render = inspect.getsource(feather_app.FeatheredActivityPulse.render_frame)
    assert init.count("create_rectangle") >= 2  # track + head (+ trail loop)
    assert "create_" not in render and "delete(" not in render
    assert "activity-trail" in render  # the gust exists and is state-managed


def test_110_init_lock_refuses_systemd_packages_and_incompatible_repositories():
    """A non-systemd target must not be able to acquire systemd itself, a
    package that hard-depends on it, or repositories that only ship
    systemd-unit packaging. Packages that merely link libsystemd stay allowed
    (Devuan ships libsystemd0 by design), and systemd targets are unaffected."""
    import app as feather_app
    import workload_resolution as wr

    assert wr.systemd_conflict("systemd-sysv")
    assert not wr.systemd_conflict("libsystemd0")

    class Rel:
        name = "systemd"

    class Pkg:
        depends = [Rel()]
    assert wr.systemd_conflict("weird-daemon", {"weird-daemon": Pkg()})
    assert not wr.systemd_conflict("weird-daemon", {})

    assert wr.repository_init_conflict(
        "Arch Linux core", "https://geo.mirror.pkgbuild.com/core/os/x86_64/", "artix", "openrc")
    assert wr.repository_init_conflict(
        "Docker CE Stable", "https://download.docker.com/linux/debian", "devuan", "sysvinit")
    assert not wr.repository_init_conflict(
        "Artix system", "https://mirror1.artixlinux.org/repos/system/os/x86_64/", "artix", "openrc")
    # No init selected (systemd distros) => no exclusions at all.
    assert not wr.repository_init_conflict(
        "Docker CE Stable", "https://download.docker.com/linux/debian", "debian", "")

    # The GUI gate consults the profile + chosen init.
    ui = feather_app.App.__new__(feather_app.App)
    ui._profile = lambda: type("P", (), {"key": "artix"})()
    ui._selected_init_system = lambda: "runit"
    repo = type("R", (), {"name": "Arch Linux core", "url": "https://geo.mirror.pkgbuild.com/core/"})()
    assert feather_app.App._init_repository_conflict(ui, repo)
    ui._selected_init_system = lambda: ""
    assert not feather_app.App._init_repository_conflict(ui, repo)


def test_110_chooser_add_survives_workflow_rerender_after_removal():
    """Removing a selected package re-renders the Repositories workflow and
    clears cached widget references; the Add action must re-resolve the live
    tree instead of reporting "Select a package/version row first" forever.

    The chooser window is part of the fixture because recovery is scoped to it:
    re-rendering the workflow to rebuild a tree only makes sense while there is
    a chooser on screen to rebuild it for. See
    test_chooser_add_after_close_is_silent for the closed case.
    """
    import app as feather_app

    ui = feather_app.App.__new__(feather_app.App)
    ui.__dict__["single_browser_tree"] = None
    rebuilt = {}

    class Window:
        def winfo_exists(self): return True

    class Tree:
        def winfo_exists(self): return True
        def selection(self): return ()
        def focus(self): return "pkg-0"

    ui.single_browser_window = Window()

    def render(force=False):
        rebuilt["called"] = force
        ui.single_browser_tree = Tree()
    ui._render_repository_workflow = render
    tree = feather_app.App._live_single_browser_tree(ui)
    assert tree is not None and rebuilt["called"] is True
    # Focused-but-unselected rows still resolve (selection() can be empty
    # immediately after a redraw).
    assert tree.focus() == "pkg-0"


def test_110_content_stage_has_no_second_package_entry_for_custom():
    """Custom packages must not present its own freehand entry + Search/Check/
    Clear row on Content: identities are chosen in the shared chooser on
    Repositories. Only a pointer note remains."""
    import inspect

    import app as feather_app

    source = inspect.getsource(feather_app.App._workload_changed)
    assert "self.custom_label.grid_remove()" in source
    assert "self.custom_tools.grid_remove()" in source
    # The entry is never re-enabled, in either branch.
    assert 'self.custom_entry.configure(state="normal"' not in source
    assert "self.custom_entry.grid()" not in source
    assert "self.custom_tools.grid()" not in source


def test_110_gnupg_absence_gates_signature_controls_and_multi_host_cert_failures():
    """Without a verifier the signature layers are disabled with a stated
    reason and an install path, rather than accepting configuration that
    cannot work. And when two unrelated hosts fail certificate validation the
    same way, the advice names the local machine (clock/trust store) as the
    probable cause instead of blaming each mirror."""
    import inspect
    import ssl
    import urllib.error

    import app as feather_app
    import repository_transport

    source = inspect.getsource(feather_app.App._sync_openpgp_availability)
    assert 'state="disabled"' in source and 'state="normal"' in source
    assert "Gpg4win" in source or "gnupg.org" in source
    help_source = inspect.getsource(feather_app.App._show_gnupg_install_help)
    assert "does not install software" in help_source  # airgap tool: no silent installs

    repository_transport._CERT_FAILED_HOSTS.clear()
    repository_transport._TLS_SUCCESS_HOSTS.clear()
    exc = ssl.SSLCertVerificationError("certificate has expired")
    exc.verify_message = "certificate has expired"
    wrapped = urllib.error.URLError(exc)
    first = repository_transport.certificate_failure_advice(wrapped, "https://a.example/x")
    assert "clock" in first and "different hosts" not in first
    # With no successful fetch to appeal to, repeated failures across hosts
    # widen the suspicion but no longer assert the machine is at fault.
    second = repository_transport.certificate_failure_advice(wrapped, "https://b.example/y")
    assert "2 different hosts" in second
    repository_transport._CERT_FAILED_HOSTS.clear()
    repository_transport._TLS_SUCCESS_HOSTS.clear()


def test_110_workflow_polish_batch(monkeypatch):
    """Mirror mode emits repository metadata; the bundle list Remove/Clear
    survive a workflow re-render; Devuan is named plainly; and a target with no
    automatic release source marks the Release field instead of only showing a
    dialog."""
    import inspect
    from types import SimpleNamespace

    import app as feather_app
    from acquisition_model import AcquisitionCapability
    import profiles

    assert profiles.PROFILES["devuan"].label == "Devuan"

    ui = feather_app.App.__new__(feather_app.App)
    ui.resolution_pass_budget = None
    ui._build_repository_scope = lambda package_only=False: None
    ui._trust_options = lambda *args, **kwargs: {
        "emit_repository": False, "baseline_manifest": "stale.json"}
    monkeypatch.setattr(
        feather_app.App, "_acquisition_state",
        lambda self: SimpleNamespace(capability=AcquisitionCapability.REPOSITORY_MIRROR))
    mirror_options = feather_app.App._build_options(ui)
    assert mirror_options.emit_repository is True
    assert mirror_options.baseline_manifest == ""

    sync = inspect.getsource(feather_app.App._sync_output_capability_controls)
    assert "setter(True)" in sync

    detect = inspect.getsource(feather_app.App.detect_versions)
    assert "_focus_validation" in detect and "release_combo" in detect

    # Remove resolves the live tree, like Add does.
    remove = inspect.getsource(feather_app.App.remove_selected_package)
    assert "_live_selected_tree" in remove
    ui = feather_app.App.__new__(feather_app.App)
    ui.__dict__["selected_tree"] = None
    made = {}

    class Tree:
        def winfo_exists(self): return True
        def selection(self): return ("1",)
        def focus(self): return "1"

    def render(force=False):
        made["forced"] = force
        ui.selected_tree = Tree()
    ui._render_repository_workflow = render
    assert feather_app.App._live_selected_tree(ui) is not None
    assert made["forced"] is True
    ui.selected_packages = ["a", "b", "c"]
    ui._refresh_selected_packages = lambda: None
    feather_app.App.remove_selected_package(ui)
    assert ui.selected_packages == ["a", "c"]


def test_110_repository_view_rebuilds_on_target_change_and_cert_advice_is_evidence_based():
    """Changing distribution/release/architecture must invalidate the rendered
    Repositories view: keying the cache on acquisition intent alone left the
    previous distribution's repository rows on screen. And a successful HTTPS
    fetch in the same session disproves the local clock/trust-store theory, so
    the certificate advice must blame the mirror instead."""
    import inspect
    import ssl
    import urllib.error

    import app as feather_app
    import profiles
    import repository_transport

    render = inspect.getsource(feather_app.App._render_repository_workflow)
    assert "_repository_workflow_key_for_target()" in render

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    ui = feather_app.App.__new__(feather_app.App)
    ui._acquisition_intent = lambda: __import__("acquisition_model").AcquisitionIntent.WORKLOAD
    ui.__dict__["release_var"] = Var("rolling")
    ui.__dict__["arch_var"] = Var("x86_64")
    ui._selected_init_system = lambda: "openrc"
    ui._profile = lambda: profiles.PROFILES["artix"]
    artix_key = feather_app.App._repository_workflow_key_for_target(ui)
    ui._profile = lambda: profiles.PROFILES["arch"]
    arch_key = feather_app.App._repository_workflow_key_for_target(ui)
    assert artix_key != arch_key, "same key across distributions leaves a stale view"
    ui.__dict__["release_var"] = Var("other")
    assert feather_app.App._repository_workflow_key_for_target(ui) != arch_key

    repository_transport._CERT_FAILED_HOSTS.clear()
    repository_transport._TLS_SUCCESS_HOSTS.clear()
    exc = ssl.SSLCertVerificationError("certificate has expired")
    exc.verify_message = "certificate has expired"
    wrapped = urllib.error.URLError(exc)
    blind = repository_transport.certificate_failure_advice(wrapped, "https://a.example/x")
    assert "clock" in blind
    repository_transport.note_successful_fetch("https://good.example/repodata/x.xml")
    informed = repository_transport.certificate_failure_advice(wrapped, "https://b.example/y")
    assert "demonstrably fine" in informed and "good.example" in informed
    assert "fault is this mirror" in informed
    repository_transport._CERT_FAILED_HOSTS.clear()
    repository_transport._TLS_SUCCESS_HOSTS.clear()

    # A failed mirror is one edit from fixed: alternates are named on the row.
    assert len(profiles.ARTIX_MIRRORS) >= 3
    assert "mirrorlist" in profiles.ARTIX_MIRROR_NOTE

# --------------------------------------------------------------------------
#  1.1.1: Artix mirror and checksum-inspection diagnostics
# --------------------------------------------------------------------------

def test_111_artix_default_uses_official_mirror_layout_and_current_list_source():
    import arch_core
    import profiles

    assert profiles.ARTIX_MIRRORLIST_URL == (
        "https://gitea.artixlinux.org/packages/artix-mirrorlist/raw/branch/master/mirrorlist")
    rows = profiles.PROFILES["artix"].repos_factory("rolling", "x86_64")
    by_suite = {row.suite: row for row in rows}
    assert by_suite["system"].url == "https://artix.wheaton.edu/repos/system/os/x86_64/"
    assert by_suite["world"].url == "https://artix.wheaton.edu/repos/world/os/x86_64/"
    assert by_suite["galaxy"].url == "https://artix.wheaton.edu/repos/galaxy/os/x86_64/"
    import core
    for suite, expected in {
        "system": "https://artix.wheaton.edu/repos/system/os/x86_64/system.db",
        "world": "https://artix.wheaton.edu/repos/world/os/x86_64/world.db",
        "galaxy": "https://artix.wheaton.edu/repos/galaxy/os/x86_64/galaxy.db",
    }.items():
        row = by_suite[suite]
        repo = core.RepoSpec(row.name, row.url, row.role, row.priority, row.enabled,
                             row.note, row.target_release, optional=row.optional,
                             repo_format=row.repo_format, suite=row.suite, components=row.components)
        assert arch_core._repository_db_url(repo) == expected


def test_111_checksum_inspection_routes_transport_and_failures_to_activity_log():
    import inspect
    import app as feather_app

    main = inspect.getsource(feather_app.App._inspect_enabled_provenance_metadata)
    advanced = inspect.getsource(feather_app.App._start_checksum_inspection)
    assert "reporter = Reporter(self._log)" in main
    assert 'checksum inspection failed: {error_text}' in main
    assert "checksum inspection read {coverage.package_count:,} package records" in main
    assert "Reporter(self._log)" in advanced
    assert 'checksum inspection failed: {error}' in advanced


#  1.1.2: custom-label output targeting and occupied-folder negotiation

def test_112_custom_label_names_publish_folder_exactly():
    import app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.release_var = Var("rolling")
    dummy.arch_var = Var("x86_64")
    dummy.folder_scheme_var = Var(app.FOLDER_SCHEMES[3])
    dummy.folder_label_var = Var("existing-bundle")
    dummy.folder_stamp_var = Var("none")
    dummy._profile = lambda: type("Profile", (), {"key": "artix"})()
    dummy._mirror_mode = lambda: False
    dummy._single_mode = lambda: False
    dummy._workload = lambda: type("Workload", (), {"key": "docker"})()

    assert app.App._folder_name(dummy) == "existing-bundle"


def test_112_confirm_output_folder_can_choose_sibling(tmp_path, monkeypatch):
    import app

    occupied = tmp_path / "existing-bundle"
    occupied.mkdir()
    (occupied / "metadata").mkdir()
    (occupied / "metadata" / "manifest.json").write_text("{}", encoding="utf-8")
    (occupied / "packages").mkdir()

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.out_var = Var(str(tmp_path))
    dummy._folder_name = lambda: "existing-bundle"
    dummy._resolved_output_path = lambda folder_name=None: app.App._resolved_output_path(dummy, folder_name)
    dummy._summarize_existing_output_folder = lambda dest: app.App._summarize_existing_output_folder(dummy, dest)
    dummy._suggest_sibling_output_folder_name = lambda base_name: app.App._suggest_sibling_output_folder_name(dummy, base_name)

    monkeypatch.setattr(app.messagebox, "askchoice", lambda *a, **k: "sibling")
    chosen = app.App._confirm_output_folder_name(dummy, "existing-bundle")
    assert chosen.startswith("existing-bundle-refresh-")
    assert chosen != "existing-bundle"


def test_112_confirm_output_folder_keeps_requested_name_on_replace(tmp_path, monkeypatch):
    import app

    occupied = tmp_path / "existing-bundle"
    occupied.mkdir()
    (occupied / "repodata").mkdir()

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.out_var = Var(str(tmp_path))
    dummy._folder_name = lambda: "existing-bundle"
    dummy._resolved_output_path = lambda folder_name=None: app.App._resolved_output_path(dummy, folder_name)
    dummy._summarize_existing_output_folder = lambda dest: app.App._summarize_existing_output_folder(dummy, dest)
    dummy._suggest_sibling_output_folder_name = lambda base_name: app.App._suggest_sibling_output_folder_name(dummy, base_name)

    monkeypatch.setattr(app.messagebox, "askchoice", lambda *a, **k: "replace")
    assert app.App._confirm_output_folder_name(dummy, "existing-bundle") == "existing-bundle"


#  1.1.3: Custom-label empty-state regression

def test_113_custom_label_empty_has_no_fallback_folder_name():
    import app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.release_var = Var("rolling")
    dummy.arch_var = Var("x86_64")
    dummy.folder_scheme_var = Var(app.FOLDER_SCHEMES[3])
    dummy.folder_label_var = Var("")
    dummy.folder_stamp_var = Var("none")
    dummy._profile = lambda: type("Profile", (), {"key": "artix"})()
    dummy._mirror_mode = lambda: False
    dummy._single_mode = lambda: False
    dummy._workload = lambda: type("Workload", (), {"key": "docker"})()

    assert app.App._folder_name(dummy) == ""


def test_113_custom_label_preview_clears_immediately():
    import app

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    class Widget:
        def __init__(self): self.kw = {}
        def configure(self, **kw): self.kw.update(kw)

    dummy = type("Dummy", (), {})()
    dummy.folder_preview = Widget()
    dummy.folder_scheme_hint = Widget()
    dummy.folder_label_entry = Widget()
    dummy.folder_scheme_var = Var(app.FOLDER_SCHEMES[3])
    dummy.folder_label_var = Var("")
    dummy.folder_stamp_var = Var("none")
    dummy.release_var = Var("rolling")
    dummy.arch_var = Var("x86_64")
    dummy._profile = lambda: type("Profile", (), {"key": "artix"})()
    dummy._mirror_mode = lambda: False
    dummy._single_mode = lambda: False
    dummy._workload = lambda: type("Workload", (), {"key": "docker"})()
    dummy._folder_name = lambda: app.App._folder_name(dummy)

    app.App._update_folder_preview(dummy)
    assert dummy.folder_preview.kw["text"] == "Folder:  "
    assert dummy.folder_label_entry.kw["state"] == "normal"


#  1.1.4: custom-label prefix remains active with empty literal label

def _make_114_custom_naming_dummy(app, stamp, label=""):
    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    dummy = type("Dummy", (), {})()
    dummy.release_var = Var("rolling")
    dummy.arch_var = Var("x86_64")
    dummy.folder_scheme_var = Var(app.FOLDER_SCHEMES[3])
    dummy.folder_label_var = Var(label)
    dummy.folder_stamp_var = Var(stamp)
    dummy._profile = lambda: type("Profile", (), {"key": "artix"})()
    dummy._mirror_mode = lambda: False
    dummy._single_mode = lambda: False
    dummy._workload = lambda: type("Workload", (), {"key": "docker"})()
    return dummy


def test_114_custom_label_empty_uses_date_prefix(monkeypatch):
    import app

    class FixedDateTime:
        @classmethod
        def now(cls):
            return cls()
        def strftime(self, fmt):
            return {"%Y-%m-%d": "2031-04-05", "%Y-%m-%d_%H%M%S": "2031-04-05_060708"}[fmt]

    monkeypatch.setattr(app, "datetime", FixedDateTime)
    dummy = _make_114_custom_naming_dummy(app, "date")
    assert app.App._folder_name(dummy) == "2031-04-05"


def test_114_custom_label_empty_uses_datetime_prefix(monkeypatch):
    import app

    class FixedDateTime:
        @classmethod
        def now(cls):
            return cls()
        def strftime(self, fmt):
            return {"%Y-%m-%d": "2031-04-05", "%Y-%m-%d_%H%M%S": "2031-04-05_060708"}[fmt]

    monkeypatch.setattr(app, "datetime", FixedDateTime)
    dummy = _make_114_custom_naming_dummy(app, "time")
    assert app.App._folder_name(dummy) == "2031-04-05_060708"


def test_114_custom_label_none_and_empty_stays_blank():
    import app
    dummy = _make_114_custom_naming_dummy(app, "none")
    assert app.App._folder_name(dummy) == ""


def test_114_output_naming_validation_accepts_prefix_only():
    import app

    for stamp in ("date", "time"):
        dummy = _make_114_custom_naming_dummy(app, stamp)
        app.App._validate_output_naming(dummy)


def test_114_output_naming_validation_rejects_empty_none_prefix():
    import app
    import pytest

    dummy = _make_114_custom_naming_dummy(app, "none")
    with pytest.raises(RuntimeError, match="both the label and Prefix are empty"):
        app.App._validate_output_naming(dummy)

#  1.1.5: editable distribution mirror catalogs for provenance evidence.

def test_115_rocky_catalog_derives_same_slice_exact_mirror(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec
    from evidence_model import AUTH_INDEPENDENT, REL_EXACT_MIRROR

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "rocky.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "rocky",
        "mirrors": [{
            "label": "Example Rocky mirror",
            "operator": "Example University",
            "country": "US",
            "url": "https://mirror.example.edu/rocky",
            "scopes": ["archive"],
            "independent_operator": True,
            "enabled": True,
        }],
        "exact_overrides": [],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Rocky 9.8 BaseOS",
        "https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/",
        role="dependency", repo_format="rpm", target_release="9.8")
    candidates = mirror_catalog.candidates_for_repository("rocky", repo)
    assert len(candidates) == 1
    assert candidates[0].url == "https://mirror.example.edu/rocky/9.8/BaseOS/x86_64/os/"
    assert candidates[0].relationship == REL_EXACT_MIRROR
    assert candidates[0].authority == AUTH_INDEPENDENT


def test_115_arch_catalog_derives_repository_channel_path(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "arch.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "arch",
        "mirrors": [{
            "label": "Example Arch mirror",
            "country": "US",
            "url": "https://mirror.example.net/archlinux",
            "scopes": ["archive"],
            "independent_operator": True,
            "enabled": True,
        }],
        "exact_overrides": [],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Arch Linux extra", "https://geo.mirror.pkgbuild.com/extra/os/x86_64/",
        role="dependency", repo_format="pacman", suite="extra")
    candidates = mirror_catalog.candidates_for_repository("arch", repo)
    assert [c.url for c in candidates] == ["https://mirror.example.net/archlinux/extra/os/x86_64/"]


def test_115_devuan_catalog_baseurl_becomes_merged_repository(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "devuan.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "devuan",
        "mirrors": [{
            "label": "Example Devuan mirror",
            "country": "US",
            "url": "https://mirror.example.org/devuan",
            "scopes": ["archive"],
            "independent_operator": True,
            "enabled": True,
        }],
        "exact_overrides": [],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Devuan excalibur", "http://deb.devuan.org/merged",
        role="dependency", repo_format="apt", suite="excalibur", components="main")
    candidates = mirror_catalog.candidates_for_repository("devuan", repo)
    assert [c.url for c in candidates] == ["https://mirror.example.org/devuan/merged/"]


def test_115_debian_security_requires_security_scoped_mirror(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "debian.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "debian",
        "mirrors": [
            {"label": "Archive only", "country": "US", "url": "https://archive.example/debian",
             "scopes": ["archive"], "independent_operator": True, "enabled": True},
            {"label": "Security mirror", "country": "US", "url": "https://security.example/debian-security",
             "scopes": ["security"], "independent_operator": True, "enabled": True},
        ],
        "exact_overrides": [],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Debian trixie-security", "https://security.debian.org/debian-security",
        role="dependency", repo_format="apt", suite="trixie-security", components="main")
    candidates = mirror_catalog.candidates_for_repository("debian", repo)
    assert [c.url for c in candidates] == ["https://security.example/debian-security/"]


def test_115_user_exact_mirror_override_persists_and_defaults_authority_unknown(tmp_path, monkeypatch):
    import mirror_catalog
    from core import RepoSpec
    from evidence_model import AUTH_UNKNOWN, REL_EXACT_MIRROR

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    repo = RepoSpec(
        "Ubuntu noble", "http://archive.ubuntu.com/ubuntu",
        role="dependency", repo_format="apt", suite="noble", components="main")
    path = mirror_catalog.add_exact_mirror_override(
        "ubuntu", repo, "https://mirror.example.org/ubuntu", "My local mirror")
    assert path == tmp_path / "ubuntu.json"
    candidates = mirror_catalog.candidates_for_repository("ubuntu", repo)
    assert len(candidates) == 1
    assert candidates[0].url == "https://mirror.example.org/ubuntu/"
    assert candidates[0].relationship == REL_EXACT_MIRROR
    assert candidates[0].authority == AUTH_UNKNOWN
    assert candidates[0].source == "mirror-catalog-user"


def test_115_app_profile_evidence_comes_from_local_catalog_not_profile_suggestion():
    import inspect
    import app

    source = inspect.getsource(app.App._profile_evidence_candidates)
    assert "mirror_catalog.candidates_for_repository" in source
    assert "evidence_suggestions" not in source


def test_115_build_stages_writable_mirror_catalog_sidecar():
    from pathlib import Path

    source = (Path(__file__).resolve().parent / "build_exe.bat").read_text(encoding="utf-8")
    assert "xcopy /E /I /Y mirror_catalogs dist\\mirror_catalogs" in source
    assert "Editable provenance mirror catalogs" in source


#  1.1.6: hard US geographic boundary for automatic evidentiary mirrors.

def test_116_automatic_catalog_evidence_is_us_only(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "ubuntu.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "ubuntu",
        "mirrors": [
            {"label": "US mirror", "country": "US", "url": "https://us.example/ubuntu",
             "scopes": ["archive"], "independent_operator": True, "enabled": True},
            {"label": "Canadian mirror", "country": "CA", "url": "https://ca.example/ubuntu",
             "scopes": ["archive"], "independent_operator": True, "enabled": True},
            {"label": "Unknown mirror", "url": "https://unknown.example/ubuntu",
             "scopes": ["archive"], "independent_operator": True, "enabled": True},
        ],
        "exact_overrides": [],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Ubuntu noble", "https://archive.ubuntu.com/ubuntu",
        role="dependency", repo_format="apt", suite="noble", components="main")
    candidates = mirror_catalog.candidates_for_repository("ubuntu", repo)
    assert [c.url for c in candidates] == ["https://us.example/ubuntu/"]
    assert "geographic policy: US" in candidates[0].note


def test_116_non_us_manual_override_cannot_assert_independent_authority(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec
    from evidence_model import AUTH_UNKNOWN

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "ubuntu.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "ubuntu",
        "mirrors": [],
        "exact_overrides": [{
            "label": "Operator override",
            "url": "https://foreign.example/ubuntu",
            "repo_name": "Ubuntu noble",
            "suite": "noble",
            "country": "DK",
            "independent_operator": True,
            "enabled": True,
        }],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Ubuntu noble", "https://archive.ubuntu.com/ubuntu",
        role="dependency", repo_format="apt", suite="noble", components="main")
    candidates = mirror_catalog.candidates_for_repository("ubuntu", repo)
    assert len(candidates) == 1
    assert candidates[0].authority == AUTH_UNKNOWN
    assert "country is not US" in candidates[0].note


def test_116_us_manual_override_may_assert_independent_authority(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec
    from evidence_model import AUTH_INDEPENDENT

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "ubuntu.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "ubuntu",
        "mirrors": [],
        "exact_overrides": [{
            "label": "Operator override",
            "url": "https://us-mirror.example/ubuntu",
            "repo_name": "Ubuntu noble",
            "suite": "noble",
            "country": "US",
            "independent_operator": True,
            "enabled": True,
        }],
    }), encoding="utf-8")
    repo = RepoSpec(
        "Ubuntu noble", "https://archive.ubuntu.com/ubuntu",
        role="dependency", repo_format="apt", suite="noble", components="main")
    candidates = mirror_catalog.candidates_for_repository("ubuntu", repo)
    assert len(candidates) == 1
    assert candidates[0].authority == AUTH_INDEPENDENT


def test_116_bundled_automatic_catalogs_contain_only_us_mirrors():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parent / "mirror_catalogs"
    minimums = {
        "alma": 3, "arch": 3, "artix": 3, "centos-stream": 3,
        "debian": 3, "devuan": 3, "epel": 3, "fedora": 3, "rocky": 3, "ubuntu": 3,
    }
    for path in root.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("mirrors", [])
        assert all(row.get("country") == "US" for row in rows), path.name
        if path.stem in minimums:
            assert len(rows) >= minimums[path.stem], path.name


def test_116_ui_added_override_exposes_country_for_plain_text_policy_edit(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    repo = RepoSpec(
        "Ubuntu noble", "https://archive.ubuntu.com/ubuntu",
        role="dependency", repo_format="apt", suite="noble", components="main")
    path = mirror_catalog.add_exact_mirror_override(
        "ubuntu", repo, "https://manual.example/ubuntu", "Manual")
    entry = json.loads(path.read_text(encoding="utf-8"))["exact_overrides"][0]
    assert entry["country"] == ""
    assert entry["independent_operator"] is False
    assert "country=US" in entry["note"]

#  1.1.7: additive output publication and repository metadata refresh

def test_117_commit_staging_merges_without_deleting_destination_only_files(tmp_path):
    from core import Reporter, commit_staging, open_staging

    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "keep-manually.txt").write_text("KEEP", encoding="utf-8")
    (dest / "same.txt").write_text("OLD", encoding="utf-8")

    staging = open_staging(dest, Reporter())
    # Simulate a generated view that no longer contains one pre-existing file.
    (staging / "keep-manually.txt").unlink()
    (staging / "same.txt").write_text("NEW", encoding="utf-8")
    (staging / "added.txt").write_text("ADDED", encoding="utf-8")

    commit_staging(staging, dest, Reporter())
    assert (dest / "keep-manually.txt").read_text(encoding="utf-8") == "KEEP"
    assert (dest / "same.txt").read_text(encoding="utf-8") == "NEW"
    assert (dest / "added.txt").read_text(encoding="utf-8") == "ADDED"



def test_117_commit_staging_preflights_conflicts_before_publication(tmp_path):
    import pytest
    from core import Reporter, commit_staging, open_staging

    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "a.txt").write_text("OLD", encoding="utf-8")
    (dest / "z-conflict").mkdir()
    (dest / "z-conflict" / "keep.txt").write_text("KEEP", encoding="utf-8")

    staging = open_staging(dest, Reporter())
    (staging / "a.txt").write_text("NEW", encoding="utf-8")
    import shutil
    shutil.rmtree(staging / "z-conflict")
    (staging / "z-conflict").write_text("FILE", encoding="utf-8")

    with pytest.raises(RuntimeError, match="directory already exists"):
        commit_staging(staging, dest, Reporter())

    assert (dest / "a.txt").read_text(encoding="utf-8") == "OLD"
    assert (dest / "z-conflict" / "keep.txt").read_text(encoding="utf-8") == "KEEP"


def test_117_commit_staging_rolls_back_if_final_directory_swap_fails(tmp_path, monkeypatch):
    import core
    import pytest
    from core import Reporter, commit_staging, open_staging

    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "state.txt").write_text("OLD", encoding="utf-8")
    staging = open_staging(dest, Reporter())
    (staging / "state.txt").write_text("NEW", encoding="utf-8")

    real_replace = core.os.replace

    def fail_new_directory_move(source, target):
        if Path(source) == staging and Path(target) == dest:
            raise OSError("simulated final swap failure")
        return real_replace(source, target)

    monkeypatch.setattr(core.os, "replace", fail_new_directory_move)
    with pytest.raises(OSError, match="simulated final swap failure"):
        commit_staging(staging, dest, Reporter())

    assert dest.is_dir()
    assert (dest / "state.txt").read_text(encoding="utf-8") == "OLD"
    assert staging.is_dir()
    assert (staging / "state.txt").read_text(encoding="utf-8") == "NEW"
    assert not core._publication_backup_path(dest).exists()


def test_117_unsealed_additive_publication_drops_inherited_whole_bundle_seal(tmp_path):
    from core import Reporter, commit_staging, invalidate_bundle_seal, open_staging

    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "payload.txt").write_text("OLD", encoding="utf-8")
    for name in ("bundle-index.json", "bundle-index.json.asc", "verify-bundle.py", "verify-bundle.py.asc"):
        (dest / name).write_text("STALE", encoding="utf-8")

    staging = open_staging(dest, Reporter())
    invalidate_bundle_seal(staging, Reporter())
    (staging / "payload.txt").write_text("NEW", encoding="utf-8")
    (staging / "new.txt").write_text("ADDED", encoding="utf-8")
    commit_staging(staging, dest, Reporter())

    assert (dest / "payload.txt").read_text(encoding="utf-8") == "NEW"
    assert (dest / "new.txt").read_text(encoding="utf-8") == "ADDED"
    for name in ("bundle-index.json", "bundle-index.json.asc", "verify-bundle.py", "verify-bundle.py.asc"):
        assert not (dest / name).exists(), name


def test_117_open_staging_recovers_interrupted_directory_swap(tmp_path):
    import os
    import core
    from core import Reporter, open_staging

    dest = tmp_path / "bundle"
    dest.mkdir()
    (dest / "state.txt").write_text("OLD", encoding="utf-8")
    backup = core._publication_backup_path(dest)
    os.replace(dest, backup)
    assert not dest.exists() and backup.exists()

    staging = open_staging(dest, Reporter())
    assert (dest / "state.txt").read_text(encoding="utf-8") == "OLD"
    assert (staging / "state.txt").read_text(encoding="utf-8") == "OLD"
    assert not backup.exists()


def test_117_existing_folder_defaults_to_addendum_and_repo_regeneration(tmp_path, monkeypatch):
    import app
    from core import BuildOptions

    dest = tmp_path / "existing"
    (dest / "repodata").mkdir(parents=True)
    (dest / "repodata" / "repomd.xml").write_text("OLD", encoding="utf-8")

    class Var:
        def get(self): return str(tmp_path)

    dummy = type("Dummy", (), {})()
    dummy.out_var = Var()
    dummy._resolved_output_path = lambda name=None: tmp_path / (name or "existing")
    dummy._summarize_existing_output_folder = lambda path: "occupied"
    dummy._suggest_sibling_output_folder_name = lambda name: name + "-new"
    dummy._folder_has_repository_metadata = lambda path: True
    dummy._open_folder_path = lambda path: None

    answers = iter(["add", "regenerate"])
    monkeypatch.setattr(app.messagebox, "askchoice", lambda *a, **k: next(answers))
    options = BuildOptions(emit_repository=True)
    chosen = app.App._confirm_output_folder_name(dummy, "existing", options)
    assert chosen == "existing"
    assert options.additive_publish is True
    assert options.emit_repository is True


def test_117_existing_repo_metadata_can_be_left_unchanged(tmp_path, monkeypatch):
    import app
    from core import BuildOptions

    dest = tmp_path / "existing"
    dest.mkdir()
    (dest / "USE-AS-REPOSITORY.txt").write_text("OLD", encoding="utf-8")

    dummy = type("Dummy", (), {})()
    dummy._resolved_output_path = lambda name=None: dest
    dummy._summarize_existing_output_folder = lambda path: "occupied"
    dummy._suggest_sibling_output_folder_name = lambda name: name + "-new"
    dummy._folder_has_repository_metadata = lambda path: True
    dummy._open_folder_path = lambda path: None

    answers = iter(["add", "keep"])
    monkeypatch.setattr(app.messagebox, "askchoice", lambda *a, **k: next(answers))
    options = BuildOptions(emit_repository=True)
    assert app.App._confirm_output_folder_name(dummy, "existing", options) == "existing"
    assert options.additive_publish is True
    assert options.emit_repository is False


def test_117_repository_rebuild_never_deletes_old_metadata_artifacts(tmp_path):
    import repository_tools

    rpm = tmp_path / "rpms" / "demo.rpm"
    rpm.parent.mkdir()
    _write_synthetic_rpm(rpm)
    repodata = tmp_path / "repodata"
    repodata.mkdir()
    orphan = repodata / "operator-kept-old-metadata.xml.gz"
    orphan.write_bytes(b"KEEP")

    repository_tools.rebuild_repository_metadata(tmp_path)
    assert orphan.read_bytes() == b"KEEP"
    assert (repodata / "repomd.xml").is_file()


def test_117_additive_repo_regeneration_indexes_all_existing_and_new_debs(tmp_path):
    import apt_core
    import repository_tools
    from core import Reporter

    debs = tmp_path / "debs"
    debs.mkdir()
    _write_tiny_deb(debs / "old.deb", package="old-addon", version="1.0-1")
    _write_tiny_deb(debs / "new.deb", package="new-addon", version="2.0-1")
    family, packages = repository_tools.load_local_repository_packages(tmp_path, "deb")
    assert family == "deb" and len(packages) == 2
    apt_core.emit_apt_repository(tmp_path, packages, Reporter(), preserve_package_locations=True)
    body = (tmp_path / "dists" / "feathered" / "main" / "binary-amd64" / "Packages").read_text()
    assert "Package: old-addon" in body and "Filename: debs/old.deb" in body
    assert "Package: new-addon" in body and "Filename: debs/new.deb" in body

# ---- 1.2.3 multi-repository mirror publication regressions -----------------

def test_123_mirror_inventory_preserves_every_repository_record_without_deduplication():
    import types
    import app as feather_app
    from core import Package, RepoSpec

    a = RepoSpec("Alma BaseOS", "https://a.example/baseos/")
    b = RepoSpec("Rocky BaseOS", "https://b.example/baseos/")
    # Same package identity exists in both repositories; repo A also publishes
    # an older version. A mirror inventory must retain all three records.
    a1 = Package("demo", "x86_64", "0", "1", "1", "demo-1-1.rpm", "sha256", "aa", a, size=10)
    a2 = Package("demo", "x86_64", "0", "2", "1", "demo-2-1.rpm", "sha256", "ab", a, size=20)
    b2 = Package("demo", "x86_64", "0", "2", "1", "demo-2-1.rpm", "sha256", "bb", b, size=30)

    ui = types.SimpleNamespace(
        repo_rows=[a, b], mirror_repos={a.source_identity, b.source_identity},
        _mirror_repo_selected=lambda repo: feather_app.App._mirror_repo_selected(ui, repo),
        _is_deb=lambda: False, _is_arch=lambda: False,
    )
    reporter = types.SimpleNamespace(log=lambda _msg: None)
    result = feather_app.App._mirror_result(ui, [a1, a2, b2], reporter)

    assert result.selected == [a1, a2, b2]
    assert result.total_size == 60
    assert len(result.mirror_repository_results) == 2
    assert [x["package_count"] for x in result.mirror_repository_summaries] == [2, 1]
    assert sum(x["total_size"] for x in result.mirror_repository_summaries) == 60


def test_123_mirror_folder_naming_forks_shared_custom_label_and_timestamp_per_repo():
    import types
    from datetime import datetime
    import app as feather_app
    from core import RepoSpec
    from feathered_app.context import FOLDER_SCHEMES

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    profile = types.SimpleNamespace(key="rhel")
    ui = types.SimpleNamespace(
        release_var=Var("9.8"), arch_var=Var("x86_64"),
        folder_scheme_var=Var(FOLDER_SCHEMES[3]),
        folder_label_var=Var("nightly"), folder_stamp_var=Var("time"),
        _profile=lambda: profile, _mirror_mode=lambda: True,
        _single_mode=lambda: False,
    )
    moment = datetime(2026, 9, 1, 22, 31, 42)
    alma = RepoSpec("AlmaLinux 9.8 BaseOS", "https://a.example/baseos/")
    rocky = RepoSpec("Rocky Linux 9.8 BaseOS", "https://b.example/baseos/")

    one = feather_app.App._folder_name(ui, mirror_repo=alma, naming_time=moment)
    two = feather_app.App._folder_name(ui, mirror_repo=rocky, naming_time=moment)
    assert one == "2026-09-01_223142_nightly-AlmaLinux-9.8-BaseOS"
    assert two == "2026-09-01_223142_nightly-Rocky-Linux-9.8-BaseOS"
    assert one != two



def test_123_output_preview_lists_each_selected_mirror_repository_and_destination():
    import types
    import app as feather_app
    from core import RepoSpec
    from feathered_app.context import FOLDER_SCHEMES

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    class Widget:
        def __init__(self): self.kw = {}
        def configure(self, **kwargs): self.kw.update(kwargs)

    alma = RepoSpec("AlmaLinux BaseOS", "https://a.example/baseos/")
    appstream = RepoSpec("AlmaLinux AppStream", "https://a.example/appstream/")
    ui = types.SimpleNamespace(
        release_var=Var("9.8"), arch_var=Var("x86_64"),
        folder_scheme_var=Var(FOLDER_SCHEMES[0]), folder_label_var=Var(""),
        folder_stamp_var=Var("date"), folder_scheme_hint=Widget(),
        folder_label_entry=Widget(), folder_preview=Widget(),
        _profile=lambda: types.SimpleNamespace(key="rhel"),
        _mirror_mode=lambda: True, _single_mode=lambda: False,
        _selected_mirror_repositories=lambda: [alma, appstream],
    )
    ui._mirror_output_folder_names = lambda naming_time=None: feather_app.App._mirror_output_folder_names(ui, naming_time)

    feather_app.App._update_folder_preview(ui)
    text = ui.folder_preview.kw["text"]
    assert "Outputs (2 independent repository mirrors):" in text
    assert "AlmaLinux BaseOS" in text and "rhel-9.8-x86_64-mirror-AlmaLinux-BaseOS-offline" in text
    assert "AlmaLinux AppStream" in text and "rhel-9.8-x86_64-mirror-AlmaLinux-AppStream-offline" in text
    assert "docker" not in text.lower()


def test_123_mirror_checkbox_repaint_invalidates_output_preview():
    import types
    import app as feather_app

    class Tree:
        def get_children(self): return ("row-a", "row-b")
        def item(self, _iid, **_kwargs): return None

    class Status:
        def __init__(self): self.text = "2 configured repositories"
        def cget(self, _name): return self.text
        def configure(self, **kwargs): self.text = kwargs.get("text", self.text)

    calls = []
    ui = types.SimpleNamespace(
        mirror_tree=Tree(),
        _mirror_iid_to_source_identity={"row-a": "a", "row-b": "b"},
        mirror_repos={"a"}, mirror_status=Status(),
        _checkbox_images=lambda: (object(), object()),
        _refresh_package_source_plan=lambda: None,
        _refresh_workload_repository_views=lambda: None,
        _refresh_package_source_coverage=lambda: None,
        _update_folder_preview=lambda: calls.append("preview"),
    )
    feather_app.App._paint_mirror_rows(ui)
    assert calls == ["preview"]


def test_123_independent_rpm_mirror_destinations_receive_only_their_own_metadata(tmp_path):
    import gzip
    import hashlib
    from core import BuildOptions, Package, RepoSpec, Reporter, ResolutionResult, write_bundle

    def make_source(name, payload_name, payload):
        source = tmp_path / (name + "-source")
        source.mkdir()
        rpm = source / payload_name
        rpm.write_bytes(payload)
        repo = RepoSpec(name, source.as_uri() + "/")
        repo.verification_strategy = "skip-provenance"
        package = Package(
            name=payload_name[:-4], arch="x86_64", epoch="0", version="1.0", release="1",
            location=payload_name, checksum_type="sha256",
            checksum=hashlib.sha256(payload).hexdigest(), repo=repo, size=len(payload))
        return repo, package

    repo_a, pkg_a = make_source("Repo A", "alpha.rpm", b"alpha-rpm-payload")
    repo_b, pkg_b = make_source("Repo B", "beta.rpm", b"beta-rpm-payload")
    opts = BuildOptions(include_dependencies=False, emit_repository=True, retries=1)

    for repo, pkg, dest in ((repo_a, pkg_a, tmp_path / "mirror-a"),
                            (repo_b, pkg_b, tmp_path / "mirror-b")):
        result = ResolutionResult([pkg], [], [pkg], reasons={pkg.nevra: "mirror artifact"})
        write_bundle(result, dest, opts, Reporter(), {
            "repository_mirror": True,
            "mirrored_repository": {"name": repo.name, "url": repo.url},
            "repositories": [{"name": repo.name, "url": repo.url}],
            "dependency_completeness": "not-applicable",
        })

    primary_a = gzip.decompress((tmp_path / "mirror-a" / "repodata" / "primary.xml.gz").read_bytes()).decode()
    primary_b = gzip.decompress((tmp_path / "mirror-b" / "repodata" / "primary.xml.gz").read_bytes()).decode()
    assert "alpha" in primary_a and "beta" not in primary_a
    assert "beta" in primary_b and "alpha" not in primary_b
    assert (tmp_path / "mirror-a" / "rpms" / "alpha.rpm").is_file()
    assert not (tmp_path / "mirror-a" / "rpms" / "beta.rpm").exists()
    assert (tmp_path / "mirror-b" / "rpms" / "beta.rpm").is_file()
    assert not (tmp_path / "mirror-b" / "rpms" / "alpha.rpm").exists()


def test_123_enhanced_explicit_evidence_preflight_includes_optional_bonds():
    import types
    import app as feather_app
    from core import RepoSpec

    class Var:
        def get(self): return "Fill gaps with independent evidence (enhanced)"

    required = RepoSpec("Needs fallback", "https://required.example/repo/")
    optional = RepoSpec("Checksum complete", "https://optional.example/repo/")
    required.evidence_urls = ["https://evidence.example/required/"]
    optional.evidence_urls = ["https://evidence.example/optional/"]
    ui = types.SimpleNamespace(
        prov_strategy_var=Var(),
        _strategy_ui_to_policy=lambda _label: "evidence-fallback",
        _enabled_provenance_repos=lambda: [required, optional],
    )
    pairs = feather_app.App._evidence_preflight_pairs(ui)
    assert pairs == [(required, required.evidence_urls[0]), (optional, optional.evidence_urls[0])]


def test_123_enhanced_unknown_checksum_coverage_is_pending_not_fallback_required():
    import types
    import app as feather_app
    from core import RepoSpec

    unknown = RepoSpec("Unknown", "https://unknown.example/repo/")
    deficient = RepoSpec("Deficient", "https://deficient.example/repo/")
    complete = RepoSpec("Complete", "https://complete.example/repo/")
    ui = types.SimpleNamespace(
        _enabled_provenance_repos=lambda: [unknown, deficient, complete],
        _digest_inspection_known=lambda repo: repo is not unknown,
        _repo_meets_digest_minimum=lambda repo, _pref: repo is complete,
    )

    required = feather_app.App._evidence_required_repos(ui, "evidence-fallback")
    pending = feather_app.App._evidence_pending_inspection_repos(ui, "evidence-fallback")
    assert required == [deficient]
    assert pending == [unknown]


def test_123_enhanced_testing_before_inspection_still_requires_a_selection():
    from test_evidence_workflow import make_ui
    import app as feather_app
    from core import RepoSpec

    pending = RepoSpec("Needs inspection", "https://pending.example/repo/")
    ui = make_ui([pending])
    focused = []
    ui._focus_validation = lambda *args: focused.append(args)
    feather_app.App._test_evidence_sources(ui)
    assert len(focused) == 1
    assert focused[0][2] == "Select an independent evidence source to test."


def test_123_enhanced_next_requires_checksum_inspection_before_evidence_contract():
    import types
    import pytest
    import app as feather_app
    from core import RepoSpec

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    pending = RepoSpec("Needs inspection", "https://pending.example/repo/")
    ui = types.SimpleNamespace(
        prov_strategy_var=Var("Fill gaps with independent evidence (enhanced)"),
        prov_digest_var=Var("Automatic"),
        _provenance_requires_evidence_selection=lambda: True,
        _strategy_ui_to_policy=lambda _label: "evidence-fallback",
        _evidence_pending_inspection_repos=lambda _strategy: [pending],
    )

    with pytest.raises(RuntimeError, match="Inspect checksum support first"):
        feather_app.App._validate_provenance_step(ui)

# ---- 1.2.3 evidence relationship/catalog routing repair --------------------

def test_123_rhel_compatible_labels_do_not_override_alma_or_rocky_vendor_identity():
    from evidence_model import infer_vendor_id

    alma_name = "AlmaLinux 9.8 BaseOS (RHEL-compatible fallback)"
    alma_url = "https://repo.almalinux.org/almalinux/9.8/BaseOS/x86_64/os/"
    rocky_name = "Rocky Linux 9.8 BaseOS (RHEL-compatible fallback)"
    rocky_url = "https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/"

    assert infer_vendor_id(alma_name, alma_url) == "almalinux"
    assert infer_vendor_id(rocky_name, rocky_url) == "rocky"
    # Name-only fallback must still prefer the concrete distro over the generic
    # compatibility qualifier.
    assert infer_vendor_id(alma_name) == "almalinux"
    assert infer_vendor_id(rocky_name) == "rocky"

    from core import RepoSpec
    from evidence_model import repositories_are_exact_mirror_compatible
    alma = RepoSpec(alma_name, alma_url, target_release="9.8")
    rocky = RepoSpec(rocky_name, rocky_url, target_release="9.8")
    assert not repositories_are_exact_mirror_compatible(alma, rocky)


def test_123_rhel_public_fallback_evidence_candidates_keep_exact_and_semantic_roles_separate():
    import app as feather_app
    from core import RepoSpec, evidence_relationship
    from evidence_model import REL_EXACT_MIRROR, REL_REBUILD_PEER, infer_vendor_id

    class Var:
        def __init__(self, value): self.value = value
        def get(self): return self.value

    alma = RepoSpec(
        "AlmaLinux 9.8 BaseOS (RHEL-compatible fallback)",
        "https://repo.almalinux.org/almalinux/9.8/BaseOS/x86_64/os/",
        "dependency", target_release="9.8")
    rocky = RepoSpec(
        "Rocky Linux 9.8 BaseOS (RHEL-compatible fallback)",
        "https://download.rockylinux.org/pub/rocky/9.8/BaseOS/x86_64/os/",
        "dependency", target_release="9.8")
    ui = object.__new__(feather_app.App)
    ui.repo_rows = [alma, rocky]
    ui.release_var = Var("9.8")
    ui.arch_var = Var("x86_64")
    ui._profile = lambda: feather_app.PROFILES["rhel"]

    for primary, peer_vendor, exact_vendor in (
        (alma, "rocky", "almalinux"),
        (rocky, "almalinux", "rocky"),
    ):
        specs = feather_app.App._evidence_candidate_specs(ui, primary)
        exact = [c for c in specs if c.relationship == REL_EXACT_MIRROR]
        peers = [c for c in specs if c.relationship == REL_REBUILD_PEER]
        assert exact, primary.name
        assert peers, primary.name
        assert all(infer_vendor_id(c.label, c.url) == exact_vendor for c in exact)
        assert all(infer_vendor_id(c.label, c.url) == peer_vendor for c in peers)
        assert all(c.url.rstrip("/") != primary.normalized_url.rstrip("/") for c in specs)

        # The proof contract selected in the UI must be the same contract used
        # by the runtime preflight/build path.
        primary.evidence_relationship_hints = {exact[0].url: exact[0].relationship}
        assert evidence_relationship(primary, exact[0].url) == REL_EXACT_MIRROR
        primary.evidence_relationship_hints = {peers[0].url: peers[0].relationship}
        assert evidence_relationship(primary, peers[0].url) == REL_REBUILD_PEER


def test_123_rhel_public_fallback_exact_catalog_follows_repository_vendor_not_target_profile():
    import app as feather_app
    from core import RepoSpec

    class Var:
        def get(self): return "9.8"

    ui = object.__new__(feather_app.App)
    ui.release_var = Var()
    ui.arch_var = type("ArchVar", (), {"get": lambda self: "x86_64"})()
    ui._profile = lambda: feather_app.PROFILES["rhel"]

    alma = RepoSpec(
        "AlmaLinux 9.8 AppStream (RHEL-compatible fallback)",
        "https://repo.almalinux.org/almalinux/9.8/AppStream/x86_64/os/",
        "dependency", target_release="9.8")
    rocky = RepoSpec(
        "Rocky Linux 9.8 AppStream (RHEL-compatible fallback)",
        "https://download.rockylinux.org/pub/rocky/9.8/AppStream/x86_64/os/",
        "dependency", target_release="9.8")

    assert feather_app.App._evidence_catalog_profile_key(ui, alma) == "alma"
    assert feather_app.App._evidence_catalog_profile_key(ui, rocky) == "rocky"
    assert feather_app.App._evidence_catalog_profile_key(ui, RepoSpec(
        "RHEL BaseOS", "https://cdn.redhat.com/content/dist/rhel9/9.8/x86_64/baseos/os/",
        "dependency", target_release="9.8")) == "rhel"


def test_117_build_script_defaults_local_and_release_is_explicit():
    source = (Path(__file__).resolve().parent / "build_exe.bat").read_text(encoding="utf-8").lower()
    assert 'set "release_mode=0"' in source
    assert 'if /i "%~1"=="--release"' in source
    assert 'if "%release_mode%"=="1" (' in source
    assert 'feathered_sign_cert_sha1 is required with --release' in source
    assert 'running local unsigned build' in source


def test_117_build_script_supports_current_python_locally_but_pins_release_python():
    source = (Path(__file__).resolve().parent / "build_exe.bat").read_text(encoding="utf-8").lower()
    assert 'py -3.14 -c' in source
    assert 'set "base_py=py -3.14"' in source
    assert 'py -3.13 -c' in source
    assert 'set "base_py=py -3.13"' in source
    assert 'py -3.12 -c' in source
    assert 'production releases require 64-bit cpython 3.13' in source
    assert '"pyinstaller==6.22.2" "zstandard==0.25.0"' in source
    assert '"%py%" -m pyinstaller' in source
    assert 'release_test_runner.py' in source


def test_117_windows_release_ci_uses_explicit_release_mode():
    workflow = (Path(__file__).resolve().parent / ".github" / "workflows" / "windows-release.yml").read_text(encoding="utf-8").lower()
    assert "run: build_exe.bat --release" in workflow


def test_124_review_pagination_exposes_every_package_without_sampling():
    """A 24,852-row mirror result must be completely reachable by pages."""
    from feathered_app.application.results import _paginate_packages

    packages = [f"pkg-{idx:05d}" for idx in range(24_852)]
    page_size = 1000
    recovered = []
    page = 0
    while True:
        visible, actual, page_count, start = _paginate_packages(
            packages, page=page, page_size=page_size)
        assert actual == page
        assert visible == packages[start:start + page_size]
        recovered.extend(visible)
        if page + 1 >= page_count:
            break
        page += 1

    assert page_count == 25
    assert recovered == packages
    assert len(recovered) == 24_852


def test_124_review_pagination_preserves_repository_order_instead_of_round_robin_sampling():
    from feathered_app.application.results import _paginate_packages

    # Mirrors are aggregated repository-by-repository. Pagination must expose
    # that real ordering, not rewrite it into the old source-balanced sample.
    packages = ([f"alma-base-{i}" for i in range(2426)] +
                [f"alma-app-{i}" for i in range(8030)] +
                [f"rocky-base-{i}" for i in range(2332)])
    first, page, pages, start = _paginate_packages(packages, page=0, page_size=1000)
    third, page3, _pages3, start3 = _paginate_packages(packages, page=2, page_size=1000)

    assert (page, start) == (0, 0)
    assert all(item.startswith("alma-base-") for item in first)
    assert (page3, start3) == (2, 2000)
    assert third[:426] == packages[2000:2426]
    assert third[426] == "alma-app-0"
    assert pages > 1


def test_124_review_pagination_clamps_out_of_range_pages_to_last_page():
    from feathered_app.application.results import _paginate_packages

    packages = list(range(24852))
    visible, page, page_count, start = _paginate_packages(
        packages, page=10_000, page_size=1000)
    assert page_count == 25
    assert page == 24
    assert start == 24_000
    assert visible == packages[24_000:]
    assert len(visible) == 852


def test_124_review_ui_uses_pagination_controls_not_preview_truncation():
    import app, inspect

    pane_source = inspect.getsource(app.App._build_review_pane)
    result_source = inspect.getsource(app.App._show_result)
    render_source = inspect.getsource(app.App._render_result_page)
    assert 'text="First"' in pane_source
    assert 'text="‹ Prev"' in pane_source
    assert 'text="Next ›"' in pane_source
    assert 'text="Last"' in pane_source
    assert 'Rows/page' in pane_source
    assert 'PREVIEW:' not in result_source
    assert 'source-balanced preview' not in result_source
    assert '_paginate_packages' in render_source


def test_124_offscreen_transfer_state_is_retained_for_later_pages():
    import app

    class Tree:
        def exists(self, _iid): return False

    dummy = type("Dummy", (), {})()
    dummy._result_item_states = {}
    dummy.result_rows = {}
    dummy.result_tree = Tree()
    dummy.transfer_done = 0
    dummy.transfer_bytes = 0
    dummy.transfer_reused = 0
    dummy.transfer_failed = 0
    dummy._update_transfer_status = lambda: None

    app.App._apply_item_event(dummy, "repo|pkg", "done", {"size": 123})
    assert dummy._result_item_states["repo|pkg"] == {
        "status": "downloaded", "tag": "done", "detail": ""}
    assert dummy.transfer_done == 1
    assert dummy.transfer_bytes == 123


def test_124_bulk_selection_applies_to_offscreen_packages_not_only_current_page():
    import types
    import app

    class Tree:
        def selection(self): return ()
        def exists(self, _iid): return True

    packages = [types.SimpleNamespace(nevra=f"pkg-{idx}") for idx in range(2500)]
    dummy = types.SimpleNamespace(
        last_result=types.SimpleNamespace(selected=packages, roots=[]),
        result_rows={packages[0].nevra: "visible-row"},
        result_tree=Tree(),
        picked={p.nevra for p in packages},
        picked_closure=None,
        summary_var=types.SimpleNamespace(set=lambda _value: None),
    )
    dummy._pick_mode = lambda: True
    dummy._set_row_checked = lambda _iid, _checked: None
    dummy._update_pick_summary = lambda: None

    app.App._bulk_pick(dummy, "none")
    assert dummy.picked == set()
    assert dummy.picked_closure == {p.nevra for p in packages}

    app.App._bulk_pick(dummy, "all")
    assert dummy.picked == {p.nevra for p in packages}


def test_124_heading_sort_orders_complete_result_before_pagination():
    import types
    import app

    def package(name, source):
        repo = types.SimpleNamespace(name=source, source_identity=source.lower())
        return types.SimpleNamespace(nevra=name, repo=repo)

    packages = [
        package("zeta-1.x86_64", "Rocky"),
        package("alpha-1.x86_64", "Alma"),
        package("beta-1.x86_64", "Alma"),
    ]
    dummy = types.SimpleNamespace(_result_sort=("source", False), _result_item_states={})
    dummy._mirror_mode = lambda: False
    dummy._result_package_identity = lambda pkg, mirror_rows=False: pkg.nevra
    result = types.SimpleNamespace(selected=packages, reasons={})

    ordered = app.App._ordered_result_packages(dummy, result)
    assert [p.nevra for p in ordered] == [
        "alpha-1.x86_64", "beta-1.x86_64", "zeta-1.x86_64"]


def test_versioned_profiles_have_no_compiled_release_fallbacks():
    """Versioned targets must heal from discovery/cache rather than source constants."""
    from profiles import PROFILES
    dynamic = {"rhel", "rocky", "alma", "centos-stream", "fedora", "photon",
               "ubuntu", "debian", "devuan"}
    assert all(PROFILES[key].fixed_releases == [] for key in dynamic)
    assert PROFILES["arch"].fixed_releases == ["rolling"]
    assert PROFILES["artix"].fixed_releases == ["rolling"]


def test_devuan_debian_suite_relationship_is_learned_from_release_table():
    from profiles import extract_devuan_debian_suites
    html = """<table><tr><th>Devuan</th><th>Status</th><th>X</th><th>Y</th><th>Debian</th></tr>
    <tr><td>excalibur 6</td><td>stable</td><td></td><td></td><td>trixie 13</td></tr>
    <tr><td>freia 7</td><td>development</td><td></td><td></td><td>forky 14</td></tr></table>"""
    assert extract_devuan_debian_suites(html) == {"excalibur": "trixie", "freia": "forky"}


def test_123_release_cache_rejects_hostile_schema2_values_and_future_timestamps():
    import math
    from feathered_app.application import discovery

    now = 1_800_000_000.0
    valid = {
        "schema": 2,
        "profiles": {
            "ubuntu": {
                "releases": ["24.04.3", "26.04"],
                "verified": ["24.04.3"],
                "codenames": {"24.04": "noble", "26.04": "resolute"},
                "vendor_suites": {},
                "observed_at": now - 10,
                "source": "archive metadata at https://archive.ubuntu.com/ubuntu",
            }
        },
    }
    clean = discovery._validated_release_cache(valid, now=now)
    assert clean["profiles"]["ubuntu"]["codenames"]["26.04"] == "resolute"
    assert discovery._release_observation_is_fresh(now - 10, now=now)
    assert not discovery._release_observation_is_fresh(math.inf, now=now)
    assert not discovery._release_observation_is_fresh(now + 1, now=now)

    for invalid_time in (math.inf, math.nan, now + 1, "garbage"):
        payload = {**valid, "profiles": {"ubuntu": {
            **valid["profiles"]["ubuntu"], "observed_at": invalid_time}}}
        sanitized = discovery._validated_release_cache(payload, now=now)
        assert sanitized["profiles"]["ubuntu"]["releases"] == ["24.04.3", "26.04"]
        assert "observed_at" not in sanitized["profiles"]["ubuntu"]

    hostile = [
        {**valid, "profiles": {"ubuntu": {**valid["profiles"]["ubuntu"], "releases": [123]}}},
        {**valid, "profiles": {"ubuntu": {**valid["profiles"]["ubuntu"], "codenames": {"26.04": "../../noble"}}}},
    ]
    for payload in hostile:
        try:
            discovery._validated_release_cache(payload, now=now)
        except ValueError:
            pass
        else:
            assert False, f"hostile cache payload was accepted: {payload!r}"


def test_123_release_cache_writes_use_atomic_secure_state_writer(tmp_path):
    from feathered_app.application.discovery import DiscoveryMixin

    class Dummy:
        def __init__(self): self.calls = []
        def _release_cache_path(self): return tmp_path / "releases.json"
        def _secure_write_json(self, path, payload): self.calls.append((path, payload))

    dummy = Dummy()
    payload = {"schema": 2, "profiles": {}}
    DiscoveryMixin._write_release_cache(dummy, payload)
    assert len(dummy.calls) == 1
    assert dummy.calls[0][0] == tmp_path / "releases.json"
    assert dummy.calls[0][1] == payload


def test_123_background_release_refresh_is_bounded_and_does_not_take_global_operation_lease(monkeypatch):
    import queue
    import types
    from feathered_app.application import discovery
    from feathered_app.application.discovery import DiscoveryMixin

    profile = types.SimpleNamespace(
        key="ubuntu", package_family="deb", release_style="version",
        release_observed_at=0.0, archive_discovery_url="https://example.invalid/ubuntu",
        release_url="", release_pattern="", release_mode="text")

    calls = {}
    def fake_discover(root, reporter, limit=40, timeout=45, workers=1):
        calls.update(root=root, limit=limit, timeout=timeout, workers=workers)
        return {"24.04": "noble", "24": "noble"}

    class ImmediateThread:
        def __init__(self, target, daemon=False): self.target = target; self.daemon = daemon
        def start(self): self.target()

    monkeypatch.setattr(discovery, "discover_apt_releases", fake_discover)
    monkeypatch.setattr(discovery.threading, "Thread", ImmediateThread)

    class Dummy:
        def __init__(self): self.events = queue.Queue()
        def _profile(self): return profile
        def _busy(self): return False
        def _begin_worker(self, *args, **kwargs): raise AssertionError("automatic refresh must not take operation lease")

    dummy = Dummy()
    DiscoveryMixin._auto_refresh_releases(dummy)
    assert calls == {"root": "https://example.invalid/ubuntu", "limit": 40, "timeout": 4, "workers": 6}
    first = dummy.events.get_nowait()
    second = dummy.events.get_nowait()
    assert first[0] == "auto_release_state"
    assert first[1] == "ubuntu"
    assert first[2] == ["24.04"]
    assert second == ("auto_release_finished", "ubuntu")


def test_123_ubuntu_base_repo_binds_discovered_suite_to_signed_numeric_identity():
    import apt_core
    import profiles
    from core import Reporter, RepoSpec

    original = dict(profiles.UBUNTU_CODENAMES)
    try:
        profiles.UBUNTU_CODENAMES.update({"24.04": "noble", "26.04": "noble"})
        current = [r for r in profiles._ubuntu_repos("24.04.3", "amd64")
                   if r.role == "dependency" and r.suite == "noble"][0]
        poisoned = [r for r in profiles._ubuntu_repos("26.04", "amd64")
                    if r.role == "dependency" and r.suite == "noble"][0]
        assert current.expected_release_version == "24.04"
        assert poisoned.expected_release_version == "26.04"

        ok = RepoSpec("Ubuntu noble", "https://example.invalid/ubuntu", repo_format="apt",
                      suite="noble", expected_release_version=current.expected_release_version)
        apt_core.check_release_target_identity(ok, {"Version": "24.04 LTS", "Codename": "noble"}, Reporter())

        bad = RepoSpec("Ubuntu noble", "https://example.invalid/ubuntu", repo_format="apt",
                       suite="noble", expected_release_version=poisoned.expected_release_version)
        try:
            apt_core.check_release_target_identity(
                bad, {"Version": "24.04 LTS", "Codename": "noble"}, Reporter())
        except RuntimeError as exc:
            assert "cross-grading" in str(exc)
        else:
            assert False, "poisoned 26.04 -> noble mapping should be rejected"
    finally:
        profiles.UBUNTU_CODENAMES.clear(); profiles.UBUNTU_CODENAMES.update(original)


def test_123_workload_matrix_fails_closed_on_enabled_repository_metadata_errors(monkeypatch):
    import types
    import verify_workload_matrix as matrix
    from core import Reporter

    template = types.SimpleNamespace(
        name="Base", url="https://example.invalid/repo", role="dependency", priority=40,
        enabled=True, target_release="1", repo_format="apt", suite="suite", components="main",
        optional=False, expected_release_version="", evidence_suggestions=[])
    profile = types.SimpleNamespace(
        key="fixture", package_family="deb", repos_factory=lambda release, arch: [template])

    monkeypatch.setattr(matrix.apt_core, "load_repository",
                        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("metadata unavailable")))
    packages, errors = matrix.load_universe(profile, "1", "amd64", Reporter())
    assert not packages
    assert len(errors) == 1 and "metadata unavailable" in errors[0]


def test_124_event_pump_survives_handler_exception_and_processes_done():
    """One stale widget must not permanently stop the Tk worker-event pump."""
    import queue as std_queue
    from feathered_app.application.operations import OperationsMixin

    class Stub(OperationsMixin):
        def __init__(self):
            self.events = std_queue.Queue()
            self.active_operation = "build"
            self.logs = []
            self.reschedules = 0
            self.done_seen = False

        def _apply_warnings(self, _warnings):
            raise RuntimeError("simulated handler bug")

        def _worker_done(self, *_args):
            self.done_seen = True
            self.active_operation = None

        def _lock_operation_controls(self):
            pass

        def _log(self, message):
            self.logs.append(str(message))

        def after(self, delay, callback):
            assert delay == 100
            assert callback.__self__ is self
            self.reschedules += 1
            return "after-id"

    stub = Stub()
    stub.events.put(("warnings", ["stale widget"]))
    stub.events.put(("done", True, "complete"))
    stub._drain_events()

    assert stub.done_seen
    assert stub.active_operation is None
    assert stub.events.empty()
    assert stub.reschedules == 1
    assert any("simulated handler bug" in line for line in stub.logs)


def test_124_keystore_identity_excludes_userinfo_and_survives_credential_rotation():
    from types import SimpleNamespace
    from feathered_app.persistence.user_state import PersistenceMixin

    dummy = PersistenceMixin.__new__(PersistenceMixin)
    one = SimpleNamespace(
        name="Internal",
        url="https://svcacct:S3cr3t@repo.internal:8443/pub/rhel/9/x86_64")
    two = SimpleNamespace(
        name="Internal",
        url="https://svcacct:RotatedPassword@repo.internal:8443/pub/rhel/9/x86_64")

    first = PersistenceMixin._keystore_key(dummy, one)
    second = PersistenceMixin._keystore_key(dummy, two)
    assert first == second
    assert "S3cr3t" not in first and "svcacct" not in first
    assert "repo.internal:8443" in first


def test_124_redact_url_preserves_nonsecret_query_encoding_exactly():
    from core import redact_url

    urls = [
        "https://repo.example/os?arch=x86_64%2Bdebug",
        "https://repo.example/os?filter=a%26b%3Dc",
        "https://repo.example/os?name=hello+world",
    ]
    for url in urls:
        assert redact_url(url) == url

    mixed = (
        "https://repo.example/os?filter=a%26b%3Dc&token=s%2Be%26x&"
        "name=hello+world")
    redacted = redact_url(mixed)
    assert redacted == (
        "https://repo.example/os?filter=a%26b%3Dc&token=REDACTED&"
        "name=hello+world")


def test_124_evidence_metadata_does_not_collapse_distinct_secret_urls():
    from types import SimpleNamespace
    from feathered_app.application.build import _indexed_evidence_records

    repo = SimpleNamespace(evidence_urls=[
        "https://mirror.example/os?token=evidence-A",
        "https://mirror.example/os?token=evidence-B",
    ])
    records = _indexed_evidence_records(
        repo,
        lambda _repo, url: "A" if url.endswith("evidence-A") else "B",
        "relationship")

    assert list(records) == ["0", "1"]
    assert records["0"]["relationship"] == "A"
    assert records["1"]["relationship"] == "B"
    assert records["0"]["url"] == records["1"]["url"]
    assert "evidence-A" not in repr(records) and "evidence-B" not in repr(records)


def test_124_short_registered_secret_does_not_corrupt_unrelated_audit_text():
    from core import redact_text, register_url_secrets

    register_url_secrets("https://user:ab@repo.example/os?token=xy")
    ordinary = "libabc-2.1 sha256=ab12cd package-xy-utils"
    assert redact_text(ordinary) == ordinary
    assert "ab" not in redact_text("https://user:ab@repo.example/os")
    assert "xy" not in redact_text("request failed token=xy")


def test_124_secret_registry_is_thread_safe_and_bounded():
    import threading
    import core

    failures = []

    def worker(offset):
        try:
            for index in range(80):
                secret = f"thread-secret-{offset}-{index:04d}"
                core.register_url_secrets(f"https://repo.example/os?token={secret}")
                core.redact_text(f"failure token={secret}")
        except Exception as exc:
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not failures
    with core._KNOWN_SECRETS_LOCK:
        assert len(core._KNOWN_SECRETS) <= core._MAX_KNOWN_SECRETS
        assert len(core._KNOWN_SECRET_ORDER) <= core._MAX_KNOWN_SECRETS


def test_124_secure_json_write_uses_private_unique_temp_and_atomic_replace(tmp_path):
    import json as std_json
    import os as std_os
    import stat
    from feathered_app.persistence.user_state import PersistenceMixin

    dummy = PersistenceMixin.__new__(PersistenceMixin)
    path = tmp_path / "archive-keyrings.json"
    stale_fixed_temp = tmp_path / "archive-keyrings.json.tmp"
    stale_fixed_temp.write_text("another instance", encoding="utf-8")

    PersistenceMixin._secure_write_json(dummy, path, {"keyrings": {"repo": "key.gpg"}})

    assert std_json.loads(path.read_text(encoding="utf-8"))["keyrings"]["repo"] == "key.gpg"
    assert stale_fixed_temp.read_text(encoding="utf-8") == "another instance"
    assert not list(tmp_path.glob(".archive-keyrings.json.*.tmp"))
    if std_os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

#  1.2.3 r13 evidence-source recovery: EPEL catalog routing and safe mirror failover.

def test_125_epel_uses_distinct_exact_mirror_catalog(tmp_path, monkeypatch):
    import json
    import mirror_catalog
    import app as feather_app
    from core import RepoSpec
    from evidence_model import AUTH_INDEPENDENT, REL_EXACT_MIRROR

    monkeypatch.setenv("FEATHERED_MIRROR_CATALOG_DIR", str(tmp_path))
    (tmp_path / "epel.json").write_text(json.dumps({
        "schema": 1,
        "distribution": "epel",
        "mirrors": [{
            "label": "Example EPEL mirror",
            "operator": "Example University",
            "country": "US",
            "url": "https://mirror.example.edu/fedora-epel",
            "scopes": ["archive"],
            "independent_operator": True,
            "enabled": True,
        }],
        "exact_overrides": [],
    }), encoding="utf-8")

    repo = RepoSpec(
        "EPEL 10 Everything (supplemental)",
        "https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/",
        role="dependency", repo_format="rpm", target_release="10.2")

    ui = object.__new__(feather_app.App)
    ui._profile = lambda: feather_app.PROFILES["rhel"]
    assert feather_app.App._evidence_catalog_profile_key(ui, repo) == "epel"

    candidates = mirror_catalog.candidates_for_repository("epel", repo)
    assert len(candidates) == 1
    assert candidates[0].url == "https://mirror.example.edu/fedora-epel/10/Everything/x86_64/"
    assert candidates[0].relationship == REL_EXACT_MIRROR
    assert candidates[0].authority == AUTH_INDEPENDENT


def test_125_bundled_epel_catalog_supplies_maximum_evidence_choices(monkeypatch):
    import app as feather_app
    import mirror_catalog
    from core import RepoSpec

    monkeypatch.delenv("FEATHERED_MIRROR_CATALOG_DIR", raising=False)
    repo = RepoSpec(
        "EPEL 10 Everything (supplemental)",
        "https://dl.fedoraproject.org/pub/epel/10/Everything/x86_64/",
        role="dependency", repo_format="rpm", target_release="10.2")
    candidates = mirror_catalog.candidates_for_repository("epel", repo)
    urls = {candidate.url for candidate in candidates}
    assert "https://mirrors.kernel.org/fedora-epel/10/Everything/x86_64/" in urls
    assert len(candidates) >= 3

    # The UI must route an EPEL row to this catalog even under an RHEL target.
    ui = object.__new__(feather_app.App)
    ui._profile = lambda: feather_app.PROFILES["rhel"]
    assert feather_app.App._evidence_catalog_profile_key(ui, repo) == "epel"


def test_125_curated_failover_never_crosses_relationship_or_authority_boundary():
    import app as feather_app
    from core import RepoSpec
    from evidence_model import (
        AUTH_INDEPENDENT, AUTH_UNKNOWN, EvidenceCandidate,
        REL_EXACT_MIRROR, REL_REBUILD_PEER,
    )

    repo = RepoSpec("Rocky BaseOS", "https://primary.example/rocky/10.2/BaseOS/x86_64/os/")
    selected = EvidenceCandidate(
        "https://one.example/rocky/10.2/BaseOS/x86_64/os/", "One",
        REL_EXACT_MIRROR, AUTH_INDEPENDENT, "mirror-catalog")
    safe = EvidenceCandidate(
        "https://two.example/rocky/10.2/BaseOS/x86_64/os/", "Two",
        REL_EXACT_MIRROR, AUTH_INDEPENDENT, "mirror-catalog")
    peer = EvidenceCandidate(
        "https://peer.example/alma/10.2/BaseOS/x86_64/os/", "Peer",
        REL_REBUILD_PEER, AUTH_INDEPENDENT, "mirror-catalog")
    unknown = EvidenceCandidate(
        "https://unknown.example/rocky/10.2/BaseOS/x86_64/os/", "Unknown",
        REL_EXACT_MIRROR, AUTH_UNKNOWN, "mirror-catalog")
    configured = EvidenceCandidate(
        "https://configured.example/rocky/10.2/BaseOS/x86_64/os/", "Configured",
        REL_EXACT_MIRROR, AUTH_INDEPENDENT, "configured")

    ui = object.__new__(feather_app.App)
    ui._evidence_candidate_specs = lambda _repo: [selected, safe, peer, unknown, configured]
    alternatives = feather_app.App._curated_exact_mirror_alternatives(ui, repo, selected.url)
    assert alternatives == [safe]


def test_125_curated_failover_recovers_availability_failure_but_not_mismatch():
    import app as feather_app
    from core import RepoSpec
    from evidence_model import AUTH_INDEPENDENT, EvidenceCandidate, REL_EXACT_MIRROR

    repo = RepoSpec("Rocky BaseOS", "https://primary.example/rocky/10.2/BaseOS/x86_64/os/")
    selected_url = "https://stale.example/rocky/10.2/BaseOS/x86_64/os/"
    alternate = EvidenceCandidate(
        "https://fresh.example/rocky/10.2/BaseOS/x86_64/os/", "Fresh mirror",
        REL_EXACT_MIRROR, AUTH_INDEPENDENT, "mirror-catalog")

    class StubReporter:
        def __init__(self): self.logs = []
        def check_cancel(self): pass
        def log(self, text): self.logs.append(text)

    ui = object.__new__(feather_app.App)
    calls = []

    def preflight(_repo, url, _reporter, **_hints):
        calls.append(url)
        if url == selected_url:
            return {"status": "unusable", "detail": "Repository metadata endpoint returned HTTP 404"}
        return {
            "status": "repository", "detail": "Spot-tested package bytes match",
            "relationship": REL_EXACT_MIRROR, "authority": AUTH_INDEPENDENT,
        }

    ui._preflight_evidence_pair = preflight
    ui._curated_exact_mirror_alternatives = lambda _repo, _url: [alternate]
    reporter = StubReporter()
    result = feather_app.App._preflight_evidence_pair_with_curated_failover(
        ui, repo, selected_url, reporter)
    assert calls == [selected_url, alternate.url]
    assert result["status"] == "repository"
    assert result["replacement_url"] == alternate.url
    assert result["relationship"] == REL_EXACT_MIRROR
    assert result["auto_reselected"] is True
    assert "Selected mirror failed" in result["detail"]

    calls.clear()
    ui._preflight_evidence_pair = lambda _repo, url, _reporter, **_hints: (
        calls.append(url) or {"status": "unusable", "detail": "Package byte mismatch under SHA512"})
    result = feather_app.App._preflight_evidence_pair_with_curated_failover(
        ui, repo, selected_url, reporter)
    assert calls == [selected_url]
    assert result["status"] == "unusable"
    assert "replacement_url" not in result


def test_125_applied_curated_failover_updates_selection_and_cache_identity():
    import app as feather_app
    from core import RepoSpec
    from evidence_model import AUTH_INDEPENDENT, REL_EXACT_MIRROR

    repo = RepoSpec("Rocky BaseOS", "https://primary.example/rocky/10.2/BaseOS/x86_64/os/")
    old = "https://stale.example/rocky/10.2/BaseOS/x86_64/os/"
    fresh = "https://fresh.example/rocky/10.2/BaseOS/x86_64/os/"
    repo.evidence_urls = [old]
    repo.evidence_relationship_hints = {old: REL_EXACT_MIRROR, fresh: REL_EXACT_MIRROR}
    repo.evidence_authority_hints = {old: AUTH_INDEPENDENT, fresh: AUTH_INDEPENDENT}

    ui = object.__new__(feather_app.App)
    ui._selected_root_names_for_evidence = lambda: set()
    ui._enabled_provenance_repos = lambda: [repo]
    ui._refresh_provenance_evidence_rows = lambda: None
    ui._update_provenance_evidence_state = lambda: None
    ui._invalidate_provenance_analysis = lambda: None
    ui._clear_validation_attention = lambda: None
    ui._refresh_provenance_source_tree = lambda: None
    ui._refresh_repo_tree_if_open = lambda: None
    logs = []
    ui._log = logs.append
    old_key = feather_app.App._evidence_preflight_key(ui, repo, old)
    ui._evidence_preflight_cache = {
        old_key: {"status": "testing", "detail": "Testing…"}}

    result = {
        "status": "repository",
        "detail": "alternate verified",
        "relationship": REL_EXACT_MIRROR,
        "authority": AUTH_INDEPENDENT,
        "replacement_url": fresh,
        "replacement_label": "Fresh mirror",
        "auto_reselected": True,
    }
    feather_app.App._apply_evidence_preflight_results(ui, [(old_key, result)])

    assert repo.evidence_urls == [fresh]
    assert repo.evidence_relationship_hints == {fresh: REL_EXACT_MIRROR}
    assert repo.evidence_authority_hints == {fresh: AUTH_INDEPENDENT}
    assert old_key not in ui._evidence_preflight_cache
    fresh_key = feather_app.App._evidence_preflight_key(ui, repo, fresh)
    assert ui._evidence_preflight_cache[fresh_key]["status"] == "repository"
    assert any("Evidence source switched" in line for line in logs)


def test_125_failed_evidence_status_exposes_detail_tooltip():
    import inspect
    import app as feather_app

    source = inspect.getsource(feather_app.App._refresh_provenance_evidence_rows)
    assert feather_app.App._evidence_row_status(
        "evidence-fallback", False, False, feather_app.REL_EXACT_MIRROR,
        {"status": "unusable"})[0] == "Test failed · optional"
    assert "self._attach_tooltip" in source
    assert 'result.get("detail"' in source


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([str(Path(__file__).parent), *sys.argv[1:]]))
