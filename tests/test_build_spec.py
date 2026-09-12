"""The build request must be decided once and then be unable to change.

Feathered currently reads roughly two dozen Tk variables at scattered points
*during* a build, and defends against them moving with `_signature()`,
`locked_output_folder_name`, `locked_mirror_publications`, and a runtime guard
that aborts with "Mirror publication plan changed after output folders were
locked." Every one of those is a purchased defence against mutable state.

These tests pin the replacement. The most load-bearing one is
`test_capture_reads_every_wizard_control`, which fails when a control is added
to the wizard without being captured -- because a spec that silently omits a
field is worse than no spec at all: the build would then read a stale or empty
value with no error anywhere.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import build_spec
from build_spec import (
    SPEC_VERSION,
    BuildSpec,
    OutputSpec,
    RepositoryRecord,
    TargetSpec,
    capture,
)
from core import RepoSpec

tk = pytest.importorskip("tkinter")


def _display_available() -> bool:
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


requires_display = pytest.mark.skipif(
    not _display_available(), reason="no display; run under xvfb-run")


class Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


def _host(**overrides):
    """A stand-in wizard. Overrides already exposing .get() are used as-is."""
    host = SimpleNamespace()
    for name in build_spec.captured_variable_names():
        supplied = overrides.pop(name, None)
        if supplied is None:
            host.__dict__[name] = Var(f"<{name}>")
        elif hasattr(supplied, "get"):
            host.__dict__[name] = supplied
        else:
            host.__dict__[name] = Var(supplied)
    host.__dict__.update(overrides)
    return host


# --------------------------------------------------------------------------
# Immutability
# --------------------------------------------------------------------------

def test_a_spec_cannot_be_edited_after_it_is_made():
    from dataclasses import FrozenInstanceError

    spec = capture(_host())
    with pytest.raises(FrozenInstanceError):
        spec.target.arch = "changed"
    with pytest.raises(FrozenInstanceError):
        spec.output.directory = "/somewhere/else"


def test_a_change_produces_a_new_spec():
    spec = capture(_host())
    updated = spec.replace_section(output=OutputSpec(directory="/new"))
    assert updated is not spec
    assert updated.output.directory == "/new"
    assert spec.output.directory != "/new"


# --------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------

def test_capture_reads_the_wizard_state():
    spec = capture(_host(arch_var="x86_64", release_var="9", out_var="/bundles"))
    assert spec.target.arch == "x86_64"
    assert spec.target.release == "9"
    assert spec.output.directory == "/bundles"


def test_capture_reads_every_wizard_control():
    """A control added without being captured is a silent stale-value bug.

    Every name in captured_variable_names() must reach a spec field, and the
    section field count must match, so adding a field to a section without
    wiring it into capture() fails here rather than at build time.
    """
    spec = capture(_host())
    flattened = json.dumps(spec.to_dict())
    scalar_vars = [name for name in build_spec.captured_variable_names()
                   if name not in ("emit_repo_var", "sign_index_var", "pin_to_inventory_baseline_var", "advisories_acknowledged_var")]
    missing = [name for name in scalar_vars if f"<{name}>" not in flattened]
    assert not missing, f"captured but never stored in the spec: {missing}"
    flags = capture(_host(pin_to_inventory_baseline_var=False, advisories_acknowledged_var=True))
    assert flags.content.pin_to_inventory_baseline is False
    assert flags.content.advisories_acknowledged is True

    # 24 scalar controls, plus five fields that come from somewhere other than
    # a control: repositories, exact_packages, and the three mirror/derived
    # values. Every field must have a source, or the build reads a default.
    # FIELD_TO_VARIABLE is larger: it also carries the two mirror settings,
    # which capture() derives through _mirror_layout/_merge_policy rather than
    # reading their controls, but apply() must still write back.
    assert len(build_spec.FIELD_TO_VARIABLE) == len(build_spec.captured_variable_names()) + 2
    assert build_spec.section_field_count() == len(build_spec.captured_variable_names()) + 6, (
        "a spec field was added or removed without updating capture(); "
        "every field must come from somewhere or the build reads a default")


def test_missing_controls_yield_documented_defaults_not_exceptions():
    """Capture runs against partially built hosts during migration."""
    spec = capture(SimpleNamespace())
    assert spec.target.arch == ""
    assert spec.output.emit_repository is True
    assert spec.output.sign_bundle_index is False
    assert spec.mirror.layout == "separate"
    assert spec.mirror.disagreement_policy == "strict"


def test_an_unreadable_control_does_not_take_the_capture_down():
    class Broken:
        def get(self):
            raise RuntimeError("Tk is gone")

    spec = capture(_host(arch_var=Var("x86_64"), release_var=Broken()))
    assert spec.target.release == ""
    assert spec.target.arch == "x86_64"


def test_mirror_layout_and_policy_come_from_the_domain_not_the_label():
    from acquisition_model import MirrorLayout
    from mirror_unification import MergePolicy

    host = _host()
    host._mirror_layout = lambda: MirrorLayout.UNIFIED
    host._merge_policy = lambda: MergePolicy.PREFER_PRIORITY

    spec = capture(host)

    assert spec.mirror.layout == "unified"
    assert spec.mirror.disagreement_policy == "prefer-priority"


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

def test_repositories_are_captured_as_data():
    repo = RepoSpec("BaseOS", "https://example.invalid/base/", "dependency",
                    repo_format="rpm-md", suite="stable", components="main")
    host = _host(repository_rows=lambda: [repo])

    spec = capture(host)

    assert len(spec.sources.repositories) == 1
    row = spec.sources.repositories[0]
    assert row.name == "BaseOS"
    assert row.url == "https://example.invalid/base/"
    assert row.repo_format == "rpm-md"


def test_credential_material_never_reaches_a_saved_spec():
    """A build profile is a file an operator may hand to someone else."""
    repo = RepoSpec("Vendor", "https://vendor.invalid/", "dependency")
    for attribute, value in (("client_cert", "/home/steve/client.pem"),
                             ("client_key", "/home/steve/client.key"),
                             ("ca_cert", "/home/steve/ca.pem"),
                             ("keyring", "/home/steve/secret.gpg")):
        try:
            object.__setattr__(repo, attribute, value)
        except AttributeError:  # pragma: no cover - property without a setter
            pass

    text = capture(_host(repository_rows=lambda: [repo])).to_json()

    for leaked in ("client.pem", "client.key", "ca.pem", "secret.gpg"):
        assert leaked not in text, f"{leaked} must not be written to a build spec"
    assert "keyring" not in RepositoryRecord.__dataclass_fields__


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------

def test_a_spec_survives_a_json_round_trip():
    repo = RepoSpec("BaseOS", "https://example.invalid/base/", "dependency")
    original = capture(_host(repository_rows=lambda: [repo],
                             mirror_repos={"b", "a"}))

    restored = BuildSpec.from_json(original.to_json())

    assert restored == original


def test_an_older_spec_with_unknown_keys_still_loads():
    """A profile written by a newer minor version must not be unopenable."""
    payload = capture(_host()).to_dict()
    payload["target"]["some_future_field"] = "ignored"
    payload["sources"]["repositories"] = [{"name": "R", "url": "u", "unknown": 1}]

    restored = BuildSpec.from_dict(payload)

    assert restored.sources.repositories[0].name == "R"


def test_a_spec_from_a_newer_version_is_refused_clearly():
    payload = capture(_host()).to_dict()
    payload["spec_version"] = SPEC_VERSION + 1

    with pytest.raises(ValueError) as excinfo:
        BuildSpec.from_dict(payload)

    assert "newer Feathered" in str(excinfo.value)


def test_serialization_is_stable_for_the_same_inputs():
    """Reproducible builds start with a reproducible request."""
    host = _host()
    assert capture(host).to_json() == capture(host).to_json()


def test_defaults_alone_produce_a_valid_round_trip():
    assert BuildSpec.from_json(BuildSpec().to_json()) == BuildSpec()
    assert BuildSpec().target == TargetSpec()


# --------------------------------------------------------------------------
# Against the real application
# --------------------------------------------------------------------------

@requires_display
def test_capture_works_against_the_real_window(tmp_path, monkeypatch):
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    import app

    window = app.App()
    try:
        spec = capture(window)
    finally:
        window.destroy()

    assert spec.target.arch
    assert spec.output.folder_scheme
    assert spec.content.selection_mode
    assert BuildSpec.from_json(spec.to_json()) == spec


# --------------------------------------------------------------------------
# Exact-package replay
# --------------------------------------------------------------------------

def _chosen(name, version, repo_name="BaseOS"):
    from types import SimpleNamespace

    return SimpleNamespace(
        name=name, evr_text=version, arch="x86_64",
        repo=SimpleNamespace(name=repo_name, role="dependency",
                             source_identity=f"id::{repo_name}"))


def test_exact_package_roots_are_captured():
    """Absent entirely before 1.2.12: a saved spec could not replay this build."""
    host = _host()
    host.__dict__["selected_packages"] = [_chosen("openssl", "1:3.0.7-1"),
                                          _chosen("curl", "7.85.0-1", "AppStream")]

    spec = capture(host)

    assert [row.name for row in spec.content.exact_packages] == ["openssl", "curl"]
    assert spec.content.exact_packages[0].version == "1:3.0.7-1"
    assert spec.content.exact_packages[1].repository == "AppStream"
    assert spec.content.exact_packages[1].source_identity == "id::AppStream"


def test_exact_package_roots_survive_a_round_trip():
    host = _host()
    host.__dict__["selected_packages"] = [_chosen("openssl", "1:3.0.7-1")]
    original = capture(host)

    restored = BuildSpec.from_json(original.to_json())

    assert restored == original
    assert restored.content.exact_packages[0].name == "openssl"


def test_a_replayed_spec_produces_the_same_request_tuples():
    """Replay must reproduce the request, not just the serialized text.

    The tuple shape here is the one `_package_requests` builds for a chosen
    package, so a divergence shows up as a different build rather than as a
    failed comparison somewhere harmless.
    """
    host = _host()
    host.__dict__["selected_packages"] = [_chosen("openssl", "1:3.0.7-1")]

    requests = build_spec.package_requests_from(BuildSpec.from_json(capture(host).to_json()))

    assert requests == [("openssl", "1:3.0.7-1", "dependency", "BaseOS",
                         "x86_64", None, "id::BaseOS")]


def test_no_resolved_package_state_reaches_a_saved_spec():
    """A spec records what was asked for, not the metadata of the moment.

    Checksums, sizes and repository handles describe the repository as it stood
    when the spec was written; a replay weeks later resolves against whatever is
    published then, and carrying stale digests would either mislead or fail.
    """
    from types import SimpleNamespace

    package = _chosen("openssl", "1:3.0.7-1")
    package.checksum = "deadbeef" * 8
    package.size = 123456
    package.digests = {"sha256": "deadbeef" * 8}
    package.repo = SimpleNamespace(
        name="BaseOS", role="dependency", source_identity="id::BaseOS",
        keyring="/home/steve/secret.gpg")

    host = _host()
    host.__dict__["selected_packages"] = [package]
    text = capture(host).to_json()

    for leaked in ("deadbeef", "123456", "secret.gpg"):
        assert leaked not in text, f"{leaked} must not be written to a build spec"
