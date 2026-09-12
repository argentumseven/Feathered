"""The unified mirror layout may merge only what it can prove is identical.

The separate layout is safe because it decides nothing: each repository is
copied as it stands. A unified mirror does decide things -- it holds one file
per package identity, so wherever two selected repositories publish the same
identity, something must be chosen. These tests pin what Feathered is willing to
choose (a copy it proved byte-identical) and what it refuses to choose (anything
else), because a silent choice here produces a mirror that resolves, installs,
and contains an artifact the operator never picked.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import apt_core
import arch_core
import core
from acquisition_model import (
    MIRROR_LAYOUT_LABELS,
    MirrorLayout,
    mirror_layout_from_label,
)
from core import BuildOptions, Package, RepoSpec, Reporter
from mirror_unification import (
    MIXED_BYTES,
    MIXED_SIZE,
    PRIORITY,
    STRONG,
    UNPROVABLE,
    WEAK,
    MergePolicy,
    conflict_report,
    mirror_sources_record,
    strong_digests,
    unified_mirror_note,
    unify_mirror_packages,
)


def repo(name: str) -> RepoSpec:
    return RepoSpec(name, f"https://example.invalid/{name}/", "dependency")


def rpm(name, source, version="1", digest=None, algorithm="sha256", size=100, extra=None):
    value = digest if digest is not None else hashlib.sha256(name.encode()).hexdigest()
    return Package(name, "x86_64", "0", version, "1", f"{name}.rpm", algorithm, value,
                   source, digests=dict(extra or {}, **{algorithm: value}), size=size)


def deb(name, source, version="1.0", digest=None):
    value = digest if digest is not None else hashlib.sha256(name.encode()).hexdigest()
    return apt_core.DebPackage(name, "amd64", version, f"{name}.deb", "sha256", value,
                               source, digests={"sha256": value}, size=100)


def arch(name, source, version="1.0-1", digest=None):
    value = digest if digest is not None else hashlib.sha256(name.encode()).hexdigest()
    return arch_core.ArchPackage(name=name, arch="x86_64", version=version,
                                 location=f"{name}.pkg.tar.zst", checksum_type="sha256",
                                 checksum=value, repo=source, digests={"sha256": value}, size=100)


# --------------------------------------------------------------------------
# What may be merged
# --------------------------------------------------------------------------

@pytest.mark.parametrize("build,label", [(rpm, "rpm"), (deb, "deb"), (arch, "arch")])
def test_identical_artifact_in_two_repositories_is_kept_once(build, label):
    base, extras = repo("BaseOS"), repo("Extras")
    shared_digest = hashlib.sha256(b"shared").hexdigest()
    packages = [
        build("openssl", base, digest=shared_digest),
        build("only-in-base", base),
        build("openssl", extras, digest=shared_digest),
    ]

    plan = unify_mirror_packages(packages, [base, extras])

    assert plan.ok
    assert plan.retained_count == 2
    assert plan.duplicate_record_count == 1
    assert [p.repo.name for p in plan.packages] == ["BaseOS", "BaseOS"]
    row = plan.deduplicated[0]
    assert row.kept_repository == "BaseOS"
    assert row.duplicate_repositories == ("Extras",)
    assert row.algorithm == "sha256"
    assert row.copies == 2


def test_selection_order_decides_which_repository_supplies_the_bytes():
    """Deterministic and predictable, not whichever record was read first."""
    base, extras = repo("BaseOS"), repo("Extras")
    shared = hashlib.sha256(b"shared").hexdigest()
    packages = [rpm("openssl", extras, digest=shared), rpm("openssl", base, digest=shared)]

    kept_first = unify_mirror_packages(packages, [base, extras])
    kept_second = unify_mirror_packages(packages, [extras, base])

    assert kept_first.packages[0].repo.name == "BaseOS"
    assert kept_second.packages[0].repo.name == "Extras"


def test_stronger_shared_algorithm_is_preferred_for_the_proof():
    base, extras = repo("BaseOS"), repo("Extras")
    weak = hashlib.sha256(b"x").hexdigest()
    strong = hashlib.sha512(b"x").hexdigest()
    left = rpm("openssl", base, digest=weak, extra={"sha512": strong})
    right = rpm("openssl", extras, digest=weak, extra={"sha512": strong})

    plan = unify_mirror_packages([left, right], [base, extras])

    assert plan.ok
    assert plan.deduplicated[0].algorithm == "sha512"


def test_different_versions_of_one_package_are_distinct_identities():
    """base+updates legitimately carry two versions; that is not a duplicate."""
    base, updates = repo("Base"), repo("Updates")
    plan = unify_mirror_packages(
        [rpm("bash", base, version="5.1"), rpm("bash", updates, version="5.2")],
        [base, updates])

    assert plan.ok
    assert plan.retained_count == 2
    assert plan.deduplicated == ()


def test_three_repositories_publishing_one_artifact_collapse_to_one():
    a, b, c = repo("A"), repo("B"), repo("C")
    shared = hashlib.sha256(b"shared").hexdigest()
    plan = unify_mirror_packages(
        [rpm("zlib", a, digest=shared), rpm("zlib", b, digest=shared),
         rpm("zlib", c, digest=shared)], [a, b, c])

    assert plan.retained_count == 1
    assert plan.duplicate_record_count == 2
    assert plan.deduplicated[0].duplicate_repositories == ("B", "C")


# --------------------------------------------------------------------------
# What may not be merged
# --------------------------------------------------------------------------

def test_same_identity_with_different_bytes_is_a_conflict_not_a_choice():
    base, vendor = repo("BaseOS"), repo("Vendor")
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest="a" * 64), rpm("openssl", vendor, digest="b" * 64)],
        [base, vendor])

    assert not plan.ok
    assert plan.conflicts[0].reason == MIXED_BYTES
    assert set(plan.conflicts[0].repositories) == {"BaseOS", "Vendor"}
    # The contested identity is withheld entirely rather than silently resolved.
    assert all(p.nevra != plan.conflicts[0].identity for p in plan.packages)


def test_no_shared_algorithm_is_a_conflict_under_the_default_policy():
    base, vendor = repo("BaseOS"), repo("Vendor")
    left = rpm("openssl", base, algorithm="sha256")
    right = rpm("openssl", vendor, algorithm="sha512",
                digest=hashlib.sha512(b"openssl").hexdigest())
    right.digests = {"sha512": right.checksum}

    plan = unify_mirror_packages([left, right], [base, vendor])

    assert not plan.ok
    assert plan.conflicts[0].reason == UNPROVABLE


def test_matching_digest_with_disagreeing_size_is_a_conflict():
    base, vendor = repo("BaseOS"), repo("Vendor")
    shared = hashlib.sha256(b"shared").hexdigest()
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest=shared, size=100),
         rpm("openssl", vendor, digest=shared, size=200)], [base, vendor])

    assert not plan.ok
    assert plan.conflicts[0].reason == MIXED_SIZE


def test_agreeing_weak_digest_plus_size_is_recorded_as_a_weak_merge():
    """Not proof of provenance, but decisive against accidental difference.

    Refusing here would block repositories that publish only sha1/md5, which is
    a metadata-format difference rather than a disagreement. The merge happens
    and the weaker basis is recorded rather than flattened into 'deduplicated'.
    """
    base, vendor = repo("BaseOS"), repo("Vendor")
    left = rpm("openssl", base, algorithm="md5", digest="d" * 32)
    right = rpm("openssl", vendor, algorithm="md5", digest="d" * 32)
    left.digests = right.digests = {"md5": "d" * 32}

    plan = unify_mirror_packages([left, right], [base, vendor])

    assert plan.ok
    assert plan.deduplicated[0].basis == WEAK
    assert plan.weakly_proven_count == 1
    assert plan.unproven_count == 0
    assert strong_digests(left) == {}


def test_disagreeing_weak_digest_is_still_decisive():
    """A weaker algorithm cannot redeem a digest that provably differs."""
    base, vendor = repo("BaseOS"), repo("Vendor")
    left = rpm("openssl", base, algorithm="md5", digest="d" * 32)
    right = rpm("openssl", vendor, algorithm="md5", digest="e" * 32)
    left.digests, right.digests = {"md5": "d" * 32}, {"md5": "e" * 32}

    plan = unify_mirror_packages([left, right], [base, vendor])

    assert not plan.ok
    assert plan.conflicts[0].reason == MIXED_BYTES


def test_conflict_report_names_the_identities_and_offers_the_way_out():
    base, vendor = repo("BaseOS"), repo("Vendor")
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest="a" * 64), rpm("openssl", vendor, digest="b" * 64)],
        [base, vendor])

    report = conflict_report(plan)

    assert "openssl" in report
    assert "BaseOS" in report and "Vendor" in report
    assert "separate-directories mirror layout" in report


def test_conflicts_do_not_hide_behind_a_truncated_report():
    base, vendor = repo("BaseOS"), repo("Vendor")
    packages = []
    for index in range(25):
        packages.append(rpm(f"pkg{index}", base, digest="a" * 64))
        packages.append(rpm(f"pkg{index}", vendor, digest="b" * 64))

    plan = unify_mirror_packages(packages, [base, vendor])
    report = conflict_report(plan, limit=5)

    assert len(plan.conflicts) == 25
    assert "and 20 more" in report
    assert "25 package identity/identities" in report


# --------------------------------------------------------------------------
# What the operator is told afterwards
# --------------------------------------------------------------------------

def test_note_states_that_a_unified_mirror_is_nobody_upstream():
    base, extras = repo("BaseOS"), repo("Extras")
    shared = hashlib.sha256(b"s").hexdigest()
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest=shared), rpm("openssl", extras, digest=shared)],
        [base, extras])

    note = unified_mirror_note(plan)

    assert "UNIFIED mirror" in note
    assert "not a copy of any single one of them" in note
    assert "1. BaseOS" in note and "2. Extras" in note
    assert "Duplicate records removed:     1" in note


def test_sources_record_attributes_every_retained_package():
    base, extras = repo("BaseOS"), repo("Extras")
    shared = hashlib.sha256(b"s").hexdigest()
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest=shared), rpm("solo", extras),
         rpm("openssl", extras, digest=shared)], [base, extras])

    record = mirror_sources_record(plan)
    json.dumps(record)  # must be serializable as written to the bundle

    rows = {row["identity"]: row for row in record["packages"]}
    merged = next(r for i, r in rows.items() if i.startswith("openssl"))
    assert merged["supplied_by"] == "BaseOS"
    assert merged["also_published_by"] == ["Extras"]
    assert merged["duplicate_proof"]["algorithm"] == "sha256"
    solo = next(r for i, r in rows.items() if i.startswith("solo"))
    assert solo["also_published_by"] == [] and solo["duplicate_proof"] is None
    assert record["duplicate_records_removed"] == 1


def test_empty_selection_summarises_without_raising():
    plan = unify_mirror_packages([], [])
    assert plan.ok and plan.retained_count == 0
    assert "no repositories" in plan.summary()


# --------------------------------------------------------------------------
# Wiring: the layout control and the publication path
# --------------------------------------------------------------------------

def test_layout_label_round_trips_and_defaults_conservatively():
    for layout in (MirrorLayout.SEPARATE, MirrorLayout.UNIFIED):
        assert mirror_layout_from_label(MIRROR_LAYOUT_LABELS[layout]) is layout
    for junk in ("", None, "whatever the operator typed"):
        assert mirror_layout_from_label(junk) is MirrorLayout.SEPARATE


def test_absent_layout_control_never_means_merge():
    """A stub host, or a mirror run started before the control existed."""
    from feathered_app.application.sources import SourcesMixin

    assert SourcesMixin._mirror_layout(SimpleNamespace()) is MirrorLayout.SEPARATE

    class Broken:
        @property
        def mirror_layout_var(self):
            raise RuntimeError("Tk is gone")

    shell = SimpleNamespace()
    shell.__dict__["mirror_layout_var"] = SimpleNamespace(get=lambda: 1 / 0)
    assert SourcesMixin._mirror_layout(shell) is MirrorLayout.SEPARATE


def test_unified_inventory_refuses_conflicts_before_any_bytes_are_fetched():
    from feathered_app.application.sources import SourcesMixin

    base, vendor = repo("BaseOS"), repo("Vendor")
    by_source = {
        base.source_identity: [rpm("openssl", base, digest="a" * 64)],
        vendor.source_identity: [rpm("openssl", vendor, digest="b" * 64)],
    }
    shell = SimpleNamespace(_is_deb=lambda: False, _is_arch=lambda: False)

    with pytest.raises(RuntimeError) as excinfo:
        SourcesMixin._unified_mirror_result(shell, [base, vendor], by_source, Reporter())

    assert "could not be proven identical" in str(excinfo.value)


def test_unified_inventory_produces_one_result_carrying_the_plan():
    from feathered_app.application.sources import SourcesMixin

    base, extras = repo("BaseOS"), repo("Extras")
    shared = hashlib.sha256(b"s").hexdigest()
    by_source = {
        base.source_identity: [rpm("openssl", base, digest=shared), rpm("solo", base)],
        extras.source_identity: [rpm("openssl", extras, digest=shared)],
    }
    shell = SimpleNamespace(_is_deb=lambda: False, _is_arch=lambda: False)
    result = SourcesMixin._unified_mirror_result(shell, [base, extras], by_source, Reporter())

    assert result.mirror_repository_results == []
    assert result.mirror_unified_plan.retained_count == 2
    # Review sees the merged population and the post-merge transfer total.
    assert len(result.selected) == 2
    assert [p.repo.name for p in result.selected] == ["BaseOS", "BaseOS"]
    assert [row["package_count"] for row in result.mirror_repository_summaries] == [2, 1]


def test_unified_layout_publishes_one_folder_not_one_per_repository():
    from feathered_app.application.output import OutputMixin

    shell = SimpleNamespace(
        _mirror_mode=lambda: True,
        _mirror_layout=lambda: MirrorLayout.UNIFIED,
        _selected_mirror_repositories=lambda: [repo("A"), repo("B")])
    assert OutputMixin._mirror_output_folder_names(shell) == []


def test_unified_folder_name_is_stable_and_carries_no_repository_component():
    import app

    shell = object.__new__(app.App)
    shell._mirror_mode = lambda: True
    shell._mirror_layout = lambda: MirrorLayout.UNIFIED
    shell._single_mode = lambda: False
    shell._profile = lambda: SimpleNamespace(key="rhel", package_family="rpm")
    shell.release_var = SimpleNamespace(get=lambda: "9")
    shell.arch_var = SimpleNamespace(get=lambda: "x86_64")
    shell.folder_scheme_var = SimpleNamespace(get=lambda: "Contents only")
    shell.folder_label_var = SimpleNamespace(get=lambda: "")
    shell.folder_stamp_var = SimpleNamespace(get=lambda: "none")

    name = app.App._folder_name(shell, mirror_repo=repo("BaseOS"))

    assert name == "mirror-unified-offline"
    assert "BaseOS" not in name


# --------------------------------------------------------------------------
# End to end: a real unified bundle on disk
# --------------------------------------------------------------------------

def _unified_bundle(tmp_path: Path):
    extras = repo("Extras")
    payload = tmp_path / "openssl.rpm"
    payload.write_bytes(b"openssl-bytes")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    local = RepoSpec("Local", tmp_path.as_uri() + "/", "dependency")
    pkg = Package("openssl", "x86_64", "0", "1", "1", "openssl.rpm", "sha256", digest,
                  local, digests={"sha256": digest}, size=payload.stat().st_size)
    duplicate = Package("openssl", "x86_64", "0", "1", "1", "openssl.rpm", "sha256", digest,
                        extras, digests={"sha256": digest}, size=payload.stat().st_size)
    plan = unify_mirror_packages([pkg, duplicate], [local, extras])
    assert plan.ok

    options = BuildOptions(retries=1)
    options.unified_mirror_note = unified_mirror_note(plan)
    options.unified_mirror_records = mirror_sources_record(plan)
    out = tmp_path / "bundle"
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), out, options, Reporter(),
                      {"workload": "unified-mirror", "repository_mirror": True})
    return out, plan


def test_unified_bundle_carries_its_merge_record(tmp_path):
    out, plan = _unified_bundle(tmp_path)

    note = (out / "UNIFIED-MIRROR.txt").read_text(encoding="utf-8")
    assert "UNIFIED mirror" in note
    # Payload-scoped, so the merge record travels with the package set it
    # describes rather than sitting loose at the bundle root.
    record = json.loads((out / "rpms" / "mirror-sources.json").read_text(encoding="utf-8"))
    assert record["mirror_layout"] == "unified"
    assert record["duplicate_records_removed"] == 1
    assert record["packages"][0]["also_published_by"] == ["Extras"]


def test_merge_record_is_written_before_the_bundle_index_is_sealed(tmp_path):
    """A file added after sealing makes a sealed mirror fail its own verifier."""
    out, _plan = _unified_bundle(tmp_path)
    core.write_bundle_index(out, Reporter(), {"tool": "test", "bundle_id": out.name})

    index = json.loads((out / "bundle-index.json").read_text(encoding="utf-8"))
    listed = {entry["path"] for entry in index["files"]}
    assert "UNIFIED-MIRROR.txt" in listed
    assert "rpms/mirror-sources.json" in listed


def test_every_backend_writes_the_merge_record_before_sealing(tmp_path):
    """The hook must fire for deb and pacman bundles, not only rpm."""
    extras = repo("Extras")
    plan_options = {}
    for family in ("deb", "arch"):
        root = tmp_path / family
        root.mkdir()
        local = RepoSpec("Local", root.as_uri() + "/", "dependency",
                         repo_format="apt" if family == "deb" else "arch",
                         suite="stable", components="main")
        if family == "deb":
            payload = root / "demo.deb"
            payload.write_bytes(b"deb-bytes")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            pkg = apt_core.DebPackage("demo", "amd64", "1.0", "demo.deb", "sha256", digest,
                                      local, digests={"sha256": digest},
                                      size=payload.stat().st_size)
            twin = apt_core.DebPackage("demo", "amd64", "1.0", "demo.deb", "sha256", digest,
                                       extras, digests={"sha256": digest},
                                       size=payload.stat().st_size)
            result = apt_core.DebResolutionResult([pkg], [], [pkg])
            writer, payload_dir = apt_core.write_bundle, "debs"
        else:
            payload = root / "demo-1.0-x86_64.pkg.tar.zst"
            payload.write_bytes(b"arch-bytes")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            pkg = arch_core.ArchPackage(
                name="demo", arch="x86_64", version="1.0",
                location=payload.name, checksum_type="sha256", checksum=digest,
                repo=local, digests={"sha256": digest}, size=payload.stat().st_size)
            pkg.provides = [arch_core.ArchRelation("demo", "=", "1.0", "provides")]
            twin = arch_core.ArchPackage(
                name="demo", arch="x86_64", version="1.0",
                location=payload.name, checksum_type="sha256", checksum=digest,
                repo=extras, digests={"sha256": digest}, size=payload.stat().st_size)
            result = arch_core.ArchResolutionResult([pkg], [], [pkg])
            writer, payload_dir = arch_core.write_bundle, "packages"

        merge = unify_mirror_packages([pkg, twin], [local, extras])
        assert merge.ok and merge.duplicate_record_count == 1
        options = BuildOptions(retries=1)
        options.unified_mirror_note = unified_mirror_note(merge)
        options.unified_mirror_records = mirror_sources_record(merge)
        out = root / "bundle"
        writer(result, out, options, Reporter(), {"workload": "unified-mirror"})

        core.write_bundle_index(out, Reporter(), {"tool": "test", "bundle_id": out.name})
        index = json.loads((out / "bundle-index.json").read_text(encoding="utf-8"))
        listed = {entry["path"] for entry in index["files"]}
        assert "UNIFIED-MIRROR.txt" in listed, family
        assert f"{payload_dir}/mirror-sources.json" in listed, family
        plan_options[family] = merge
    assert set(plan_options) == {"deb", "arch"}


def test_separate_layout_writes_no_merge_record(tmp_path):
    """The default publication is unchanged and gains no unified artifacts."""
    payload = tmp_path / "demo.rpm"
    payload.write_bytes(b"demo")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    local = RepoSpec("Local", tmp_path.as_uri() + "/", "dependency")
    pkg = Package("demo", "x86_64", "0", "1", "1", "demo.rpm", "sha256", digest, local,
                  digests={"sha256": digest}, size=payload.stat().st_size)
    out = tmp_path / "plain"
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), out, BuildOptions(retries=1),
                      Reporter(), {"workload": "separate-mirror"})

    assert not (out / "UNIFIED-MIRROR.txt").exists()
    assert not (out / "rpms" / "mirror-sources.json").exists()


# --------------------------------------------------------------------------
# Disagreement policy
# --------------------------------------------------------------------------

def test_prefer_priority_merges_what_strict_refuses():
    """The operator asked for resolution by selection order, so resolve."""
    base, vendor = repo("BaseOS"), repo("Vendor")
    left = rpm("openssl", base, algorithm="sha256")
    right = rpm("openssl", vendor, algorithm="sha512",
                digest=hashlib.sha512(b"openssl").hexdigest())
    right.digests = {"sha512": right.checksum}

    assert not unify_mirror_packages([left, right], [base, vendor]).ok

    plan = unify_mirror_packages([left, right], [base, vendor],
                                 MergePolicy.PREFER_PRIORITY)

    assert plan.ok
    assert plan.retained_count == 1
    assert plan.packages[0].repo.name == "BaseOS"
    assert plan.deduplicated[0].basis == PRIORITY
    assert plan.unproven_count == 1


def test_priority_merge_is_recorded_not_disguised_as_proof():
    """An unchecked merge must not be reported as a verified duplicate."""
    base, vendor = repo("BaseOS"), repo("Vendor")
    left = rpm("openssl", base, digest="a" * 64)
    right = rpm("openssl", vendor, digest="b" * 64)

    plan = unify_mirror_packages([left, right], [base, vendor],
                                 MergePolicy.PREFER_PRIORITY)

    assert plan.ok and plan.unproven_count == 1
    row = mirror_sources_record(plan)["packages"][0]
    assert row["merge_basis"] == PRIORITY
    assert row["duplicate_proof"] is None, "unchecked merges must carry no proof"
    note = unified_mirror_note(plan)
    assert "WARNING" in note and "resolved by priority" in note


def test_one_unprovable_pair_downgrades_the_whole_identity():
    """A group must not be reported as proven because most of it was."""
    a, b, c = repo("A"), repo("B"), repo("C")
    shared = hashlib.sha256(b"shared").hexdigest()
    odd = rpm("zlib", c, algorithm="sha512", digest=hashlib.sha512(b"z").hexdigest())
    odd.digests = {"sha512": odd.checksum}

    plan = unify_mirror_packages(
        [rpm("zlib", a, digest=shared), rpm("zlib", b, digest=shared), odd],
        [a, b, c], MergePolicy.PREFER_PRIORITY)

    assert plan.ok
    assert plan.deduplicated[0].basis == PRIORITY
    assert plan.deduplicated[0].duplicate_repositories == ("B", "C")


def test_strict_remains_the_default_everywhere():
    """An unset or unreadable control must never mean 'merge unchecked'."""
    from feathered_app.application.sources import SourcesMixin

    assert SourcesMixin._merge_policy(SimpleNamespace()) is MergePolicy.STRICT
    shell = SimpleNamespace()
    shell.__dict__["mirror_conflict_policy_var"] = SimpleNamespace(get=lambda: 1 / 0)
    assert SourcesMixin._merge_policy(shell) is MergePolicy.STRICT
    assert unify_mirror_packages([], []).policy is MergePolicy.STRICT


def test_conflict_report_names_the_policy_that_would_resolve_it():
    base, vendor = repo("BaseOS"), repo("Vendor")
    plan = unify_mirror_packages(
        [rpm("openssl", base, digest="a" * 64), rpm("openssl", vendor, digest="b" * 64)],
        [base, vendor])

    report = conflict_report(plan)

    assert "Prefer the higher-priority repository" in report
    assert "mirror-sources.json" in report
