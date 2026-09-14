"""Guardrails for the assurance vocabulary.

The mode names are short because they appear in tables, which means a reader
will infer a strength ordering from the words alone. These tests pin the
ordering and require every mode to say what it does not prove, so a future mode
cannot be added with a reassuring name and no definition.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import provenance


def _mode_constants() -> dict[str, str]:
    """Every module-level mode string, by constant name."""
    skip = {"PROVENANCE_EVIDENCE_NONE"}  # a sentinel, not an assurance outcome
    return {
        name: value for name, value in vars(provenance).items()
        if name.isupper() and isinstance(value, str)
        and (name.startswith(("VERIFIED_", "PROVENANCE_")) or name == "UNVERIFIED")
        and name not in skip
    }


def test_every_assurance_mode_has_a_definition():
    missing = [
        f"{name}={value!r}" for name, value in _mode_constants().items()
        if value not in provenance.ASSURANCE_SEMANTICS
    ]
    assert not missing, (
        "assurance modes with no semantics entry: " + ", ".join(missing) +
        ". A mode that ships without an explicit 'does not prove' is a name a "
        "reader will over-trust."
    )


def test_every_definition_states_both_halves():
    for mode, row in provenance.ASSURANCE_SEMANTICS.items():
        assert row.proves.strip(), f"{mode} does not say what it proves"
        assert row.does_not_prove.strip(), f"{mode} does not say what it fails to prove"
        assert row.mode == mode
        assert row.authority in {"vendor", "archive", "acquisition", "corroboration", "none"}


def test_peer_lineage_ranks_below_signatures_and_byte_match():
    """The README says peers are not substitutes for exact bytes. Pin that."""
    rank = {mode: row.rank for mode, row in provenance.ASSURANCE_SEMANTICS.items()}
    peer = rank[provenance.VERIFIED_PEER_CORROBORATED]
    assert peer < rank[provenance.VERIFIED_VENDOR]
    assert peer < rank[provenance.VERIFIED_ARCHIVE]
    assert peer < rank[provenance.VERIFIED_BYTE_CORROBORATED], (
        "independent rebuilds produce different binaries by construction, so peer "
        "lineage must never outrank an actual byte comparison"
    )
    assert rank[provenance.UNVERIFIED] == 0


def test_signature_modes_outrank_every_corroboration_mode():
    sem = provenance.ASSURANCE_SEMANTICS
    signed = min(sem[m].rank for m in (provenance.VERIFIED_VENDOR, provenance.VERIFIED_ARCHIVE))
    corroboration = [row.rank for row in sem.values() if row.authority == "corroboration"]
    assert corroboration and max(corroboration) < signed


def test_legend_is_ordered_strongest_first_and_scoped_to_present_modes():
    legend = provenance.assurance_legend(
        [provenance.UNVERIFIED, provenance.VERIFIED_VENDOR, provenance.VERIFIED_PEER_CORROBORATED])
    assert [row["mode"] for row in legend] == [
        provenance.VERIFIED_VENDOR,
        provenance.VERIFIED_PEER_CORROBORATED,
        provenance.UNVERIFIED,
    ]
    assert all("proves" in row and "does_not_prove" in row for row in legend)


def test_unknown_mode_gets_an_explicit_placeholder_not_a_guess():
    row = provenance.explain_assurance("some-future-mode")
    assert row.rank == 0
    assert "Unknown" in row.proves
    assert "Do not infer strength" in row.does_not_prove


def test_bundle_provenance_embeds_the_legend_for_its_own_modes():
    record = provenance.build_provenance(
        bundle_id="t", target={}, repositories=[], entries=[], warnings=[])
    entry = provenance.PackageProvenance(
        package_id="x-1.0", filename="x.rpm", sha256="a" * 64, size=1,
        source_url="https://example.invalid/x.rpm", repository="test")
    entry.assurance = provenance.VERIFIED_VENDOR
    entry.vendor_signature_verified = True
    record.packages.append(entry)

    payload = json.loads(record.to_json())
    modes = {row["mode"] for row in payload["assurance_legend"]}
    assert provenance.VERIFIED_VENDOR in modes
    # Scoped to what the bundle actually recorded, not the whole vocabulary.
    assert provenance.VERIFIED_METADATA not in modes


def test_both_provenance_writers_emit_the_plain_text_legend(tmp_path):
    """Both public entry points must emit the real legend, even when delegated."""
    import core
    import apt_core
    legends = []
    for name, backend in (("rpm", core), ("deb", apt_core)):
        directory = tmp_path / name
        directory.mkdir()
        from provenance import PackageProvenance, VERIFIED_DIGEST
        entries = [PackageProvenance(package_id="fixture", filename="fixture.pkg",
                   sha256="a" * 64, size=1, source_url="https://example.test/repo/fixture.pkg",
                   repository="fixture", assurance=VERIFIED_DIGEST, digest_checked=True)]
        backend._write_provenance(tmp_path, directory, entries, [], core.BuildOptions(),
                                  core.Reporter(), {})
        legend = (directory / "ASSURANCE.txt").read_text(encoding="utf-8")
        assert len(legend) > 100
        legends.append(legend)
    assert legends[0] == legends[1]
