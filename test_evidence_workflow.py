"""Behavioral regressions for explicit evidence tests and stable checksum policy."""
import queue
import threading
from types import SimpleNamespace

import pytest
import app
from core import RepoSpec
from evidence_model import REL_EXACT_MIRROR, REL_REBUILD_PEER


class Var:
    def __init__(self, value=""): self.value = value
    def get(self): return self.value
    def set(self, value): self.value = value


class Widget:
    def __init__(self): self.values = []; self.state = None
    def winfo_exists(self): return True
    def configure(self, **kwargs): self.__dict__.update(kwargs)
    def delete(self, *_): pass
    def get_children(self): return []


def make_ui(rows, strategy="evidence-fallback", coverage=None):
    ui = object.__new__(app.App)
    ui.repo_rows = rows
    ui.loaded_packages = []
    ui._enabled_provenance_repos = lambda: rows
    ui._repository_build_purposes = lambda repo: []
    ui._selected_root_names_for_evidence = lambda: set()
    ui._provenance_detected_cache = {}
    ui._provenance_digest_coverage_cache = {}
    ui._evidence_preflight_cache = {}
    for repo in rows:
        repo.verification_strategy = strategy
        if coverage is not None:
            set_coverage(ui, repo, coverage)
    for name in ("prov_enabled_sources_var", "prov_detected_var", "prov_digest_var",
                 "prov_digest_help_var", "prov_strategy_var", "prov_strategy_help_var",
                 "prov_evidence_state_var", "status_var"):
        setattr(ui, name, Var())
    ui.prov_strategy_var.set(ui._strategy_policy_to_ui(strategy))
    ui.prov_digest_var.set("Automatic")
    for name in ("prov_source_tree", "prov_digest_combo", "prov_strategy_combo", "prov_evidence_test_btn"):
        setattr(ui, name, Widget())
    ui._refresh_provenance_source_tree = lambda: None
    ui._refresh_provenance_evidence_rows = lambda: None
    ui.worker = None
    ui.active_operation = None
    return ui


def set_coverage(ui, repo, algorithms):
    key = ui._provenance_repo_cache_key(repo)
    ui._provenance_detected_cache[key] = list(algorithms)
    ui._provenance_digest_coverage_cache[key] = {
        "total": 1, **{p: int(ui._minimum_met_by_algorithms(algorithms, p))
                       for p in ("auto", "sha256", "sha384", "sha512")}}


def source(pref="auto"):
    return RepoSpec("Source", "https://source.example/repo/", enabled=True,
                    digest_preference=pref, evidence_urls=["https://mirror.example/repo/"])


@pytest.mark.parametrize("strategy", ["evidence-fallback", "full-corroboration", "checksum-required"])
@pytest.mark.parametrize("pref", ["auto", "sha256", "sha384", "sha512"])
@pytest.mark.parametrize("coverage", [None, [], ["sha256"], ["sha512"]])
def test_refresh_preserves_policy_and_all_choices(strategy, pref, coverage):
    repo = source(pref)
    ui = make_ui([repo], strategy, coverage)
    ui._refresh_provenance_editor()
    assert [ui._digest_ui_to_policy(v) for v in ui.prov_digest_combo.values] == [
        "auto", "sha256", "sha384", "sha512"]
    assert ui._digest_ui_to_policy(ui.prov_digest_var.get()) == pref
    assert repo.digest_preference == pref
    assert ui.prov_digest_combo.state == "readonly"
    assert ui.prov_evidence_test_btn.state == (
        "disabled" if strategy == "checksum-required" else "normal")
    if coverage == ["sha256"]:
        assert "SHA-512 (0 of 1 direct)" in ui.prov_digest_combo.values
        if pref == "sha512" and strategy != "evidence-fallback":
            assert "requirement is currently unmet" in ui.prov_digest_help_var.get()


def test_refresh_and_mixed_policies_never_normalize_without_user_choice():
    first, second = source("sha512"), RepoSpec("Other", "https://other.example/", digest_preference="sha256")
    ui = make_ui([first, second], coverage=["sha256"])
    ui._refresh_provenance_editor()
    assert ui.prov_digest_var.get().startswith("Mixed")
    assert len(ui.prov_digest_combo.values) == 5
    assert "Each source keeps its own policy" in ui.prov_digest_help_var.get()
    second.digest_preference = "sha512"
    for algorithms in (["sha256"], ["sha512"], []):
        for repo in (first, second): set_coverage(ui, repo, algorithms)
        ui._refresh_provenance_editor()
        assert ui._digest_ui_to_policy(ui.prov_digest_var.get()) == "sha512"
        assert first.digest_preference == second.digest_preference == "sha512"


@pytest.mark.parametrize("strategy", ["evidence-fallback", "full-corroboration"])
@pytest.mark.parametrize("coverage", [None, [], ["sha256"]])
@pytest.mark.parametrize("relationship", [REL_EXACT_MIRROR, REL_REBUILD_PEER])
def test_explicit_test_runs_for_unknown_required_and_optional_sources(monkeypatch, strategy, coverage, relationship):
    repo = source()
    ui = make_ui([repo], strategy, coverage)
    calls = []
    monkeypatch.setattr(app, "evidence_relationship", lambda *_: relationship)
    result_status = "peer" if relationship == REL_REBUILD_PEER else "repository"
    ui._busy = lambda: False
    ui._claim_operation = lambda *args, **kwargs: True
    ui._focus_validation = lambda *args: pytest.fail(str(args))
    ui.cancel_event = threading.Event()
    ui.events = queue.Queue()
    ui._log = lambda *args: None
    ui._progress = lambda *args: None
    def probe(repo, url, reporter):
        calls.append((repo, url))
        return {"status": result_status, "relationship": relationship}
    ui._preflight_evidence_pair_with_curated_failover = probe
    class InlineThread:
        def __init__(self, target, **kwargs): self.target = target
        def start(self): self.target()
    monkeypatch.setattr(app.threading, "Thread", InlineThread)
    ui._test_evidence_sources()
    assert calls == [(repo, repo.evidence_urls[0])]
    kind, results = ui.events.get_nowait()
    assert kind == "evidence_preflight"
    assert results[0][1]["status"] == result_status
    assert ui.events.get_nowait()[0:2] == ("done", True)


def test_optional_failure_does_not_block_but_becomes_required_when_minimum_changes():
    repo = source()
    ui = make_ui([repo], coverage=["sha256"])
    url = repo.evidence_urls[0]
    ui._evidence_preflight_cache[ui._evidence_preflight_key(repo, url)] = {"status": "unusable", "detail": "Offline"}
    ui._validate_provenance_step()  # Complete direct coverage; optional diagnostic failure.
    repo.digest_preference = "sha512"
    ui.prov_digest_var.set("SHA-512")
    with pytest.raises(RuntimeError): ui._validate_provenance_step()
    ui._evidence_preflight_cache[ui._evidence_preflight_key(repo, url)] = {"status": "repository", "relationship": REL_EXACT_MIRROR}
    ui._validate_provenance_step()
    repo.digest_preference = "sha384"  # A pass with a different policy cannot waive a new test.
    with pytest.raises(RuntimeError): ui._validate_provenance_step()


def test_peer_pass_cannot_fill_an_enhanced_gap(monkeypatch):
    repo = source()
    ui = make_ui([repo], coverage=[])
    monkeypatch.setattr(app, "evidence_relationship", lambda *_: REL_REBUILD_PEER)
    assert ui._evidence_preflight_pairs() == [(repo, repo.evidence_urls[0])]
    ui._evidence_preflight_cache[ui._evidence_preflight_key(repo, repo.evidence_urls[0])] = {
        "status": "peer", "relationship": REL_REBUILD_PEER}
    with pytest.raises(RuntimeError, match="Semantic rebuild peers"):
        ui._validate_provenance_step()


@pytest.mark.parametrize("required,pending,suffix", [(True, False, "required"), (False, False, "optional"), (False, True, "requirement unknown")])
@pytest.mark.parametrize("status,outcome", [("repository", "Byte match passed"), ("unusable", "Test failed"), ("testing", "Testing")])
def test_test_outcomes_stay_visible_independently_of_requirement(required, pending, suffix, status, outcome):
    label, testing = app.App._evidence_row_status("evidence-fallback", required, pending, REL_EXACT_MIRROR, {"status": status})
    assert label == f"{outcome} · {suffix}"
    assert testing == (status == "testing")


def test_peer_outcome_explains_fallback_ineligibility():
    label, _ = app.App._evidence_row_status("evidence-fallback", False, True, REL_REBUILD_PEER, {"status": "peer"})
    assert label == "Peer test passed · cannot fill gaps"


def test_loaded_mixed_package_coverage_does_not_hide_a_gap():
    repo = source("sha512")
    ui = make_ui([repo])
    ui.loaded_packages = [
        SimpleNamespace(repo=repo, digests={"sha512": "ab" * 64}, checksum_type="", checksum=""),
        SimpleNamespace(repo=repo, digests={"sha256": "cd" * 32}, checksum_type="", checksum="")]
    assert ui._digest_inspection_known(repo)
    assert not ui._repo_meets_digest_minimum(repo, "sha512")
    assert ui._repo_meets_digest_minimum(repo, "sha256")
    assert ui._evidence_required_repos("evidence-fallback") == [repo]

@pytest.mark.parametrize("strategy", ["evidence-fallback", "checksum-required", "full-corroboration"])
def test_explicit_policy_change_never_lowers_minimum(strategy):
    repo = source("auto")
    ui = make_ui([repo], coverage=["sha256"])
    invalidations = []
    ui._invalidate_provenance_analysis = lambda: invalidations.append(True)
    ui._log = lambda *_: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui.prov_digest_var.set("SHA-512 (0 of 1 direct)")
    ui.prov_strategy_var.set(ui._strategy_policy_to_ui(strategy))
    ui._provenance_policy_changed()
    assert repo.digest_preference == "sha512"
    assert repo.verification_strategy == strategy
    assert ui._digest_ui_to_policy(ui.prov_digest_var.get()) == "sha512"
    assert invalidations


def test_changing_one_mixed_axis_preserves_the_other():
    first, second = source("sha512"), RepoSpec("Other", "https://other.example/", digest_preference="sha256")
    ui = make_ui([first, second], coverage=["sha256"])
    ui._invalidate_provenance_analysis = lambda: None
    ui._log = lambda *_: None
    ui._refresh_repo_tree_if_open = lambda: None
    ui._refresh_provenance_editor()
    ui.prov_strategy_var.set(ui._strategy_policy_to_ui("skip-provenance"))
    ui._provenance_policy_changed()
    assert [r.digest_preference for r in (first, second)] == ["sha512", "sha256"]
    assert ui.prov_digest_combo.state == "disabled"
    ui.prov_strategy_var.set(ui._strategy_policy_to_ui("full-corroboration"))
    ui._provenance_policy_changed()
    assert [r.digest_preference for r in (first, second)] == ["sha512", "sha256"]
    first.verification_strategy = "evidence-fallback"
    ui._refresh_provenance_editor()
    ui.prov_digest_var.set("SHA-384 or stronger")
    ui._provenance_policy_changed()
    assert [r.verification_strategy for r in (first, second)] == ["evidence-fallback", "full-corroboration"]
    assert first.digest_preference == second.digest_preference == "sha384"

@pytest.mark.parametrize("matching", [True, False])
def test_sha512_fallback_checks_distinct_artifact_bytes(tmp_path, monkeypatch, matching):
    import hashlib
    import core
    from test_feather import rpm_pkg
    repo = source("sha512")
    repo.verification_strategy = "evidence-fallback"
    body = b"acquisition artifact bytes\n"
    package = rpm_pkg("demo", "1.0", repo=repo)
    package.digests = {"sha256": hashlib.sha256(body).hexdigest()}
    package.checksum_type, package.checksum = "sha256", package.digests["sha256"]
    primary = tmp_path / "primary.rpm"
    primary.write_bytes(body)
    evidence = tmp_path / core.Path(package.location).name
    evidence.write_bytes(body if matching else b"different artifact bytes\n")
    repo.evidence_urls = [evidence.as_uri()]
    monkeypatch.setattr(core, "mirrors_are_distinct", lambda *_: (True, "distinct local test files"))
    if not matching:
        with pytest.raises(RuntimeError, match="(?i)(mismatch|disagree|different)"):
            core.verify_package_artifact(package, primary, core.BuildOptions(), core.Reporter())
        return
    assert core.verify_package_artifact(package, primary, core.BuildOptions(), core.Reporter())
    record = package.verification
    assert not record.package_digest_checked
    assert record.evidence_artifact_checked
    assert record.evidence_artifact_digest_type == "sha512"
    assert record.evidence_artifact_digest == hashlib.sha512(body).hexdigest()
