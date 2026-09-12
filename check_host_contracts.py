"""Fail if mypy accepts malformed build capabilities or rejects the real adapter.

Runs in static-analysis CI, where mypy is already installed. It does not add
analysis dependencies to the Windows signing environment or the runtime suite.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

POSITIVE = '''\
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
from feathered_app.build_host_contracts import BuildEvent, BuildFeedbackHost, PublicationOptions
from feathered_app.build_service_host import bind_build_services
from feathered_app.build_services import BuildServices
from feathered_app.build_publication import PublicationContext, confirm_publication

class Recorder:
    def log(self, message: str) -> None: pass
    def warn(self, message: str) -> None: pass
    def progress(self, label: str, value: float) -> None: pass

@dataclass
class Options:
    additive_publish: bool = False
    emit_repository: bool = True

services = BuildServices(reporter=Recorder(), events=Queue[BuildEvent]())
feedback: BuildFeedbackHost = bind_build_services(services)
feedback._on_item_event("package", "done", {"bytes": 42})
feedback.request_cancel()
options: PublicationOptions = Options()
context = PublicationContext(
    resolve_path=lambda name: Path(name), is_mirror=lambda: False,
    summarize=lambda path: str(path), suggest_sibling=lambda name: name + "-next",
    has_repository_metadata=lambda path: False, log=lambda message: None)
result: str | None = confirm_publication(context, "bundle", options,
                                        choose=services.publication_policy)

from acquisition_model import AcquisitionCapability
from feathered_app.source_scope import BuildScopeContext, ParticipationContext, select_build_scope, participates, TargetScope, RepositoryTarget, target_compatible

rows = ["base", "vendor"]
scope = BuildScopeContext[str](
    participating=lambda: rows, root_coverage=lambda: ["vendor"],
    capability=lambda: AcquisitionCapability.FULL_TRANSACTION,
    repositories=lambda: rows, mirror_selected=lambda row: row == "vendor",
    url=lambda row: "https://example.test/" + row, name=lambda row: row,
    init_conflict=lambda row: None, log=lambda message: None)
selected_rows: list[str] = select_build_scope(scope)
participation = ParticipationContext[str](
    enabled=lambda row: True, url=lambda row: row,
    compatible=lambda row: True, mirror_mode=lambda: False,
    mirror_selected=lambda row: False, tier=lambda row: "additional",
    profile_managed=lambda row: False, identity=lambda row: row,
    role=lambda row: "dependency", exact_mode=lambda: False,
    exact_source_ids=lambda: set(), required_roles=lambda: [])
selected: bool = participates("base", participation)
compatible: bool = target_compatible(TargetScope("rpm", "rocky", "9", "x86_64"), RepositoryTarget())

from feathered_app.metadata_loading import MetadataSource, MetadataReporter, MetadataCacheHost, MetadataLoadContext, load_metadata, lookup_metadata_cache, store_metadata_cache

@dataclass
class Source:
    name: str = "base"
    url: str = "https://example.test/base"
    enabled: bool = True
    optional: bool = False
    priority: int = 0
    source_identity: str = "base"

class LoadRecorder(Recorder):
    def check_cancel(self) -> None: pass

@dataclass
class Cache:
    loaded_signature: object = None
    loaded_packages: list[str] = field(default_factory=list)

source_contract: MetadataSource = Source()
reporter_contract: MetadataReporter = LoadRecorder()
cache: MetadataCacheHost[str] = Cache()
metadata = MetadataLoadContext[Source, str](
    build_scope=lambda: [Source()], signature=lambda: "sources", signature_tier=lambda row: "base",
    selected_arch=lambda: "x86_64", mirror_mode=lambda: False,
    load_repository=lambda row, arches, reporter: [row.name],
    validate_successful=lambda successful, attempted: None,
    active_source_method=lambda: "Custom repositories", source_tier=lambda row: "base",
    lookup_cache=lambda signature: lookup_metadata_cache(cache, signature),
    store_cache=lambda signature, packages: store_metadata_cache(cache, signature, packages),
    cancelled_error=RuntimeError)
packages: list[str] = load_metadata(metadata, reporter_contract)

import io
import core
import apt_core
import arch_core
from repository_transport import fetch_bytes
from transaction_model import RootRequest
from root_requests import RootInput, RootTuple, normalize_requests

valid_root_inputs: list[RootInput] = [RootRequest("typed"), ("legacy", None, "vendor"), ["json-list", None, None]]
normalized_roots: list[RootRequest] = normalize_requests(valid_root_inputs)
root_tuple: RootTuple = normalized_roots[0].as_tuple()
root_name: str = root_tuple[0]
root_slice: tuple[str | None, ...] = normalized_roots[0][1:]

from feathered_app.build_backend import BackendHost

class FamilyHost:
    def _is_arch(self) -> bool: return False
    def _is_deb(self) -> bool: return True
    def _known_workload_repository_roles(self) -> list[str]: return ["vendor"]

family_host: BackendHost = FamilyHost()

def backend_contracts(rpm: list[core.Package], deb: list[apt_core.DebPackage], arch: list[arch_core.ArchPackage]) -> None:
    reporter = core.Reporter()
    rpm_result: core.ResolutionResult = core.resolve([RootRequest("root")], rpm, "x86_64", core.BuildOptions(target_inventory=core.TargetInventory()), reporter)
    deb_result: apt_core.DebResolutionResult = apt_core.resolve([], deb, "amd64", core.BuildOptions(target_inventory=apt_core.AptTargetInventory()), reporter)
    arch_result: arch_core.ArchResolutionResult = arch_core.resolve([], arch, "x86_64", core.BuildOptions(target_inventory=arch_core.ArchTargetInventory()), reporter)
    if arch:
        shared_package: core.DownloadPackage = arch[0]
    payload: bytes = fetch_bytes("https://example.test/metadata", reporter,
        repo=core.RepoSpec("base", "https://example.test/"),
        open_url_fn=lambda url, timeout, source: io.BytesIO(b"metadata"),
        redact_url_fn=lambda url: url)

from transaction_resolution import TransactionContext, resolve_fixed_point
from transaction_inventory import (retained_rpm_inventory, retained_deb_inventory, retained_arch_inventory,
    rpm_retained_failures, deb_retained_failures, arch_retained_failures, arch_upgrade_requests)

def inventory_contracts(rpm: list[core.Package], deb: list[apt_core.DebPackage], arch: list[arch_core.ArchPackage]) -> None:
    rpm_inv: core.TargetInventory | None = retained_rpm_inventory(core.TargetInventory(), rpm)
    deb_inv: apt_core.AptTargetInventory | None = retained_deb_inventory(apt_core.AptTargetInventory(), deb)
    arch_inv: arch_core.ArchTargetInventory | None = retained_arch_inventory(arch_core.ArchTargetInventory(), arch)
    rpm_problems: list[tuple[core.Package, core.Requirement, str]] = rpm_retained_failures(rpm, rpm_inv)
    deb_problems: list[tuple[apt_core.DebPackage, apt_core.DebRequirement, str]] = deb_retained_failures(deb, deb_inv)
    arch_problems: list[tuple[arch_core.ArchPackage, arch_core.ArchRelation, str]] = arch_retained_failures(arch, arch_inv)
    roots: tuple[list[RootRequest], bool] = arch_upgrade_requests([RootRequest("root", scope=None)], arch, "x86_64", core.BuildOptions(target_inventory=arch_inv))
    core.TargetInventory(retained_packages=rpm, relationships_complete=True)
    apt_core.AptTargetInventory(retained_packages=deb, relationships_complete=True)
    arch_core.ArchTargetInventory(retained_packages=arch, relationships_complete=True)


def record_problem(result: core.ResolutionResult, requirement: core.Requirement, label: str, reason: str) -> None:
    result.unresolved.append(requirement)
    result.unresolved_notes[label] = reason

transaction_context = TransactionContext[core.Package, core.Requirement, core.BuildOptions[core.TargetInventory], core.ResolutionResult](
    resolve_once=lambda roots, rows, options: core.resolve(roots, rows, "x86_64", options, core.Reporter()),
    prepare_options=lambda prior: core.BuildOptions(), selected=lambda result: result.selected,
    retained_failures=lambda result: rpm_retained_failures(result.selected, core.TargetInventory()), record_unresolved=record_problem,
    finalize=lambda result, roots: None, check_cancel=lambda: None,
    max_resolution_passes=lambda: 8, include_dependencies=lambda: True)
transaction_result: core.ResolutionResult = resolve_fixed_point(transaction_context, [RootRequest("root")], [])

'''

NEGATIVE = '''\
from feathered_app.build_host_contracts import EventSink, CancellationSignal, PublicationPolicy, PublicationOptions, BuildFeedbackHost

class WrongSink:
    def put(self, event: int) -> None: pass

class WrongCancellation:
    def is_set(self) -> str: return "yes"
    def set(self) -> None: pass

class WrongOptions:
    additive_publish: str = "yes"
    emit_repository: bool = True

bad_sink: EventSink = WrongSink()  # reject
bad_cancellation: CancellationSignal = WrongCancellation()  # reject
bad_policy: PublicationPolicy = lambda title, message: "cancel"  # reject
bad_options: PublicationOptions = WrongOptions()  # reject
bad_host: BuildFeedbackHost = object()  # reject

from feathered_app.source_scope import BuildScopeContext, ParticipationContext, select_build_scope, TargetScope
bad_target: TargetScope = object()  # reject
bad_participation: ParticipationContext[str] = object()  # reject

def wrong_repository_type(context: BuildScopeContext[str]) -> list[int]:
    return select_build_scope(context)  # reject

from feathered_app.metadata_loading import MetadataSource, MetadataReporter, MetadataCacheHost, MetadataLoadContext, load_metadata, store_metadata_cache
bad_source: MetadataSource = object()  # reject
bad_reporter: MetadataReporter = object()  # reject
bad_cache: MetadataCacheHost[str] = object()  # reject

def wrong_package_type(context: MetadataLoadContext[MetadataSource, str], reporter: MetadataReporter) -> list[int]:
    return load_metadata(context, reporter)  # reject

def wrong_cache_write(cache: MetadataCacheHost[str]) -> None:
    store_metadata_cache(cache, "sources", [42])  # reject

import io
import core
import apt_core
import arch_core
from repository_transport import ByteResponse, TransportReporter
from feathered_app.build_backend import BackendHost

bad_response: ByteResponse = io.StringIO("text")  # reject
bad_transport_reporter: TransportReporter = object()  # reject
bad_download: core.DownloadPackage = object()  # reject
bad_family_host: BackendHost = object()  # reject

def wrong_inventory_and_package_families(deb: list[apt_core.DebPackage], reporter: core.Reporter) -> None:
    core.resolve([], [], "x86_64", core.BuildOptions(target_inventory=apt_core.AptTargetInventory()), reporter)  # reject
    arch_core.resolve([], [], "x86_64", core.BuildOptions(target_inventory=core.TargetInventory()), reporter)  # reject
    core.resolve([], deb, "x86_64", core.BuildOptions(), reporter)  # reject

from typing import Sequence
from transaction_resolution import TransactionContext, TransactionPackage, resolve_fixed_point

bad_transaction_package: TransactionPackage = object()  # reject
bad_transaction_context: TransactionContext[core.Package, core.Requirement, core.BuildOptions[core.TargetInventory], core.ResolutionResult] = object()  # reject

def wrong_transaction_result(context: TransactionContext[core.Package, core.Requirement, core.BuildOptions[core.TargetInventory], core.ResolutionResult]) -> apt_core.DebResolutionResult:
    return resolve_fixed_point(context, [], [])  # reject

def wrong_transaction_options(context: TransactionContext[core.Package, core.Requirement, core.BuildOptions[core.TargetInventory], core.ResolutionResult]) -> core.BuildOptions[apt_core.AptTargetInventory]:
    return context.prepare_options([])  # reject

def wrong_transaction_requirements(context: TransactionContext[core.Package, core.Requirement, core.BuildOptions[core.TargetInventory], core.ResolutionResult], result: core.ResolutionResult) -> Sequence[tuple[core.Package, str, str]]:
    return context.retained_failures(result)  # reject

from transaction_inventory import (retained_rpm_inventory, retained_deb_inventory, retained_arch_inventory,
    rpm_retained_failures, deb_retained_failures, arch_upgrade_requests)

def mixed_inventory_contracts(rpm: list[core.Package], deb: list[apt_core.DebPackage], arch: list[arch_core.ArchPackage]) -> list[tuple[core.Package, core.Requirement, str]]:
    retained_rpm_inventory(apt_core.AptTargetInventory(), rpm)  # reject
    retained_deb_inventory(arch_core.ArchTargetInventory(), deb)  # reject
    retained_arch_inventory(arch_core.ArchTargetInventory(), rpm)  # reject
    rpm_retained_failures(deb, core.TargetInventory())  # reject
    arch_upgrade_requests([], arch, "x86_64", core.BuildOptions(target_inventory=apt_core.AptTargetInventory()))  # reject
    core.TargetInventory(retained_packages=deb)  # reject
    arch[0].managed = "unknown"  # reject
    return deb_retained_failures(deb, apt_core.AptTargetInventory())  # reject

from root_requests import RootRequest, normalize_requests

def malformed_root_inputs() -> list[str]:
    RootRequest("root", version=42)  # reject
    normalize_requests(["abc"])  # reject
    normalize_requests([("root", None)])  # reject
    normalize_requests([("root", 42, None)])  # reject
    core.resolve([("root", None)], [], "x86_64", core.BuildOptions(), core.Reporter())  # reject
    return normalize_requests([("root", None, None)])  # reject

'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="feathered-host-contracts-") as directory:
        for name, source in (("valid_host", POSITIVE), ("invalid_host", NEGATIVE)):
            path = Path(directory) / f"{name}.py"
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-m", "mypy", "--config-file", str(ROOT / "mypy.ini"),
                 "--no-error-summary", "--show-error-codes", str(path)],
                cwd=ROOT, capture_output=True, text=True,
            )
            output = result.stdout + result.stderr
            expected = {line for line, text in enumerate(source.splitlines(), 1)
                        if text.endswith("# reject")}
            actual: list[int] = []
            unexpected: list[str] = []
            for line in output.splitlines():
                if ": error:" not in line:
                    continue
                match = re.match(re.escape(str(path)) + r":(\d+): error:", line)
                if match:
                    actual.append(int(match.group(1)))
                else:
                    unexpected.append(line)
            wanted_status = 1 if expected else 0
            if (result.returncode != wanted_status or set(actual) != expected
                    or len(actual) != len(expected) or unexpected):
                print(f"Host contract gate FAILED for {name}:\n{output}")
                return 1
            print(f"{name}: {'rejected all ' + str(len(expected)) + ' malformed capabilities' if expected else 'checked service, source, metadata, transport, backend and transaction interfaces accepted'}")
    print("Host contract gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
