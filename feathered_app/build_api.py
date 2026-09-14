"""Prepare and execute portable build settings without importing the GUI.

Repository endpoints come from the spec. Local credentials, vendor trust
profiles and an optional workload catalogue are explicit runtime inputs.
No source is discovered or enabled implicitly during replay.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field, replace, asdict
from typing import Mapping

from build_spec import BuildSpec, repositories_from
from core import Cancelled, RepoSpec, Reporter, infer_vendor_id, redact_text
from feathered_app.build_outcome import BuildOutcome, BuildStatus
from feathered_app.build_preparation import DecisionDeclined, PreparationRejected, prepare_job
from feathered_app.build_runner import BuildPlan, run
from feathered_app.prepared_plan import PreparedPlan
from feathered_app.build_services import BuildServices
from feathered_app.headless_host import HeadlessHost
from feathered_app.spec_replay import resolve_exact_packages
from profiles import PROFILES


CREDENTIAL_FIELDS = frozenset({'client_cert', 'client_key', 'ca_cert', 'keyring'})


@dataclass(frozen=True)
class PreparationInputs:
    repository_credentials: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    vendor_signature_profiles: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    workloads: Mapping | None = None
    resolution_pass_budget: int = 0

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) - {
                'repository_credentials', 'vendor_signature_profiles', 'resolution_pass_budget'}:
            raise PreparationRejected('Invalid runtime configuration fields.')
        credentials = data.get('repository_credentials', {})
        vendors = data.get('vendor_signature_profiles', {})
        if not isinstance(credentials, dict) or not isinstance(vendors, dict):
            raise PreparationRejected('Runtime credential and vendor sections must be objects.')
        for identity, row in credentials.items():
            if (not isinstance(identity, str) or not isinstance(row, dict)
                    or set(row) - CREDENTIAL_FIELDS or not all(isinstance(v, str) for v in row.values())):
                raise PreparationRejected('Invalid repository credential entry.')
        for vendor, row in vendors.items():
            if (not isinstance(vendor, str) or not isinstance(row, dict)
                    or set(row) - {'keyring', 'policy'}
                    or not all(isinstance(v, str) for v in row.values())
                    or row.get('policy', 'record') not in {'record', 'require'}):
                raise PreparationRejected('Invalid vendor signature profile.')
        budget = data.get('resolution_pass_budget', 0)
        if type(budget) is not int or budget < 0:
            raise PreparationRejected('Resolution pass budget must be a nonnegative integer.')
        return cls(copy.deepcopy(credentials), copy.deepcopy(vendors), resolution_pass_budget=budget)


@dataclass(frozen=True)
class PreparedBuild:
    host: HeadlessHost
    plan: PreparedPlan


def prepare_build(spec: BuildSpec, services: BuildServices,
                  inputs: PreparationInputs | None = None, *, do_download=True) -> PreparedBuild:
    """Resolve saved roots and return an owned, validated execution plan.

    A plan and its host belong to one invocation and must not be shared between
    concurrent executions. This operation may read metadata and inventory files.
    It never publishes a bundle. Invalid requests raise PreparationRejected;
    refusal and cancellation remain distinguishable from execution failure.
    """
    try:
        if not isinstance(spec, BuildSpec):
            raise ValueError('spec: expected BuildSpec')
        spec = BuildSpec.from_dict(asdict(spec))
    except (ValueError, TypeError) as exc:
        raise PreparationRejected(redact_text(str(exc))) from exc
    inputs = inputs if inputs is not None else PreparationInputs()
    if not isinstance(inputs, PreparationInputs):
        raise PreparationRejected('Invalid preparation inputs.')
    checked = PreparationInputs.from_dict({
        'repository_credentials': inputs.repository_credentials,
        'vendor_signature_profiles': inputs.vendor_signature_profiles,
        'resolution_pass_budget': inputs.resolution_pass_budget})
    if inputs.workloads is not None and not isinstance(inputs.workloads, Mapping):
        raise PreparationRejected('Workload catalogue must be a mapping.')
    inputs = replace(checked, workloads=inputs.workloads)
    if services.should_cancel():
        raise Cancelled('Operation cancelled')
    profiles = [p for p in PROFILES.values() if p.label == spec.target.distribution]
    if not profiles:
        raise PreparationRejected('Choose a recognized target distribution.')
    profile = profiles[0]
    if spec.target.arch not in profile.arches:
        raise PreparationRejected(f'Unsupported target architecture for {profile.label}: {spec.target.arch}')
    if not spec.target.release.strip() and profile.package_family != 'arch':
        raise PreparationRejected('Choose a target release.')
    if spec.target.init_system and spec.target.init_system not in profile.init_systems:
        raise PreparationRejected('The selected init system is not supported by this target.')
    if spec.content.selection_mode not in {'Workload preset', 'Choose packages', 'Entire repository (mirror)'}:
        raise PreparationRejected('Choose a supported acquisition mode.')
    if spec.mirror.layout not in {'separate', 'unified'} or spec.mirror.disagreement_policy not in {'strict', 'prefer-priority'}:
        raise PreparationRejected('Invalid mirror layout or disagreement policy.')
    repositories = repositories_from(spec, RepoSpec)
    unknown = set(inputs.repository_credentials) - {r.source_identity for r in repositories}
    if unknown:
        raise PreparationRejected('Runtime credentials refer to a source absent from this spec.')
    for repo in repositories:
        for key, value in inputs.repository_credentials.get(repo.source_identity, {}).items():
            if key not in CREDENTIAL_FIELDS:
                raise PreparationRejected('Unsupported repository credential field.')
            setattr(repo, key, value)
    host = HeadlessHost(spec, services, repositories, workloads=inputs.workloads)
    from kubernetes_workflow import KUBERNETES_KEYS, VKS_KEY, rolling_source
    workload = host._workload()
    if workload.key in KUBERNETES_KEYS | {VKS_KEY}:
        if not workload.supports_target(profile.key, spec.target.release):
            raise PreparationRejected('This workload is not offered for the selected Linux release.')
        context = host._selected_workload_context()
        try:
            context.validate()
        except ValueError as exc:
            raise PreparationRejected(str(exc)) from exc
        if workload.key in KUBERNETES_KEYS:
            from kubernetes_workflow import synchronize_repository
            def make_repository(template, _tier):
                return RepoSpec(template.name, template.url, role=template.role, priority=template.priority,
                    repo_format=template.repo_format, suite=template.suite, components=template.components, flat_repo=template.flat_repo)
            synchronize_repository(host.repo_rows, profile.package_family, context.minor, make_repository)
        if workload.key == VKS_KEY and context.pin_baseline and spec.target.inventory_path.strip():
            for repo in host.repo_rows:
                if rolling_source(repo):
                    repo.enabled = False
    host.vendor_signature_profiles = copy.deepcopy(dict(inputs.vendor_signature_profiles))
    # The visible signature dropdown describes only the selected vendor row.
    # New specs carry the full required-vendor set; never apply that row's
    # label globally to unrelated vendors.
    required = spec.sources.required_signature_vendors
    if required is None and spec.sources.vendor_signature_policy.startswith('Require'):
        if not inputs.vendor_signature_profiles:
            raise PreparationRejected(
                'Legacy spec lacks vendor-scoped signature policies. Recapture it or supply runtime vendor profiles.')
    for vendor in required or ():
        host.vendor_signature_profiles.setdefault(vendor, {})['policy'] = 'require'
    host.resolution_pass_budget = inputs.resolution_pass_budget
    if spec.content.selection_mode == 'Workload preset' and not any(
            w.label == spec.content.workload for w in host.workloads.values()):
        raise PreparationRejected('Choose a workload present in the supplied catalogue.')
    reporter = Reporter(host._log, host._progress, host.cancel_event)
    try:
        if spec.content.exact_packages:
            host.selected_packages = resolve_exact_packages(host, reporter)
        plan = prepare_job(host, do_download=do_download, confirm_package_only=services.package_only_policy)
        reporter.check_cancel()
    except Cancelled:
        raise
    except (ValueError, RuntimeError, OSError) as exc:
        raise PreparationRejected(redact_text(str(exc))) from exc
    return PreparedBuild(host, plan)


def execute_build(spec: BuildSpec, services: BuildServices,
                  inputs: PreparationInputs | None = None, *, timeout: float | None = None) -> BuildOutcome:
    """Prepare and execute, returning a terminal result independent of UI state.

    Timeout is cooperative: blocking I/O must reach a backend cancellation
    checkpoint. No background build is abandoned after this function returns.
    """
    deadline = time.monotonic() + max(0, timeout) if timeout is not None else None
    expired = lambda: deadline is not None and time.monotonic() >= deadline
    declined = {'value': False}

    def decision(title, message):
        accepted = services.decision_policy(title, message)
        declined['value'] |= not bool(accepted)
        return accepted

    def trust(rows):
        accepted = services.trust_policy(rows)
        declined['value'] |= not bool(accepted)
        return accepted

    wrapped = replace(services, should_cancel=lambda: expired() or services.should_cancel(),
                      decision_policy=decision, trust_policy=trust)
    try:
        prepared = prepare_build(spec, wrapped, inputs)
    except DecisionDeclined as exc:
        return BuildOutcome(BuildStatus.DECLINED, redact_text(str(exc)))
    except Cancelled as exc:
        return BuildOutcome(BuildStatus.TIMED_OUT if expired() else BuildStatus.CANCELLED, redact_text(str(exc)))
    except PreparationRejected as exc:
        return BuildOutcome(BuildStatus.INVALID, redact_text(str(exc)))
    except Exception as exc:
        return BuildOutcome(BuildStatus.FAILED, redact_text(str(exc)))
    outcome = run(prepared.host, prepared.plan)
    if outcome.status is BuildStatus.CANCELLED:
        if expired():
            return replace(outcome, status=BuildStatus.TIMED_OUT, message='Build exceeded its timeout and was cancelled.')
        if declined['value']:
            return replace(outcome, status=BuildStatus.DECLINED)
    return outcome
