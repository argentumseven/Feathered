"""Portable build settings, repository policy and exact-package identities.

capture() records GUI choices; apply() restores controls and required vendor
policies. build_api resolves exact identities and prepares execution without Tk.
Local certificate/keyring paths are runtime inputs rather than portable fields.
Endpoint and evidence URLs are preserved and can contain credentials.
JSON round-trip fidelity does not promise byte-identical repository contents.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields, replace, is_dataclass
from typing import Any, Dict, Mapping, Optional, Tuple, Union, get_args, get_origin, get_type_hints

SPEC_VERSION = 3

#  Repository attributes worth carrying in a spec. Deliberately excludes
#  client_cert/client_key/ca_cert/keyring: those are references to local
#  credential material, and a saved build profile is a file an operator may
#  hand to someone else.
REPOSITORY_FIELDS: Tuple[str, ...] = (
    "name", "url", "role", "priority", "enabled", "optional", "note",
    "source_tier", "workload_profile_managed", "target_profile_key", "target_arch",
    "evidence_relationship_hints", "evidence_authority_hints",
    "repo_format", "flat_repo", "suite", "components", "target_release",
    "expected_release_version", "vendor_id", "allow_unverified_index",
    "evidence_urls", "evidence_policy", "digest_preference",
    "digest_requirement", "verification_strategy", "redirect_allow_origins",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _decode(value: Any, shape: Any, path: str) -> Any:
    origin, args = get_origin(shape), get_args(shape)
    if origin is Union and type(None) in args:
        if value is None:
            return None
        return _decode(value, next(arg for arg in args if arg is not type(None)), path)
    if shape in (str, bool, int):
        if type(value) is not shape:
            raise ValueError(f"{path}: expected {shape.__name__}")
        return value
    if origin is tuple:
        if not isinstance(value, (tuple, list)):
            raise ValueError(f"{path}: expected an array")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(item, args[0], f"{path}[{i}]") for i, item in enumerate(value))
        if len(value) != len(args):
            raise ValueError(f"{path}: expected {len(args)} entries")
        return tuple(_decode(item, kind, f"{path}[{i}]") for i, (item, kind) in enumerate(zip(value, args)))
    if isinstance(shape, type) and is_dataclass(shape):
        return _restore(shape, value, path)
    raise ValueError(f"{path}: unsupported field type")


def _restore(section_cls: Any, payload: Any, path: str = "spec") -> Any:
    """Validate recognized fields; preserve compatibility by ignoring unknown keys."""
    if not isinstance(payload, Mapping):
        raise ValueError(f"{path}: expected an object")
    hints = get_type_hints(section_cls)
    return section_cls(**{key: _decode(value, hints[key], f"{path}.{key}" if path != "spec" else key)
                          for key, value in payload.items() if key in hints})


@dataclass(frozen=True)
class RepositoryRecord:
    """A repository as it appears in a saved spec: data, never credentials."""

    name: str = ""
    url: str = ""
    role: str = ""
    priority: int = 0
    enabled: bool = True
    optional: bool = False
    note: str = ""
    source_tier: str = ""
    workload_profile_managed: bool = False
    target_profile_key: str = ""
    target_arch: str = ""
    evidence_relationship_hints: Tuple[Tuple[str, str], ...] = ()
    evidence_authority_hints: Tuple[Tuple[str, str], ...] = ()
    repo_format: str = ""
    flat_repo: bool = False
    suite: str = ""
    components: str = ""
    target_release: str = ""
    expected_release_version: str = ""
    vendor_id: str = ""
    allow_unverified_index: bool = False
    evidence_urls: Tuple[str, ...] = ()
    evidence_policy: str = ""
    digest_preference: str = ""
    digest_requirement: str = ""
    verification_strategy: str = ""
    redirect_allow_origins: Tuple[str, ...] = ()

    @classmethod
    def capture(cls, repo) -> "RepositoryRecord":
        values: Dict[str, Any] = {}
        for name in REPOSITORY_FIELDS:
            value = getattr(repo, name, None)
            if name in ("evidence_relationship_hints", "evidence_authority_hints"):
                values[name] = tuple(sorted((str(k), str(v)) for k, v in (value or {}).items()))
            elif name in ("evidence_urls", "redirect_allow_origins"):
                values[name] = tuple(str(item) for item in (value or ()))
            elif name == "priority":
                values[name] = int(value or 0)
            elif name in ("flat_repo", "enabled", "optional", "allow_unverified_index", "workload_profile_managed"):
                values[name] = bool(value)
            else:
                values[name] = _text(value)
        return cls(**values)


@dataclass(frozen=True)
class TargetSpec:
    distribution: str = ""
    release: str = ""
    arch: str = ""
    init_system: str = ""
    inventory_path: str = ""
    baseline_path: str = ""
    platform_note: str = ""


@dataclass(frozen=True)
class ExactPackageRecord:
    """One exact-package root, as an identity rather than a resolved package.

    A saved spec must not carry checksums, sizes or repository handles: those
    describe the metadata as it stood when the spec was written, and a replay
    weeks later resolves against whatever the repository publishes then. What
    replays correctly is what the operator asked for -- this name, at this
    version, from this repository -- which is exactly the tuple
    ``_package_requests`` builds.
    """

    name: str = ""
    version: str = ""
    role: str = ""
    repository: str = ""
    arch: str = ""
    source_identity: str = ""

    @classmethod
    def capture(cls, package) -> "ExactPackageRecord":
        repo = getattr(package, "repo", None)
        return cls(
            name=_text(getattr(package, "name", "")),
            version=_text(getattr(package, "evr_text", "")),
            role=_text(getattr(repo, "role", "")),
            repository=_text(getattr(repo, "name", "")),
            arch=_text(getattr(package, "arch", "")),
            source_identity=_text(getattr(repo, "source_identity", "")))

    def as_request(self):
        """The tuple shape ``_package_requests`` produces for a chosen package."""
        return (self.name, self.version or None, self.role or None,
                self.repository or None, self.arch or None, None,
                self.source_identity or None)


@dataclass(frozen=True)
class ContentSpec:
    selection_mode: str = ""
    workload: str = ""
    custom_packages: str = ""
    package_version: str = ""
    dependency_mode: str = ""
    #  Exact-package roots. Absent before 1.2.12, which meant a saved spec could
    #  not reproduce an exact-package build at all -- the JSON round-tripped and
    #  the replay silently had nothing to build.
    exact_packages: Tuple[ExactPackageRecord, ...] = ()
    k8s_minor: str = ""
    apiserver_oldest_minor: str = ""
    apiserver_newest_minor: str = ""
    pin_to_inventory_baseline: bool = False
    advisories_acknowledged: bool = False
    image_baker_name: str = "feathered-node-additions"



@dataclass(frozen=True)
class SourceSpec:
    method: str = ""
    mirror_method: str = ""
    vendor_signature_policy: str = ""
    required_signature_vendors: Optional[Tuple[str, ...]] = None
    signing_key: str = ""
    repository_tool_path: str = ""
    repositories: Tuple[RepositoryRecord, ...] = ()


@dataclass(frozen=True)
class MirrorSpec:
    layout: str = "separate"
    disagreement_policy: str = "strict"
    selected_repositories: Tuple[str, ...] = ()


@dataclass(frozen=True)
class OutputSpec:
    directory: str = ""
    folder_scheme: str = ""
    folder_label: str = ""
    folder_stamp: str = ""
    emit_repository: bool = True
    sign_bundle_index: bool = False


@dataclass(frozen=True)
class ProvenanceSpec:
    strategy: str = ""
    digest_policy: str = ""


@dataclass(frozen=True)
class BuildSpec:
    """Portable settings; runtime services and preparation are supplied separately."""

    spec_version: int = SPEC_VERSION
    target: TargetSpec = field(default_factory=TargetSpec)
    content: ContentSpec = field(default_factory=ContentSpec)
    sources: SourceSpec = field(default_factory=SourceSpec)
    mirror: MirrorSpec = field(default_factory=MirrorSpec)
    output: OutputSpec = field(default_factory=OutputSpec)
    provenance: ProvenanceSpec = field(default_factory=ProvenanceSpec)

    # -- serialization -----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["spec_version"] = max(3, self.spec_version)
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True) + "\n"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BuildSpec":
        if not isinstance(data, Mapping):
            raise ValueError("spec: expected an object")
        version = data.get("spec_version", SPEC_VERSION)
        if type(version) is not int or version < 1:
            raise ValueError("spec_version: expected a supported positive integer")
        if version > SPEC_VERSION:
            raise ValueError(f"spec_version: Build spec version {version} was written by a newer Feathered "
                             f"than this one, which understands version {SPEC_VERSION}.")
        # Validate before migration so legacy transformations cannot coerce bad
        # trust controls or fail with an implementation exception.
        _restore(cls, data)
        if version < 3:
            target = data.get('target', {})
            for key in ('environment', 'kubernetes_purpose', 'kubernetes_version', 'api_server_versions',
                        'platform_release', 'kubernetes_release', 'os_image'):
                if key in target:
                    _decode(target[key], str, 'target.' + key)
            data = _migrate_previous_spec(data)
        return _restore(cls, data)

    @classmethod
    def from_json(cls, text: str) -> "BuildSpec":
        return cls.from_dict(json.loads(text))

    def replace_section(self, **sections) -> "BuildSpec":
        """Frozen means a change produces a new spec, never an edit in place."""
        return replace(self, **sections)


def _var(host, name: str, default: str = "") -> str:
    """Read one Tk variable without letting an absent control raise.

    Capture runs against partially built hosts in tests and, during migration,
    against a window whose later panes have not been constructed yet. A missing
    control must yield the documented default, not an exception.
    """
    variable = host.__dict__.get(name)
    if variable is None:
        return default
    try:
        value = variable.get()
    except Exception:
        return default
    return default if value is None else str(value)


def _flag(host, name: str, default: bool = False) -> bool:
    variable = host.__dict__.get(name)
    if variable is None:
        return default
    try:
        return bool(variable.get())
    except Exception:
        return default


def capture(host) -> BuildSpec:
    """Read the whole wizard state once, into an object that cannot change."""
    layout = getattr(host, "_mirror_layout", None)
    policy = getattr(host, "_merge_policy", None)
    return BuildSpec(
        target=TargetSpec(
            distribution=_var(host, "distro_var"),
            release=_var(host, "release_var"),
            arch=_var(host, "arch_var"),
            init_system=_var(host, "init_system_var"),
            inventory_path=_var(host, "inventory_var"),
            baseline_path=_var(host, "baseline_var"),
            platform_note=_var(host, "platform_note_var"),
        ),
        content=ContentSpec(
            selection_mode=_var(host, "selection_mode_var"),
            workload=_var(host, "workload_var"),
            custom_packages=_var(host, "custom_var"),
            package_version=_var(host, "package_version_var"),
            dependency_mode=_var(host, "mode_var"),
            k8s_minor=_var(host, "k8s_minor_var"),
            apiserver_oldest_minor=_var(host, "apiserver_oldest_minor_var"),
            apiserver_newest_minor=_var(host, "apiserver_newest_minor_var"),
            pin_to_inventory_baseline=_flag(host, "pin_to_inventory_baseline_var", False),
            advisories_acknowledged=_flag(host, "advisories_acknowledged_var", False),
            image_baker_name=_var(host, "image_baker_name_var"),

            exact_packages=tuple(
                ExactPackageRecord.capture(package)
                for package in (host.__dict__.get("selected_packages") or ())),
        ),
        sources=SourceSpec(
            method=_var(host, "source_method_var"),
            mirror_method=_var(host, "mirror_source_method_var"),
            vendor_signature_policy=_var(host, "vendor_signature_policy_var"),
            required_signature_vendors=tuple(sorted(
                str(vendor) for vendor, policy in host.__dict__.get("vendor_signature_profiles", {}).items()
                if policy.get("policy") == "require")),
            signing_key=_var(host, "signing_key_var"),
            repository_tool_path=_var(host, "repo_tool_path_var"),
            repositories=tuple(
                RepositoryRecord.capture(repo)
                for repo in (getattr(host, "repository_rows", lambda: ())() or ())),
        ),
        mirror=MirrorSpec(
            layout=getattr(layout() if callable(layout) else None, "value", "separate"),
            disagreement_policy=getattr(
                policy() if callable(policy) else None, "value", "strict"),
            selected_repositories=tuple(sorted(
                str(item) for item in (getattr(host, "mirror_repos", None) or ()))),
        ),
        output=OutputSpec(
            directory=_var(host, "out_var"),
            folder_scheme=_var(host, "folder_scheme_var"),
            folder_label=_var(host, "folder_label_var"),
            folder_stamp=_var(host, "folder_stamp_var"),
            emit_repository=_flag(host, "emit_repo_var", True),
            sign_bundle_index=_flag(host, "sign_index_var", False),
        ),
        provenance=ProvenanceSpec(
            strategy=_var(host, "prov_strategy_var"),
            digest_policy=_var(host, "prov_digest_var"),
        ),
    )


#  Spec field -> the Tk variable that holds it. One table drives both the
#  exhaustiveness test and apply(), so a control cannot be captured without
#  being restorable, or restored without being captured.
FIELD_TO_VARIABLE: Tuple[Tuple[str, str, str], ...] = (
    ("target", "distribution", "distro_var"),
    ("target", "release", "release_var"),
    ("target", "arch", "arch_var"),
    ("target", "init_system", "init_system_var"),
    ("target", "inventory_path", "inventory_var"),
    ("target", "baseline_path", "baseline_var"),
    ("target", "platform_note", "platform_note_var"),
    ("content", "k8s_minor", "k8s_minor_var"),
    ("content", "apiserver_oldest_minor", "apiserver_oldest_minor_var"),
    ("content", "apiserver_newest_minor", "apiserver_newest_minor_var"),
    ("content", "pin_to_inventory_baseline", "pin_to_inventory_baseline_var"),
    ("content", "advisories_acknowledged", "advisories_acknowledged_var"),
    ("content", "image_baker_name", "image_baker_name_var"),

    ("content", "selection_mode", "selection_mode_var"),
    ("content", "workload", "workload_var"),
    ("content", "custom_packages", "custom_var"),
    ("content", "package_version", "package_version_var"),
    ("content", "dependency_mode", "mode_var"),
    ("sources", "method", "source_method_var"),
    ("sources", "mirror_method", "mirror_source_method_var"),
    ("sources", "vendor_signature_policy", "vendor_signature_policy_var"),
    ("sources", "signing_key", "signing_key_var"),
    ("sources", "repository_tool_path", "repo_tool_path_var"),
    # Mirror settings were captured and never applied, so replaying a unified
    # mirror produced a separate-folder one.
    ("mirror", "layout", "mirror_layout_var"),
    ("mirror", "disagreement_policy", "mirror_conflict_policy_var"),
    ("output", "directory", "out_var"),
    ("output", "folder_scheme", "folder_scheme_var"),
    ("output", "folder_label", "folder_label_var"),
    ("output", "folder_stamp", "folder_stamp_var"),
    ("output", "emit_repository", "emit_repo_var"),
    ("output", "sign_bundle_index", "sign_index_var"),
    ("provenance", "strategy", "prov_strategy_var"),
    ("provenance", "digest_policy", "prov_digest_var"),
)


def _control_value(section: str, attribute: str, value):
    """Translate a stored value into what its control actually holds.

    Most fields round-trip as themselves. The two mirror settings are stored as
    domain values (``unified``, ``prefer-priority``) but their comboboxes hold
    operator-facing labels, so writing the raw value would select nothing.
    """
    if section != "mirror":
        return value
    from acquisition_model import MIRROR_LAYOUT_LABELS, MirrorLayout
    from mirror_unification import MERGE_POLICY_LABELS, MergePolicy

    if attribute == "layout":
        layout = MirrorLayout.UNIFIED if value == MirrorLayout.UNIFIED.value else MirrorLayout.SEPARATE
        return MIRROR_LAYOUT_LABELS[layout]
    if attribute == "disagreement_policy":
        policy = (MergePolicy.PREFER_PRIORITY
                  if value == MergePolicy.PREFER_PRIORITY.value else MergePolicy.STRICT)
        return MERGE_POLICY_LABELS[policy]
    return value


def apply(host, spec: BuildSpec, *, skip=()) -> Tuple[str, ...]:
    """Write a spec back onto a wizard. Returns the controls actually set.

    The inverse of ``capture``, and the reason a saved build profile or a
    command-line invocation can drive the same code path an operator does
    rather than a parallel one. Absent controls are skipped rather than
    created: a partially built window is a legitimate host.

    Values are set through the Tk variables so every existing trace callback
    fires, which is what keeps derived state -- release lists, repository
    seeding, capability -- consistent with the values written.
    """
    if spec.sources.required_signature_vendors is not None:
        policies = host.__dict__.setdefault("vendor_signature_profiles", {})
        for vendor in spec.sources.required_signature_vendors:
            policies.setdefault(vendor, {})["policy"] = "require"
    applied = []
    for section, attribute, variable in FIELD_TO_VARIABLE:
        if variable in skip:
            continue
        control = host.__dict__.get(variable)
        if control is None:
            continue
        value = getattr(getattr(spec, section, None), attribute, None)
        if value is None:
            continue
        try:
            control.set(_control_value(section, attribute, value))
        except Exception:
            continue
        applied.append(variable)
    return tuple(applied)


def package_requests_from(spec: BuildSpec):
    """The exact-package request tuples a replayed build should resolve."""
    return [record.as_request() for record in spec.content.exact_packages]


def repositories_from(spec: BuildSpec, repo_factory):
    """Rebuild RepoSpec objects from a spec's repository records.

    ``repo_factory`` is passed in rather than imported so this module stays
    free of the package backends. Credential material was deliberately never
    captured. build_api attaches them by source identity from PreparationInputs
    after reconstruction; they are never inferred from a GUI configuration.
    """
    built = []
    for row in spec.sources.repositories:
        repo = repo_factory(row.name, row.url, row.role or "dependency")
        for attribute in ("source_tier", "workload_profile_managed", "target_profile_key", "target_arch",
                          "evidence_relationship_hints", "evidence_authority_hints",
                          "priority", "enabled", "optional", "note", "repo_format",
                          "flat_repo", "suite", "components", "target_release", "vendor_id",
                          "expected_release_version", "allow_unverified_index",
                          "evidence_policy", "digest_preference", "digest_requirement",
                          "verification_strategy",
                          # Captured since 1.2.9 but previously not restored, so a
                          # replayed build silently lost its evidence sources and
                          # ran with an empty credential redirect allow-list.
                          "evidence_urls", "redirect_allow_origins"):
            value = getattr(row, attribute, None)
            if value in (None, "") or value == ():
                continue
            if attribute in ("evidence_relationship_hints", "evidence_authority_hints"):
                value = dict(value)
            elif attribute in ("evidence_urls", "redirect_allow_origins"):
                value = list(value)
            try:
                setattr(repo, attribute, value)
            except AttributeError:
                continue
        built.append(repo)
    return built


def captured_variable_names() -> Tuple[str, ...]:
    """Every Tk variable ``capture`` reads, for the exhaustiveness test.

    Kept as data rather than derived by inspection so that adding a field to a
    section without wiring it into ``capture`` is a visible omission.
    """
    return (
        "distro_var", "release_var", "arch_var", "init_system_var",
        "inventory_var", "baseline_var", "platform_note_var",
        "k8s_minor_var",
        "apiserver_oldest_minor_var",
        "apiserver_newest_minor_var",
        "pin_to_inventory_baseline_var",
        "advisories_acknowledged_var",
        "image_baker_name_var",

        "selection_mode_var", "workload_var", "custom_var",
        "package_version_var", "mode_var",
        "source_method_var", "mirror_source_method_var",
        "vendor_signature_policy_var", "signing_key_var", "repo_tool_path_var",
        "out_var", "folder_scheme_var", "folder_label_var", "folder_stamp_var",
        "emit_repo_var", "sign_index_var",
        "prov_strategy_var", "prov_digest_var",
    )


def section_field_count() -> int:
    """Total scalar fields across the spec, used to detect an unwired addition."""
    return sum(len(fields(section))
               for section in (TargetSpec, ContentSpec, SourceSpec, MirrorSpec,
                               OutputSpec, ProvenanceSpec))


def _migrate_previous_spec(data: Mapping[str, Any]) -> Dict[str, Any]:
    from kubernetes_workflow import LABELS
    from k8s_version import parse
    from copy import deepcopy
    out = deepcopy(dict(data))
    target = out.setdefault('target', {})
    content = out.setdefault('content', {})
    env = target.pop('environment', '')
    purpose = target.pop('kubernetes_purpose', '')
    version = target.pop('kubernetes_version', '')
    servers = target.pop('api_server_versions', '')
    notes = [target.get('platform_note', '')]
    for key, label in [('platform_release','VKS release'), ('kubernetes_release','VKr'), ('os_image','OS image')]:
        value = target.pop(key, '')
        if value:
            notes.append(f'{label}: {value}')
    if env not in ('', 'General Linux'):
        key = 'kubernetes-client' if purpose == 'Client tools' else 'vks-node-additions' if env == 'VMware VKS' else 'kubernetes-node'
        # Preserve exact-package intent and exact pins. Migration never substitutes
        # a preset's default roots for a saved exact package request.
        content['workload'] = LABELS[key]
        if version:
            content['k8s_minor'] = parse(version).line
            notes.append('Previous package constraint: ' + version + '; repository minor migration does not enforce its patch')
        minors = [parse(v).minor for v in servers.split(',') if v.strip()]
        if minors:
            content['apiserver_oldest_minor'] = str(min(minors))
            content['apiserver_newest_minor'] = str(max(minors))
        # These former controls cannot be inferred from a VKr label.
        content.setdefault('image_baker_name', 'feathered-node-additions')
        content['advisories_acknowledged'] = False
    target['platform_note'] = '; '.join(n for n in notes if n)
    out['spec_version'] = 3
    return out
