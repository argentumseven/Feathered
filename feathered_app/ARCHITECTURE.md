# Feathered application architecture

`app.py` is the Tk composition root. Application behavior is divided between UI/application mixins and a Tk-independent build core.

## Desktop application modules

- `ui/theme.py` - themed dialogs, visual primitives, and activity indicators.
- `ui/layout.py` - root layout, navigation, scrolling, validation focus, and shared widget helpers.
- `ui/panes.py` - wizard pane construction.
- `application/tools.py` - repository-maintenance tools and transfer UI coordination.
- `application/selection.py` - package selection and review-state coordination.
- `review_state.py` - Tk-independent ownership of review results, selections,
  unresolved-requirement waivers, pagination, and transfer-row status. The
  desktop shell exposes its historical attribute names through compatibility
  descriptors; analysis reconciliation and bulk selection run on the state
  object without widget dependencies.
- `persistence/user_state.py` - aliases, key/trust references, vendor signature profiles, and entitlement persistence.
- `application/provenance.py` - evidence, digest, signature, provenance, and keyring policy.
- `application/output.py` - output naming and publication-path interaction.
- `application/sources.py` - target, workload, package, and repository source planning.
- `application/media.py` - local/removable-media handling and source state.
- `application/build.py` - GUI-facing build orchestration and repository scoping.
- `application/discovery.py` - release discovery, probes, reports, and version scans.
- `application/repositories.py` - repository editing and trust configuration.
- `application/results.py` - result rendering, trust/conflict decisions, and output actions.
- `operation_state.py` - headless exclusive-operation lease and legacy field adapters.
- `operation_runtime.py` - one headless owner for the lease, tracked worker and
  cancellation event; all exclusive desktop workers use its start/completion
  boundary, while Tk updates remain on the main-thread event queue.
- `application/operations.py` - GUI operation controls, visual activity timer,
  worker-completion dispatch and the main-thread event queue.

## Build core

The headless build path is based on explicit request/state objects rather than Tk variables.

- `build_spec.py` - serializable, immutable build request.
- `build_request.py` - frozen request accessors used during execution.
- `build_intent.py` - target/package-family/acquisition-intent derivation.
- `build_backend.py` - package-family backend dispatch.
- `build_plan.py` - root/source-plan construction.
- `build_mirror.py` - mirror inventory and unified-mirror population.
- `build_output.py` - deterministic publication naming and output policy.
- `build_preparation.py` - request validation and preparation into executable state.
- `build_runner.py` - execution of a prepared build.
- `build_services.py` / `build_service_host.py` - logging, cancellation, trust/conflict decisions, and publication services.
- `build_publication.py` - publication confirmation and output capability handling.
- `headless_host.py` - Tk-free build host.
- `build_api.py` - public preparation/execution API used by the CLI.

`source_scope.py` owns target compatibility, repository participation, and final source-scope selection. `repository_universe.py`, `metadata_loading.py`, and the package-family core modules provide the repository data used by preparation and resolution.

`repository_selection.py` owns the independent source-selection policies used by
the desktop wizard. `WorkloadRepositoryService` enables or materializes required
workload-role sources and disables obsolete profile-managed sources without
overriding manually configured rows. `MirrorSelectionService` calculates
selectable mirror candidates and reconciles explicit source-identity selections
across refreshes. Both receive repository lists and callbacks as explicit inputs
and require neither Tk nor an `App` reference. The GUI adapters retain the
existing public methods, logging, widget updates, and derived-state invalidation.
`RepositoryUniverse` remains the sole storage for the separate transaction and
mirror repository lists; this extraction does not migrate every wizard attribute
out of the legacy `App` object.

## Wizard navigation boundary

`wizard_navigation.py` holds the deterministic stage map, Next/Back labels,
local target/repository/review prerequisites, logical validation-focus targets,
and alternate source-recovery policy. It accepts plain values, not Tk widgets,
`App`, or mutable repository objects. `ui/layout.py` retains widget updates,
domain-specific validator adapters, dialogs, scroll/focus,
and main-thread pane transitions. Public navigation methods are preserved as
adapters, including free rail navigation and a terminal Review page. Recovery
choices are only *offered* by the service: applying a choice remains an explicit
user action in the GUI.

`repository_status.py` now projects workload-role, distribution, exact-package
and mirror-source requirements from explicit source snapshots. It does not read
widgets or the ambient `App` object, distinguishes identical repository labels
by concrete source identity, and redacts repository credentials in displayed
locations. `repository_workflow.py` selects the Repositories pane mode and its
full-target cache identity without constructing widgets. The existing
`SourcesMixin` and `PaneMixin` methods collect inputs and render the returned
state, keeping the public desktop integration stable.

## Option advisories

`option_advisory.py` classifies dropdown values as stable, pre-release,
end-of-life or init-incompatible from explicit inputs (release identities known
to be development series, Kubernetes lifecycle rows, init conflicts). It owns
`preferred_default`, which selects the newest stable option for fresh targets.
It imports neither Tk nor `App`. `ui/option_marking.py` renders the result:
it recolours and tags rows of ttk's popdown listbox after Tk refills it, while
selection still maps by index to the unchanged `-values`, and it switches the
closed field to `Prerelease.TCombobox` / `Incompatible.TCombobox` without
replacing validation's `Attention.TCombobox`. Beta release identities are
learned by release discovery and persisted in the release cache (`prerelease`).

## Package-source coverage

`package_coverage.py` owns eligibility, package-family version comparisons,
repository priority ordering, optional gaps, workload-name substitution and
source-identity-safe mirror counts. The GUI acquires metadata, freezes its target
inputs before launching the worker and renders the service result. The existing
`PaneMixin` matching/selection methods remain compatibility adapters. Coverage
does not certify dependencies or artifact integrity. Tests exercise all three
package families and execute both root and mirror checks on a real background
thread with live-GUI-variable access prohibited.

## Wizard validation boundary

`provenance_validation.py` enforces the evidence navigation gate from explicit
checksum/inspection prerequisites and immutable snapshots of current evidence
selection plus keyed spot-test outcomes. It does not access Tk, App, the network,
or repository caches. The GUI retains responsibility for constructing those
snapshots, particularly the full preflight cache key: selection, checksum policy,
root set and evidence relationship must all match a prior successful test.
Semantic rebuild peers cannot fill acquisition checksum gaps under Enhanced.

`package_name_validation.py` checks free-form package roots against the loaded
package index, including virtual provides and near-name suggestions, without
controlling GUI prompts. This is an advisory check, not a substitute for final
resolver output; an empty or stale index cannot establish package availability.
Both existing wizard methods remain compatibility adapters to these services.

## Compatibility surface

The public `App` class remains a composition of responsibility-oriented mixins so existing callers and tests can continue to override application methods. `app.py` retains a narrow six-port legacy facade for older monkeypatching
callers; independently configured instances use `ApplicationDependencyPorts`.

New non-UI work should prefer the explicit build API and service interfaces rather than adding additional GUI state dependencies.

## Threading boundary

Tk state is captured on the main thread before build execution. The shared
`OperationRuntime` registers each exclusive operation's worker before starting
it, rejects overlap, and retains the previous worker until it actually exits
even if its completion event is consumed early. UI cancellation uses the
runtime's cooperative cancellation event. Unrelated best-effort background
queries remain under their existing non-exclusive `BackgroundJobs` scheduler.
Worker execution consumes frozen request/preparation state and communicates
through service/event interfaces. Mid-build trust, conflict, waiver, and publication decisions are policy calls rather than direct message-box dependencies.

## Package-manager boundary

Feathered computes and transports a conservative content set. It does not claim to replace the native package manager's final transaction semantics. Generated receiver workflows and native-conformance harnesses intentionally hand final transaction evaluation to APT, DNF/YUM, or pacman.

## Completion scope

The application/build split is implemented. GUI capture creates a portable
`BuildSpec`; preparation produces an owned plan; execution uses explicit services
and a package-family backend. CLI execution imports no Tk modules. The worker
path consumes captured state rather than reading live widgets.

The RPM implementation has been separated from `core.py` into domain models,
metadata loading, resolution, artifact verification, native repository writing,
publication, transport, and OpenPGP modules. `core.py` retains compatibility
exports and dependency injection hooks. APT and Arch retain their family-specific
metadata, resolver, and writer entry points, while sharing acquisition, digests,
bundle records, and publication support.

The remaining mixins, state views, and compatibility adapters are supported code.
`ApplicationStateView` groups existing App attributes; it does not create a second
state store. APT and Arch are not fully decomposed into one module per operation,
and not every background producer uses the same coordinator. Neither is required
by the current boundary. Further extraction should follow a demonstrated defect,
maintenance problem, or performance need.

Boundary coverage lives in `tests/test_architecture.py`,
`tests/test_core_decomposition.py`, `tests/test_headless_execution.py`,
`tests/test_prepared_adapter_parity.py`, `tests/test_build_worker_isolation.py`,
and the host-contract checker. Release acceptance is documented in
`../VALIDATION.md`.

RPM module planning is implemented in `module_runtime.py`, with metadata loading,
filtering, and emission in `module_policy.py`. Planning resolves unambiguous
runtime requirements before choosing RPMs. It does not invoke a native DNF
fallback on the builder. DNF remains the receiver transaction evaluator;
`native_dnf_modules.py` adds modular fixtures to the existing native CI gate.
