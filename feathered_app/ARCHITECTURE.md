# Feathered application architecture

`app.py` is the Tk composition root. Application behavior is divided between UI/application mixins and a Tk-independent build core.

## Desktop application modules

- `ui/theme.py` - themed dialogs, visual primitives, and activity indicators.
- `ui/layout.py` - root layout, navigation, scrolling, validation focus, and shared widget helpers.
- `ui/panes.py` - wizard pane construction.
- `application/tools.py` - repository-maintenance tools and transfer UI coordination.
- `application/selection.py` - package selection and review-state coordination.
- `persistence/user_state.py` - aliases, key/trust references, vendor signature profiles, and entitlement persistence.
- `application/provenance.py` - evidence, digest, signature, provenance, and keyring policy.
- `application/output.py` - output naming and publication-path interaction.
- `application/sources.py` - target, workload, package, and repository source planning.
- `application/media.py` - local/removable-media handling and source state.
- `application/build.py` - GUI-facing build orchestration and repository scoping.
- `application/discovery.py` - release discovery, probes, reports, and version scans.
- `application/repositories.py` - repository editing and trust configuration.
- `application/results.py` - result rendering, trust/conflict decisions, and output actions.
- `application/operations.py` - worker ownership, cancellation, progress, and event dispatch.

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

## Compatibility surface

The public `App` class remains a composition of responsibility-oriented mixins so existing callers and tests can continue to override application methods. `app.py` also preserves dependency propagation for callers that monkeypatch exported dependencies through the public module.

New non-UI work should prefer the explicit build API and service interfaces rather than adding additional GUI state dependencies.

## Threading boundary

Tk state is captured on the main thread before build execution. Worker execution consumes frozen request/preparation state and communicates through service/event interfaces. Mid-build trust, conflict, waiver, and publication decisions are policy calls rather than direct message-box dependencies.

## Package-manager boundary

Feathered computes and transports a conservative content set. It does not claim to replace the native package manager's final transaction semantics. Generated receiver workflows and native-conformance harnesses intentionally hand final transaction evaluation to APT, DNF/YUM, or pacman.
