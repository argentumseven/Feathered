"""Run a Feathered build from saved settings without a display or Tk.

The GUI and CLI use shared preparation rules and the same execution runner.
Repository rows must be explicit in the spec. Credentials and vendor keyrings
can be supplied separately with --runtime-config; no GUI configuration is read.

Usage: python feathered_cli.py build --spec build.json
       python feathered_cli.py show --spec build.json

Exit codes: 0 published, 1 execution failed, 2 decision declined,
4 cooperative timeout, 5 invalid request or cancellation. Code 3 (no display)
is retained as a historical reserved value and is no longer produced.

--dry-run describes saved settings; it does not resolve a publication plan.
Timeout is cooperative and can wait for blocking backend I/O to return.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_spec
from build_spec import BuildSpec
from core import redact_text, redact_url

# Cooperative deadline shared by preparation and execution.
DEFAULT_TIMEOUT_S = 4 * 60 * 60


def load_spec(path: Path) -> BuildSpec:
    try:
        return BuildSpec.from_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(redact_text(f"ERROR: no such build spec: {path}")) from None
    except json.JSONDecodeError as exc:
        raise ValueError(redact_text(f"ERROR: {path} is not valid JSON: {exc}")) from None
    except ValueError as exc:
        raise ValueError(redact_text(f"ERROR: {exc}")) from None


def describe(spec: BuildSpec) -> str:
    lines = [
        f"target      {spec.target.distribution} {spec.target.release} ({spec.target.arch})",
        f"content     {spec.content.selection_mode}"
        + (f" \u2192 {spec.content.workload}" if spec.content.workload else ""),
        f"sources     {spec.sources.method or 'not set'}",
        f"repositories {len(spec.sources.repositories)}",
    ]
    from core import RepoSpec
    repositories = build_spec.repositories_from(spec, RepoSpec)
    for row, repository in zip(spec.sources.repositories, repositories):
        state = "enabled" if row.enabled else "disabled"
        lines.append(f"  - {row.name} [{state}, priority {row.priority}] {redact_url(row.url)}")
        lines.append(f"    identity: {repository.source_identity}")
    if spec.content.exact_packages:
        lines.append(f"exact roots {len(spec.content.exact_packages)}")
        for row in spec.content.exact_packages:
            version = row.version or "latest"
            lines.append(f"  - {row.name} {version} [{row.repository or 'any repository'}]")
    lines.append(f"output      {spec.output.directory}")
    lines.append(f"            scheme={spec.output.folder_scheme} "
                 f"stamp={spec.output.folder_stamp} "
                 f"repo_metadata={spec.output.emit_repository} "
                 f"signed_index={spec.output.sign_bundle_index}")
    if spec.mirror.layout != "separate":
        lines.append(f"mirror      {spec.mirror.layout}, "
                     f"disagreements: {spec.mirror.disagreement_policy}")
    return redact_text("\n".join(lines))


def run_build(spec: BuildSpec, *, output: str = "", timeout: int = DEFAULT_TIMEOUT_S,
              quiet: bool = False, accept_trust: bool = False,
              accept_conflicts: bool = False, accept_package_only: bool = False,
              existing_output: str = "cancel", existing_metadata: str = "cancel",
              runtime_inputs=None) -> int:
    """Prepare and execute through the Tk-free API; return its terminal exit code."""
    from dataclasses import replace
    from core import Reporter, redact_text
    from feathered_app.build_api import execute_build
    from feathered_app.build_services import BuildServices

    if output:
        spec = replace(spec, output=replace(spec.output, directory=output))

    def trust_policy(rows):
        for row in rows:
            print(f"TRUST: {redact_text(str(row))}", file=sys.stderr)
        return accept_trust

    def decision_policy(title, message):
        print(f"DECISION: {redact_text(str(message))}", file=sys.stderr)
        return accept_conflicts

    def package_only_policy(title, message):
        print(f"PACKAGE-ONLY: {redact_text(str(message))}", file=sys.stderr)
        return accept_package_only

    def publication_policy(title, message, *, choices, **kwargs):
        print(f"OUTPUT: {redact_text(str(message))}", file=sys.stderr)
        allowed = {key for key, label in choices}
        choice = existing_metadata if 'regenerate' in allowed else existing_output
        return choice if choice in allowed else 'cancel'

    reporter = Reporter(log=lambda message: print(redact_text(str(message)), flush=True) if not quiet else None)
    services = BuildServices(reporter, trust_policy, decision_policy,
                             publication_policy=publication_policy, package_only_policy=package_only_policy)
    outcome = execute_build(spec, services, runtime_inputs, timeout=timeout)
    if outcome.exit_code == 0:
        if not outcome.output_path or not Path(outcome.output_path).is_dir():
            print('ERROR: execution reported success without a published directory.', file=sys.stderr)
            return 1
        print(f"\nBundle: {redact_text(outcome.output_path)}")
    else:
        print(f"ERROR: {redact_text(outcome.message)}", file=sys.stderr)
    return outcome.exit_code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="feathered", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="run a build from a saved spec")
    build.add_argument("--spec", type=Path, required=True)
    build.add_argument("--out", default="", help="override the spec's output directory")
    build.add_argument("--dry-run", action="store_true",
                       help="describe saved settings without resolving or fetching packages")
    build.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    build.add_argument("--quiet", action="store_true", help="suppress the activity log")
    build.add_argument("--accept-conflict-notices", action="store_true",
                       help="answer yes to mid-build conflict and waiver "
                            "questions; they are printed either way")
    build.add_argument("--accept-trust-findings", action="store_true",
                       help="proceed despite trust findings; they are printed and "
                            "recorded in the bundle's provenance either way")

    build.add_argument("--accept-package-only", action="store_true",
                       help="accept a root-artifact-only workload when base sources are unavailable")
    build.add_argument("--existing-output", choices=("cancel", "sibling", "add"), default="cancel",
                       help="explicit policy for a populated destination; mirrors permit sibling only")
    build.add_argument("--existing-metadata", choices=("cancel", "regenerate", "keep"), default="cancel",
                       help="explicit repository metadata policy for additive publication")
    build.add_argument("--runtime-config", type=Path,
                       help="local JSON with source credential paths and vendor signature profiles")

    show = sub.add_parser("show", help="print a saved spec")
    show.add_argument("--spec", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        spec = load_spec(args.spec)
    except (OSError, ValueError) as exc:
        print(redact_text(str(exc)), file=sys.stderr)
        return 5

    if args.command == "show":
        print(describe(spec))
        return 0

    if args.out:
        from build_spec import OutputSpec
        from dataclasses import replace as _replace
        spec = spec.replace_section(output=_replace(spec.output, directory=args.out))
    if args.dry_run:
        print(describe(spec))
        print("\nDry run: nothing was fetched or written.")
        return 0
    runtime_inputs = None
    if args.runtime_config:
        from feathered_app.build_api import PreparationInputs
        try:
            runtime_inputs = PreparationInputs.from_dict(json.loads(args.runtime_config.read_text(encoding="utf-8")))
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"ERROR: {redact_text(str(exc))}", file=sys.stderr)
            return 5
    return run_build(spec, runtime_inputs=runtime_inputs,
                     accept_package_only=args.accept_package_only,
                     existing_output=args.existing_output, existing_metadata=args.existing_metadata, output=args.out, timeout=args.timeout, quiet=args.quiet,
                     accept_trust=args.accept_trust_findings,
                     accept_conflicts=args.accept_conflict_notices)


if __name__ == "__main__":
    raise SystemExit(main())
