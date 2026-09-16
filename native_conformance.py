"""Native package-manager conformance checks for Feathered.

This is intentionally an integration tier, not part of the fast/default pytest
suite. Feathered does not need to choose the same providers as APT/DNF/pacman;
the relevant invariant is that a closure Feathered calls complete can be
consumed offline by the native package manager using only the repository
Feathered generated.

That invariant is the load-bearing claim of the whole product. Feathered
reimplements three dependency resolvers, and the failure mode is not a crash --
it is a bundle that installs on the target and then breaks, or one that is
quietly missing something the target's real solver would have pulled. These
checks are the only evidence the claim holds.

Run:
    python native_conformance.py                  # report every tier
    python native_conformance.py --require apt    # a SKIP becomes a failure
    python native_conformance.py --require all

Exit status is 0 only if no tier failed and every required tier actually ran. A
tier that cannot run reports SKIP, so a bare run reports honestly without
failing. CI must pass --require (or set FEATHERED_REQUIRE_CONFORMANCE) naming
the tiers that worker can execute, otherwise a worker missing its package
manager reports success while validating nothing.

Scenario coverage is deliberately more than one root and one dependency. A
trivial A -> B graph proves almost nothing about a resolver; the cases below
target constructs that actually differ between implementations: transitive
depth, virtual/versioned provides, alternatives, and a version constraint that
must exclude an available older candidate.
"""
from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading
import traceback
from pathlib import Path

import apt_core
import arch_core
import core
import repository_tools

TIERS = ("apt", "dnf", "pacman")


def _native_file_url(path: Path) -> str:
    """Return a canonical local URL for native package-manager fixtures.

    Feathered's product URL helper intentionally preserves authority-less and
    UNC-compatible forms.  libcurl-backed DNF/pacman fixture consumers require
    the canonical absolute ``file:///...`` form, so the external-oracle harness
    uses pathlib's native URI serializer instead of changing product behavior.
    """
    return path.resolve().as_uri()


class _QuietRepositoryHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args) -> None:
        return


@contextlib.contextmanager
def _http_repository(path: Path):
    """Serve one generated bundle on loopback for transport-level validation."""
    handler = functools.partial(_QuietRepositoryHandler, directory=str(path))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------

def _make_deb(root: Path, upstream: Path, name: str, depends: str = "",
              version: str = "1.0", provides: str = "") -> None:
    tree = root / f"{name}-{version}-src"
    if tree.exists():
        shutil.rmtree(tree)
    (tree / "DEBIAN").mkdir(parents=True)
    control = (
        f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
        "Maintainer: Feathered Test <test@example.invalid>\n"
        "Description: native conformance fixture\n"
    )
    if depends:
        control += f"Depends: {depends}\n"
    if provides:
        control += f"Provides: {provides}\n"
    (tree / "DEBIAN" / "control").write_text(control, encoding="utf-8")
    subprocess.run(
        ["dpkg-deb", "--build", str(tree), str(upstream / f"{name}_{version}_amd64.deb")],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _make_rpm(root: Path, upstream: Path, name: str, requires: str = "",
              version: str = "1.0", provides: str = "") -> None:
    """Build a tiny noarch RPM with optional controlled dependency metadata."""
    top = root / "rpmbuild"
    for leaf in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
        (top / leaf).mkdir(parents=True, exist_ok=True)
    spec = top / "SPECS" / f"{name}-{version}.spec"
    extra = f"Requires: {requires}\n" if requires else ""
    if provides:
        extra += f"Provides: {provides}\n"
    spec.write_text(
        f"""Name: {name}
Version: {version}
Release: 1
Summary: Feathered native conformance fixture
License: MIT
BuildArch: noarch
{extra}
%description
Controlled Feathered native conformance package.

%prep

%build

%install
mkdir -p %{{buildroot}}/usr/share/feathered-native
printf '%s\\n' '{name}' > %{{buildroot}}/usr/share/feathered-native/{name}.txt

%files
/usr/share/feathered-native/{name}.txt
""",
        encoding="utf-8",
    )
    built = subprocess.run(
        ["rpmbuild", "-bb", "--define", f"_topdir {top}", str(spec)],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    rpms = sorted((top / "RPMS").rglob(f"{name}-{version}-1*.rpm"))
    if len(rpms) != 1:
        raise RuntimeError(
            f"rpmbuild did not produce exactly one RPM for {name} {version}: "
            f"{built.stdout}{built.stderr}")
    shutil.copy2(rpms[0], upstream / rpms[0].name)


def _make_arch_package(upstream: Path, name: str, depends: str = "",
                       version: str = "1.0-1", provides: str = "",
                       conflicts: str = "") -> None:
    """Build a tiny uncompressed-semantics Arch package using portable tar.gz."""
    filename = upstream / f"{name}-{version}-x86_64.pkg.tar.gz"
    lines = [
        f"pkgname = {name}", f"pkgbase = {name}", f"pkgver = {version}",
        "pkgdesc = Feathered native conformance fixture", "url = https://example.invalid",
        "builddate = 1", "packager = Feathered Test", "size = 32",
        "arch = x86_64", "license = MIT",
    ]
    for field_name, value in (("depend", depends), ("provides", provides),
                              ("conflict", conflicts)):
        for atom in str(value or "").split(","):
            atom = atom.strip()
            if atom:
                lines.append(f"{field_name} = {atom}")
    pkginfo = ("\n".join(lines) + "\n").encode()
    payload = name.encode() + b"\n"
    with tarfile.open(filename, "w:gz") as tf:
        meta = tarfile.TarInfo(".PKGINFO"); meta.size = len(pkginfo); meta.mode = 0o644
        tf.addfile(meta, io.BytesIO(pkginfo))
        member = tarfile.TarInfo(f"usr/share/feathered-native/{name}.txt")
        member.size = len(payload); member.mode = 0o644
        tf.addfile(member, io.BytesIO(payload))


def _check_closure(label: str, result, expected) -> set:
    if result.unresolved:
        raise RuntimeError(
            f"[{label}] Feathered declared the controlled graph unresolved: {result.unresolved}")
    selected = {p.name for p in result.selected}
    missing = [name for name in expected if name not in selected]
    if missing:
        raise RuntimeError(
            f"[{label}] Feathered's closure omitted {missing}; selected {sorted(selected)}")
    return selected


# --------------------------------------------------------------------------
# APT
# --------------------------------------------------------------------------

def run_apt_conformance() -> str:
    if not (shutil.which("dpkg-deb") and shutil.which("apt-get")):
        return "SKIP APT: dpkg-deb and apt-get are not both available"

    with tempfile.TemporaryDirectory(prefix="feathered-native-apt-") as td:
        root = Path(td)
        upstream = root / "upstream"
        upstream.mkdir()

        # Depth: a one-edge graph cannot catch a resolver that stops after the
        # first level.
        _make_deb(root, upstream, "fnc-leaf")
        _make_deb(root, upstream, "fnc-mid", "fnc-leaf (>= 1.0)")
        _make_deb(root, upstream, "fnc-deep", "fnc-mid (>= 1.0)")
        # Version floor: two candidates exist and only the newer satisfies the
        # constraint. A greedy first-match resolver emits a bundle APT refuses.
        _make_deb(root, upstream, "fnc-versioned", version="1.0")
        _make_deb(root, upstream, "fnc-versioned", version="2.0")
        _make_deb(root, upstream, "fnc-needs-new", "fnc-versioned (>= 2.0)")
        # Virtual provides: the requirement names something no package is called.
        _make_deb(root, upstream, "fnc-provider", provides="fnc-virtual")
        _make_deb(root, upstream, "fnc-needs-virtual", "fnc-virtual")
        # Alternatives: the first branch does not exist, the second must be taken.
        _make_deb(root, upstream, "fnc-alt-b")
        _make_deb(root, upstream, "fnc-needs-alt", "fnc-absent-package | fnc-alt-b")

        scenarios = [
            ("transitive depth", "fnc-deep", ("fnc-deep", "fnc-mid", "fnc-leaf")),
            ("version floor", "fnc-needs-new", ("fnc-needs-new", "fnc-versioned")),
            ("virtual provides", "fnc-needs-virtual", ("fnc-needs-virtual", "fnc-provider")),
            ("alternatives", "fnc-needs-alt", ("fnc-needs-alt", "fnc-alt-b")),
        ]

        repository_tools.rebuild_repository_metadata(upstream)
        repo = core.RepoSpec(
            "Native conformance source", core.path_to_file_url(upstream), repo_format="apt",
            suite="feathered", components="main", verification_strategy="skip-provenance")
        reporter = core.Reporter()
        packages = apt_core.load_repository(repo, {"amd64"}, reporter)
        options = core.BuildOptions(include_dependencies=True, verify_checksums=True,
                                    emit_repository=True)

        for index, (label, root_name, expected) in enumerate(scenarios):
            result = apt_core.resolve([(root_name, None, None)], packages, "amd64",
                                      options, reporter)
            _check_closure(label, result, expected)
            if root_name == "fnc-needs-new":
                versions = {p.name: str(getattr(p, "version", "")) for p in result.selected}
                if not versions.get("fnc-versioned", "").startswith("2"):
                    raise RuntimeError(
                        f"[{label}] version floor ignored: chose fnc-versioned "
                        f"{versions.get('fnc-versioned')!r}, needed >= 2.0")

            bundle = root / f"bundle-{index}"
            apt_core.write_bundle(result, bundle, options, reporter,
                                  {"test": f"native-apt-conformance:{label}"})
            _apt_solve(root, bundle, index, label, root_name, expected)

        def status_row(name, version, depends=""):
            return (f"Package: {name}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {version}\n"
                    + (f"Depends: {depends}\n" if depends else "") + "Description: captured native fixture\n\n")

        # The generated plan, not the original optional request list, drives APT.
        newer = apt_core.resolve([("fnc-versioned", "2.0", None)], packages, "amd64", options, reporter)
        older = apt_core.resolve([("fnc-versioned", "1.0", None), ("fnc-optional-absent", None, None)],
            packages, "amd64", core.BuildOptions(optional_roots={"fnc-optional-absent"}), reporter)
        additive = root / "pinned-additive"
        apt_core.write_bundle(newer, additive, options, reporter, {})
        apt_core.write_bundle(older, additive, core.BuildOptions(additive_publish=True), reporter,
                              {"requested_packages":["fnc-versioned", "fnc-optional-absent"]})
        _apt_solve(root, additive, 100, "pinned additive version with missing optional root", "fnc-versioned",
                   ["fnc-versioned"], status_row("fnc-versioned", "2.0"), {"fnc-versioned":"1.0"})

        reverse_bundle = root / "reverse-check"
        apt_core.write_bundle(newer, reverse_bundle, options, reporter, {})
        _apt_solve(root, reverse_bundle, 101, "retained reverse dependency blocks upgrade", "fnc-versioned", [],
            status_row("fnc-versioned", "1.0") + status_row("fnc-retained", "1.0", "fnc-versioned (= 1.0)"),
            expect_failure=True)

        delta = root / "baseline-delta"
        apt_core.write_bundle(older, delta, core.BuildOptions(baseline_manifest=str(additive / "debs/manifest.json")), reporter, {})
        from receiver_preflight import validate
        import json
        contract = json.loads((delta / "debs/INSTALLATION-CONTRACT.json").read_text())
        try:
            validate(contract, {}, machine="x86_64")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Baseline delta preflight accepted a target missing its baseline")
        validate(contract, {("fnc-versioned", "amd64"):"1.0"}, machine="x86_64")
        _apt_solve(root, delta, 102, "installed baseline permits empty delta", "fnc-versioned", [],
                   status_row("fnc-versioned", "1.0"))

    return ("PASS APT: native apt-get accepted and solved "
            f"{len(scenarios)+3} generated Feathered bundle/target scenarios offline "
            f"({', '.join(label for label, _, _ in scenarios)}, pinned additive/optional roots, reverse dependency rejection, baseline delta)")


def _apt_solve(root: Path, bundle: Path, index: int, label: str,
               root_name: str, expected, installed_status="", expected_versions=None, expect_failure=False) -> None:
    apt_state = root / f"apt-state-{index}"
    lists = apt_state / "lists"
    cache = apt_state / "cache"
    (lists / "partial").mkdir(parents=True)
    (cache / "archives" / "partial").mkdir(parents=True)
    etc = apt_state / "etc"
    etc.mkdir()
    status = apt_state / "status"
    status.write_text(installed_status, encoding="utf-8")
    sources = etc / "sources.list"
    sources.write_text(
        f"deb [trusted=yes] {core.path_to_file_url(bundle)} feathered main\n", encoding="utf-8")
    common = [
        "apt-get",
        "-o", f"Dir::Etc::sourcelist={sources}",
        "-o", "Dir::Etc::sourceparts=-",
        "-o", f"Dir::State::lists={lists}",
        "-o", f"Dir::State::status={status}",
        "-o", f"Dir::Cache={cache}",
        "-o", "Acquire::Languages=none",
        "-o", "APT::Get::List-Cleanup=0",
    ]
    update = subprocess.run(common + ["update"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if update.returncode != 0:
        raise RuntimeError(f"[{label}] Native APT rejected Feathered repository metadata:\n"
                           + update.stdout + update.stderr)
    arguments = (bundle / "debs" / "TRANSACTION-ARGS.txt").read_text().splitlines()
    solve = subprocess.run(
        common + ["-s", "--no-download", "--no-remove", "install", *arguments],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if expect_failure:
        if solve.returncode == 0:
            raise RuntimeError(f"[{label}] Native APT accepted an invalid target transaction")
        return
    if solve.returncode != 0:
        raise RuntimeError(f"[{label}] Native APT could not solve Feathered's COMPLETE bundle "
                           "offline:\n" + solve.stdout + solve.stderr)
    for name in expected:
        if name not in solve.stdout:
            raise RuntimeError(
                f"[{label}] Native APT solve output did not include {name}:\n" + solve.stdout)
    if expected_versions:
        import re
        observed = dict(re.findall(r"^Inst (\S+)(?: \[[^]]+\])? \((\S+)", solve.stdout, flags=re.MULTILINE))
        for name, version in expected_versions.items():
            if observed.get(name) != version:
                raise RuntimeError(f"[{label}] Native APT did not preserve {name}={version}: {observed}")


# --------------------------------------------------------------------------
# DNF
# --------------------------------------------------------------------------

def run_dnf_conformance() -> str:
    """Validate Feathered COMPLETE RPM bundles with native DNF offline.

    Feathered intentionally remains the planning/provenance resolver. DNF is the
    final transaction oracle: if Feathered says the controlled graph is complete,
    DNF must be able to solve a transaction using only the emitted local repo.
    """
    if not (shutil.which("rpmbuild") and shutil.which("dnf")):
        return "SKIP DNF: rpmbuild and dnf are not both available"

    with tempfile.TemporaryDirectory(prefix="feathered-native-dnf-") as td:
        root = Path(td)
        upstream = root / "upstream"
        upstream.mkdir()

        _make_rpm(root, upstream, "fnc-leaf")
        _make_rpm(root, upstream, "fnc-mid", "fnc-leaf >= 1.0")
        _make_rpm(root, upstream, "fnc-deep", "fnc-mid >= 1.0")
        _make_rpm(root, upstream, "fnc-versioned", version="1.0")
        _make_rpm(root, upstream, "fnc-versioned", version="2.0")
        _make_rpm(root, upstream, "fnc-needs-new", "fnc-versioned >= 2.0")
        _make_rpm(root, upstream, "fnc-provider", provides="fnc-virtual = 1.0")
        _make_rpm(root, upstream, "fnc-needs-virtual", "fnc-virtual")

        scenarios = [
            ("transitive depth", "fnc-deep", ("fnc-deep", "fnc-mid", "fnc-leaf")),
            ("version floor", "fnc-needs-new", ("fnc-needs-new", "fnc-versioned")),
            ("virtual provides", "fnc-needs-virtual", ("fnc-needs-virtual", "fnc-provider")),
        ]

        repository_tools.rebuild_repository_metadata(upstream)
        repo = core.RepoSpec(
            "Native conformance source", core.path_to_file_url(upstream), repo_format="rpm",
            verification_strategy="skip-provenance")
        reporter = core.Reporter()
        packages = core.load_repository(repo, {"noarch", "x86_64"}, reporter)
        options = core.BuildOptions(include_dependencies=True, verify_checksums=True,
                                    emit_repository=True)

        for index, (label, root_name, expected) in enumerate(scenarios):
            result = core.resolve([(root_name, None, None)], packages, "x86_64", options, reporter)
            _check_closure(label, result, expected)

            bundle = root / f"bundle-{index}"
            core.write_bundle(result, bundle, options, reporter,
                              {"test": f"native-dnf-conformance:{label}"})

            def run_oracle(repo_url: str, transport: str) -> None:
                installroot = root / f"dnf-installroot-{index}-{transport}"
                cachedir = root / f"dnf-cache-{index}-{transport}"
                installroot.mkdir(); cachedir.mkdir()
                # tsflags=test asks RPM to validate the complete transaction
                # without committing it. All configured system repositories are
                # disabled and the only enabled source is Feathered's bundle.
                command = [
                    "dnf", "-y",
                    "--installroot", str(installroot),
                    "--releasever", "9",
                    "--setopt", "reposdir=/dev/null",
                    "--setopt", f"cachedir={cachedir}",
                    "--setopt", "persistdir=/var/lib/dnf",
                    "--setopt", "install_weak_deps=False",
                    "--setopt", "tsflags=test",
                    "--disablerepo=*",
                    f"--repofrompath=feathered,{repo_url}",
                    "--enablerepo=feathered",
                    "--nogpgcheck",
                    "install", root_name,
                ]
                solve = subprocess.run(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
                if solve.returncode != 0:
                    raise RuntimeError(
                        f"[{label}] Native DNF could not solve/test Feathered's COMPLETE "
                        f"bundle over {transport}:\n" + solve.stdout + solve.stderr)
                output = solve.stdout + solve.stderr
                for name in expected:
                    if name not in output:
                        raise RuntimeError(
                            f"[{label}] Native DNF {transport} transaction output did not "
                            f"include {name}:\n" + output)

            # Every scenario exercises canonical local file:// consumption.
            run_oracle(_native_file_url(bundle), "file")
            # One representative graph is also fetched through loopback HTTP.
            # This makes librepo validate transfer metadata, including
            # <size package>, instead of proving only local-file readability.
            if index == 0:
                with _http_repository(bundle) as http_url:
                    run_oracle(http_url, "http")

    return ("PASS DNF: native dnf accepted and transaction-tested "
            f"{len(scenarios)} generated Feathered bundles over canonical file URLs, "
            "plus loopback HTTP transfer validation "
            f"({', '.join(label for label, _, _ in scenarios)})")


# --------------------------------------------------------------------------
# pacman
# --------------------------------------------------------------------------

def run_pacman_conformance() -> str:
    """Validate Feathered COMPLETE Arch bundles with native pacman offline."""
    if not shutil.which("pacman"):
        return "SKIP pacman: pacman is not available"

    with tempfile.TemporaryDirectory(prefix="feathered-native-pacman-") as td:
        root = Path(td)
        upstream = root / "upstream"; upstream.mkdir()

        _make_arch_package(upstream, "fnc-leaf")
        _make_arch_package(upstream, "fnc-mid", "fnc-leaf>=1.0")
        _make_arch_package(upstream, "fnc-deep", "fnc-mid>=1.0")
        _make_arch_package(upstream, "fnc-provider", provides="fnc-virtual=1.0")
        _make_arch_package(upstream, "fnc-needs-virtual", "fnc-virtual")
        _make_arch_package(upstream, "fnc-database")
        _make_arch_package(
            upstream, "fnc-renderer-a", provides="fnc-renderer=1.0",
            conflicts="fnc-database")
        _make_arch_package(upstream, "fnc-renderer-b", provides="fnc-renderer=1.0")
        _make_arch_package(
            upstream, "fnc-needs-renderer", "fnc-renderer,fnc-database")
        _make_arch_package(upstream, "fnc-render-helper", conflicts="fnc-database")
        _make_arch_package(
            upstream, "fnc-transitive-a", "fnc-render-helper",
            provides="fnc-renderer-transitive=1.0")
        _make_arch_package(
            upstream, "fnc-transitive-b", provides="fnc-renderer-transitive=1.0")
        _make_arch_package(
            upstream, "fnc-needs-transitive",
            "fnc-renderer-transitive,fnc-database")

        scenarios = [
            ("transitive depth", "fnc-deep",
             ("fnc-deep", "fnc-mid", "fnc-leaf"), ()),
            ("virtual provides", "fnc-needs-virtual",
             ("fnc-needs-virtual", "fnc-provider"), ()),
            ("provider conflict backtracking", "fnc-needs-renderer",
             ("fnc-needs-renderer", "fnc-renderer-b", "fnc-database"),
             ("fnc-renderer-a",)),
            ("transitive provider conflict backtracking", "fnc-needs-transitive",
             ("fnc-needs-transitive", "fnc-transitive-b", "fnc-database"),
             ("fnc-transitive-a", "fnc-render-helper")),
        ]

        repository_tools.rebuild_repository_metadata(upstream)
        repo = core.RepoSpec(
            "Native conformance source", core.path_to_file_url(upstream) + "/",
            repo_format="pacman", suite="feathered", verification_strategy="skip-provenance")
        reporter = core.Reporter()
        packages = arch_core.load_repository(repo, {"x86_64"}, reporter)
        options = core.BuildOptions(include_dependencies=True, verify_checksums=True,
                                    emit_repository=True)

        for index, (label, root_name, expected, forbidden) in enumerate(scenarios):
            result = arch_core.resolve([(root_name, None, None)], packages, "x86_64",
                                       options, reporter)
            selected = _check_closure(label, result, expected)
            unexpected = sorted(set(forbidden) & selected)
            if unexpected:
                raise RuntimeError(
                    f"[{label}] Feathered selected conflicting provider(s) {unexpected}; "
                    f"selected {sorted(selected)}")

            bundle = root / f"bundle-{index}"
            arch_core.write_bundle(result, bundle, options, reporter, {
                "test": f"native-pacman-conformance:{label}",
                "requested_packages": [root_name]})

            dbpath = root / f"pacman-db-{index}"; dbpath.mkdir()
            cache = root / f"pacman-cache-{index}"; cache.mkdir()
            installroot = root / f"pacman-root-{index}"; installroot.mkdir()
            config = root / f"pacman-{index}.conf"
            config.write_text(
                "[options]\nArchitecture = x86_64\nSigLevel = Never\nLocalFileSigLevel = Never\n"
                f"CacheDir = {cache}\n\n[feathered]\n"
                f"Server = {_native_file_url(bundle / 'packages')}\n",
                encoding="utf-8")
            common = ["pacman", "--root", str(installroot), "--dbpath", str(dbpath),
                      "--config", str(config), "--noconfirm"]
            update = subprocess.run(common + ["-Sy"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            if update.returncode != 0:
                raise RuntimeError(f"[{label}] Native pacman rejected Feathered repository "
                                   "metadata:\n" + update.stdout + update.stderr)
            solve = subprocess.run(
                common + ["-Sp", "--print-format", "%n", root_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if solve.returncode != 0:
                raise RuntimeError(f"[{label}] Native pacman could not solve Feathered's COMPLETE "
                                   "bundle offline:\n" + solve.stdout + solve.stderr)
            output = solve.stdout + solve.stderr
            for name in expected:
                if name not in output:
                    raise RuntimeError(
                        f"[{label}] Native pacman solve output did not include {name}:\n" + output)

    return ("PASS pacman: native pacman accepted and solved "
            f"{len(scenarios)} generated Feathered bundles offline "
            f"({', '.join(label for label, _, _, _ in scenarios)})")


RUNNERS = {
    "apt": run_apt_conformance,
    "dnf": run_dnf_conformance,
    "pacman": run_pacman_conformance,
}


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def _required_tiers(argument) -> set:
    raw = list(argument or [])
    from_env = os.environ.get("FEATHERED_REQUIRE_CONFORMANCE", "")
    if from_env:
        raw.append(from_env)
    names = set()
    for chunk in raw:
        for name in str(chunk).replace(",", " ").split():
            name = name.strip().lower()
            if name == "all":
                names.update(TIERS)
            elif name in TIERS:
                names.add(name)
            elif name:
                raise SystemExit(
                    f"unknown conformance tier: {name} (choose from {', '.join(TIERS)}, all)")
    return names


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Feathered bundles against native package managers.")
    parser.add_argument(
        "--require", action="append", metavar="TIER",
        help="tiers that must actually run; a SKIP becomes a failure. Comma or space "
             "separated, or 'all'. Also read from FEATHERED_REQUIRE_CONFORMANCE.")
    args = parser.parse_args(argv)
    required = _required_tiers(args.require)

    failed = []
    skipped = []
    for tier in TIERS:
        try:
            line = RUNNERS[tier]()
        except Exception:
            # Keep going: one broken tier must not hide the state of the others.
            print(f"FAIL {tier}: conformance raised", flush=True)
            traceback.print_exc()
            failed.append(tier)
            continue
        print(line, flush=True)
        if line.startswith("SKIP"):
            skipped.append(tier)

    unmet = sorted(required.intersection(skipped))
    if unmet:
        print(f"\nERROR: required conformance tier(s) did not run: {', '.join(unmet)}. "
              "Install the native package manager on this worker, or drop the tier from "
              "--require.", flush=True)
    if failed:
        print(f"\nERROR: conformance FAILED for: {', '.join(failed)}.", flush=True)
    if failed or unmet:
        return 1
    if not required:
        print("\nNote: no tier was required, so SKIP did not fail this run. CI should pass "
              "--require naming the tiers this worker can execute.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
