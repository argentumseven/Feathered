"""Differential oracle: check Feathered's closure against libsolv, at volume.

`native_conformance.py` is the authority -- it runs the real package managers --
but each of its scenarios costs a hand-written fixture and a real package build
(`rpmbuild`, `dpkg-deb`), so there are seven per family and the twentieth would
cost as much as the eighth. The long-tail failures most likely to bite live
exactly where seven hand-written cases do not reach: unusual conflicts, versioned
virtual provides, deep chains with a version floor discovered late.

libsolv reads *metadata*, not built packages, so a scenario here costs a few
kilobytes of generated text and no toolchain at all. That is what makes
thousands of randomly generated graphs feasible.

WHAT THIS PROVES, AND WHAT IT DOES NOT
--------------------------------------
The question is **"is Feathered's closure installable?"**, not "does it match
libsolv's chosen set". Those are different, and the difference matters:

    libsolv : pkg0 pkg2 pkg3 pkg6 pkg7 pkg8
    Feathered: pkg0 pkg3 pkg5 pkg6 pkg7 pkg8

That divergence (seed 2739) is not a defect. Both closures are complete; they
picked different providers for the same virtual requirement. A set-equality or
subset check calls it a failure, and an early version of this oracle did exactly
that at a rate of ~0.8% -- enough false positives to make the gate worthless.

So the check loads **only the packages Feathered selected** into a libsolv pool
and asks libsolv to install the roots from that pool alone. If it can, the
bundle is installable; if it cannot, something the closure needed is missing.
That mirrors the `apt-get --simulate --no-remove` the generated installer runs
on the target, and it has no provider-choice false positives.

Feathered computes a download closure, not a minimal transaction. Over-inclusion
costs disk space on a USB stick and is not a defect; under-inclusion is, because
a package missing from the bundle cannot be installed on the far side of an air
gap. This check is sensitive to exactly that asymmetry.

Tiering, which must not be blurred:

  * dnf *is* libsolv, so agreement for rpm is close to proof.
  * apt has its own solver and pacman uses libalpm, so for deb this is a
    high-volume *screen* -- suggestive, never authoritative.

A pass here is evidence about the closure algorithm. It is not a substitute for
a native tier in `native_conformance.py`.

The generator is the single source of truth for a scenario: it emits both the
in-memory package records Feathered resolves and the repository metadata libsolv
loads. It therefore exercises the resolver, not the metadata parsers, which the
native oracles already cover by running the real tools against real output.

STATUS: EXPERIMENTAL -- NOT A RELEASE GATE
------------------------------------------
This oracle is not yet trustworthy enough to block a build, and is deliberately
not wired into windows-release.yml.

It has teeth: deliberately dropping one package from the closure is detected in
40/40 scenarios, with the missing package and its requirers named. But at 6,000
scenarios it also reports roughly 0.5% failures that are harness artifacts
rather than Feathered defects. One was traced in full -- seed 108/deb, where the
shipped set provably satisfies every requirement in the graph and the restricted
libsolv pool still refused it -- and the remainder have not been run down.

Until that rate is zero, a failure here is a prompt to investigate, not evidence
of a bug. Do not gate on it, and do not record a pass in VALIDATION.md as
though it were a tier. The first false positive treated as authoritative is
what makes a gate get switched off.

Usage::

    python solv_oracle.py                      # default scenario budget
    python solv_oracle.py --scenarios 2000     # more graphs
    python solv_oracle.py --seed 12345         # reproduce one failure
    python solv_oracle.py --require solv       # SKIP becomes failure, for CI
"""
from __future__ import annotations

import argparse
import hashlib
import random
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import apt_core
import core
from core import BuildOptions, Package, RepoSpec, Reporter

try:
    import solv  # type: ignore
except ImportError:  # pragma: no cover - exercised by the SKIP path
    solv = None

ARCH = {"rpm": "x86_64", "deb": "amd64"}


# --------------------------------------------------------------------------
# Scenario model
# --------------------------------------------------------------------------

@dataclass
class Node:
    """One package in a generated dependency graph."""

    name: str
    version: str
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)


@dataclass
class Scenario:
    seed: int
    family: str
    nodes: List[Node]
    roots: List[str]

    def describe(self) -> str:
        return (f"seed={self.seed} family={self.family} "
                f"nodes={len(self.nodes)} roots={','.join(self.roots)}")


def generate(seed: int, family: str) -> Scenario:
    """A random but reproducible dependency graph.

    Shapes deliberately included because they are where a greedy closure and a
    SAT solver are most likely to diverge: chains long enough to need more than
    one resolution pass, several versions of one name so a version floor can be
    discovered late, and virtual provides with more than one provider.
    """
    #  Mixed into the seed so the two families do not generate identical graphs.
    rng = random.Random(f"{seed}:{family}")
    count = rng.randint(3, 14)
    names = [f"pkg{index}" for index in range(count)]
    virtuals = [f"virt{index}" for index in range(rng.randint(0, 2))]

    nodes: List[Node] = []
    for position, name in enumerate(names):
        # A set literal, not a list: iteration order over strings depends on
        # PYTHONHASHSEED, so the same seed produced different graphs between
        # runs and "reproduce with --seed N" did not. Keep graph generation
        # independent of PYTHONHASHSEED so failures remain reproducible.
        for version in (("1", "2") if rng.random() < 0.3 else ("1",)):
            requires: List[str] = []
            # Only depend forward, so the graph stays acyclic and a missing
            # package is unambiguously the resolver's omission.
            for candidate in names[position + 1:]:
                if rng.random() < 0.35:
                    requires.append(candidate)
            if virtuals and rng.random() < 0.3:
                requires.append(rng.choice(virtuals))
            provides = [v for v in virtuals if rng.random() < 0.4]
            nodes.append(Node(name=name, version=version,
                              requires=requires, provides=provides))

    # Any virtual that is required must have at least one provider, or the
    # scenario tests unsatisfiability rather than closure agreement.
    for virtual in virtuals:
        if not any(virtual in node.provides for node in nodes):
            rng.choice(nodes).provides.append(virtual)
    #  Sets are used above for membership only; every ordering that reaches the
    #  generated scenario is a list or tuple, so a seed fully determines it.

    roots = [names[0]]
    if count > 4 and rng.random() < 0.4:
        roots.append(rng.choice(names[1:]))
    return Scenario(seed=seed, family=family, nodes=nodes, roots=sorted(set(roots)))


def _digest(node: Node) -> str:
    return hashlib.sha256(f"{node.name}-{node.version}".encode()).hexdigest()


# --------------------------------------------------------------------------
# Feathered side
# --------------------------------------------------------------------------

def feathered_closure(scenario: Scenario) -> Tuple[set, List[str]]:
    """Return ``({(name, version), ...}, unresolved)`` for the generated graph.

    Versions matter: shipping pkg5-1 where the closure needed pkg5-2 is exactly
    the kind of omission this oracle exists to catch, so the identity carried
    forward is the specific package, not the name.
    """
    repo = RepoSpec("Oracle", "https://oracle.invalid/repo/", "dependency",
                    repo_format="apt" if scenario.family == "deb" else "rpm-md",
                    suite="stable", components="main")
    arch = ARCH[scenario.family]
    reporter = Reporter()

    if scenario.family == "deb":
        packages = [
            apt_core.DebPackage(
                node.name, arch, node.version, f"{node.name}_{node.version}.deb",
                "sha256", _digest(node), repo, digests={"sha256": _digest(node)}, size=100,
                provides=apt_core.parse_provides(", ".join(node.provides)) if node.provides else [],
                depends=apt_core.parse_dependency_field(", ".join(node.requires), "depends")
                if node.requires else [])
            for node in scenario.nodes]
        result = apt_core.resolve([(r, None, None) for r in scenario.roots],
                                  packages, arch, BuildOptions(), reporter)
    else:
        packages = []
        for node in scenario.nodes:
            pkg = Package(node.name, arch, "0", node.version, "1",
                          f"{node.name}-{node.version}.rpm", "sha256", _digest(node),
                          repo, digests={"sha256": _digest(node)}, size=100)
            pkg.provides = ([core.Requirement(node.name, "EQ", "0", node.version, "1", "provides")]
                            + [core.Requirement(v, kind="provides") for v in node.provides])
            pkg.requires = [core.Requirement(r, kind="requires") for r in node.requires]
            packages.append(pkg)
        result = core.resolve([(r, None, "dependency") for r in scenario.roots],
                              packages, arch, BuildOptions(), reporter)

    selected = {(p.name, p.version) for p in result.selected}
    unresolved = [str(u) for u in getattr(result, "unresolved", []) or []]
    return selected, unresolved


# --------------------------------------------------------------------------
# libsolv side
# --------------------------------------------------------------------------

def _primary_xml(scenario: Scenario, nodes: Optional[Sequence[Node]] = None) -> str:
    nodes = scenario.nodes if nodes is None else nodes
    metadata = ET.Element("metadata", {
        "xmlns": "http://linux.duke.edu/metadata/common",
        "xmlns:rpm": "http://linux.duke.edu/metadata/rpm",
        "packages": str(len(nodes))})
    for node in nodes:
        package = ET.SubElement(metadata, "package", {"type": "rpm"})
        ET.SubElement(package, "name").text = node.name
        ET.SubElement(package, "arch").text = ARCH["rpm"]
        ET.SubElement(package, "version",
                      {"epoch": "0", "ver": node.version, "rel": "1"})
        checksum = ET.SubElement(package, "checksum", {"type": "sha256", "pkgid": "YES"})
        checksum.text = _digest(node)
        ET.SubElement(package, "size", {"package": "100"})
        ET.SubElement(package, "location",
                      {"href": f"{node.name}-{node.version}.rpm"})
        fmt = ET.SubElement(package, "format")
        provides = ET.SubElement(fmt, "rpm:provides")
        ET.SubElement(provides, "rpm:entry", {
            "name": node.name, "flags": "EQ", "epoch": "0",
            "ver": node.version, "rel": "1"})
        for virtual in node.provides:
            ET.SubElement(provides, "rpm:entry", {"name": virtual})
        if node.requires:
            requires = ET.SubElement(fmt, "rpm:requires")
            for requirement in node.requires:
                ET.SubElement(requires, "rpm:entry", {"name": requirement})
    return ET.tostring(metadata, encoding="unicode")


def _packages_file(scenario: Scenario, nodes: Optional[Sequence[Node]] = None) -> str:
    stanzas = []
    for node in (scenario.nodes if nodes is None else nodes):
        lines = [f"Package: {node.name}",
                 f"Version: {node.version}",
                 f"Architecture: {ARCH['deb']}",
                 f"Filename: pool/{node.name}_{node.version}.deb",
                 "Size: 100",
                 f"SHA256: {_digest(node)}"]
        if node.requires:
            lines.append("Depends: " + ", ".join(node.requires))
        if node.provides:
            lines.append("Provides: " + ", ".join(node.provides))
        lines.append("Description: oracle fixture")
        stanzas.append("\n".join(lines))
    return "\n\n".join(stanzas) + "\n"


def solv_solution(scenario: Scenario, workdir: Path,
                  nodes: Optional[Sequence[Node]] = None) -> Optional[set]:
    """Ask libsolv to install the roots from ``nodes`` (default: the whole repo).

    Returns the solved set, or None when libsolv cannot satisfy the roots from
    what it was given -- which for a restricted pool means the closure under
    test is not installable.
    """
    pool = solv.Pool()
    pool.setarch(ARCH[scenario.family])
    repo = pool.add_repo("oracle")

    if scenario.family == "deb":
        path = workdir / "Packages"
        path.write_text(_packages_file(scenario, nodes), encoding="utf-8")
        repo.add_debpackages(solv.xfopen(str(path)), 0)
    else:
        path = workdir / "primary.xml"
        path.write_text(_primary_xml(scenario, nodes), encoding="utf-8")
        repo.add_rpmmd(solv.xfopen(str(path)), None, 0)

    pool.addfileprovides()
    pool.createwhatprovides()

    jobs = []
    for root in scenario.roots:
        selection = pool.select(root, solv.Selection.SELECTION_NAME)
        if selection.isempty():
            return None
        jobs += selection.jobs(solv.Job.SOLVER_INSTALL)

    solver = pool.Solver()
    if solver.solve(jobs):
        return None
    return {(s.name, s.evr.split("-")[0].split(":")[-1])
            for s in solver.transaction().newsolvables()}


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

@dataclass
class Outcome:
    checked: int = 0
    skipped: int = 0
    failures: List[str] = field(default_factory=list)


def check(scenario: Scenario, workdir: Path) -> Tuple[str, str]:
    """Return ``(verdict, detail)`` where verdict is ok/skip/fail."""
    # 1. Is the scenario satisfiable at all? A graph libsolv cannot solve from
    #    the full repository tests unsatisfiability handling, not closure
    #    completeness, so it is not this oracle's question.
    if solv_solution(scenario, workdir) is None:
        return "skip", "libsolv found no solution from the full repository"

    # 2. What would Feathered put in the bundle?
    selected, unresolved = feathered_closure(scenario)
    if not selected:
        return "fail", f"{scenario.describe()}\n    Feathered selected nothing"

    # 3. Can libsolv install the roots from *only* that, as the target must?
    shipped = [node for node in scenario.nodes if (node.name, node.version) in selected]
    if solv_solution(scenario, workdir, shipped) is not None:
        return "ok", ""

    # Name what is missing, using the requirements the shipped set cannot meet.
    available = {node.name for node in shipped} | {
        virtual for node in shipped for virtual in node.provides}
    gaps = sorted({requirement
                   for node in shipped for requirement in node.requires
                   if requirement not in available})
    return "fail", (
        f"{scenario.describe()}\n"
        f"    Feathered shipped: "
        f"{', '.join(sorted(f'{n}-{v}' for n, v in selected))}\n"
        f"    unsatisfied:       {', '.join(gaps) or 'root not present in the closure'}\n"
        f"    unresolved:        {'; '.join(unresolved) or 'none reported'}\n"
        f"    reproduce:         python solv_oracle.py --seed {scenario.seed} "
        f"--family {scenario.family} --scenarios 1")


def run(families: Sequence[str], scenarios: int, first_seed: int) -> Outcome:
    outcome = Outcome()
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for offset in range(scenarios):
            for family in families:
                scenario = generate(first_seed + offset, family)
                verdict, detail = check(scenario, workdir)
                if verdict == "ok":
                    outcome.checked += 1
                elif verdict == "skip":
                    outcome.skipped += 1
                else:
                    outcome.checked += 1
                    outcome.failures.append(detail)
    return outcome


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", type=int, default=400)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--family", action="append", choices=sorted(ARCH),
                        help="repeatable; defaults to all")
    parser.add_argument("--require", action="append", default=[],
                        help="'solv' turns a SKIP into a failure, for CI")
    parser.add_argument("--gate", action="store_true",
                        help="exit non-zero on findings; unsafe until the "
                             "residual false-positive rate is zero")
    args = parser.parse_args(argv)

    if solv is None:
        message = ("SKIP solv: python3-solv is not installed "
                   "(Debian/Ubuntu: apt-get install python3-solv)")
        print(message)
        # --require exists so a misconfigured runner cannot report success by
        # validating nothing, matching native_conformance.py.
        return 1 if "solv" in args.require else 0

    families = args.family or sorted(ARCH)
    outcome = run(families, args.scenarios, args.seed)

    for failure in outcome.failures:
        print("FAIL " + failure)
    print(f"solv oracle (EXPERIMENTAL): {outcome.checked} scenario(s) compared across "
          f"{', '.join(families)}, {outcome.skipped} skipped, "
          f"{len(outcome.failures)} failing")
    if outcome.failures:
        print("Findings above are candidates for investigation, not confirmed defects: "
              "this harness has a known residual false-positive rate. See the module "
              "docstring before acting on one.")
        # Exit 0 unless explicitly asked to gate, so nobody wires an
        # experimental harness into a pipeline by accident.
        return 1 if args.gate else 0
    print("PASS solv: every generated closure was installable from itself")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
