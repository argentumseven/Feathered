from __future__ import annotations

import re
from collections import defaultdict, deque
from functools import cmp_to_key
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

import rpm_capabilities
from core_models import BuildOptions, Package, ProviderMatch, Requirement, ResolutionResult, TargetInventory
from execution_reporter import Reporter

if TYPE_CHECKING:
    from root_requests import RootInput

def _segments(value: str) -> List[Tuple[int, Union[int, str]]]:
    out: List[Tuple[int, Union[int, str]]] = []
    i = 0
    value = value or ""
    while i < len(value):
        c = value[i]
        if c == "~": out.append((-1, "~")); i += 1; continue
        if c == "^": out.append((0, "^")); i += 1; continue
        if not c.isalnum(): i += 1; continue
        j = i + 1
        if c.isdigit():
            while j < len(value) and value[j].isdigit(): j += 1
            out.append((2, int(value[i:j].lstrip("0") or "0")))
        else:
            while j < len(value) and value[j].isalpha(): j += 1
            out.append((1, value[i:j]))
        i = j
    return out


def rpmvercmp(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    for left, right in zip(sa, sb):
        if left == right: continue
        lt, lv = left; rt, rv = right
        if lt == -1 or rt == -1: return -1 if lt == -1 else 1
        if lt != rt: return 1 if lt > rt else -1
        # Segment kinds: 2 = numeric run (value is int), 1 = alphabetic run
        # (value is str), 0 = "^", -1 = "~". Matching kinds guarantee matching
        # value types, so each branch compares like with like -- comparing a
        # numeric run as text would rank 1.9 above 1.10.
        if lt == 2:
            ln, rn = int(lv), int(rv)
            if ln != rn: return -1 if ln < rn else 1
        else:
            ls, rs = str(lv), str(rv)
            if ls != rs: return -1 if ls < rs else 1
    if len(sa) == len(sb): return 0
    rest = sa[len(sb):] if len(sa) > len(sb) else sb[len(sa):]
    if rest and rest[0][0] == -1: return -1 if len(sa) > len(sb) else 1
    return 1 if len(sa) > len(sb) else -1


def compare_evr(left: Tuple[str, str, str], right: Tuple[str, str, str]) -> int:
    try: le = int(left[0] or "0")
    except ValueError: le = 0
    try: re_ = int(right[0] or "0")
    except ValueError: re_ = 0
    if le != re_: return 1 if le > re_ else -1
    c = rpmvercmp(left[1], right[1])
    return c if c else rpmvercmp(left[2], right[2])


_PYDIST_CAP_RE = rpm_capabilities.PYDIST_CAP_RE


def _pep503_name(value: str) -> str:
    return rpm_capabilities.pep503_name(value, substitute=lambda pattern, replacement, text: re.sub(pattern, replacement, text))


def canonical_capability_name(name: str) -> str:
    return rpm_capabilities.canonical_capability_name(
        name, pattern=_PYDIST_CAP_RE, normalize=lambda value: _pep503_name(value))


def capability_names_equal(left: str, right: str) -> bool:
    return canonical_capability_name(left) == canonical_capability_name(right)


def _index_keys(name: str) -> Tuple[str, ...]:
    # Keep this tiny, frequently called index operation local. Capability
    # normalization remains delegated through the existing core hook.
    raw = (name or "").strip()
    canonical = canonical_capability_name(raw)
    return (raw,) if canonical == raw else (raw, canonical)


def _provider_candidates(index: Dict[str, List[ProviderMatch]], req: Requirement) -> List[ProviderMatch]:
    """Return de-duplicated provider candidates using exact and canonical keys."""
    seen: Set[Tuple[int, str, str, Optional[Tuple[str, str, str]]]] = set()
    out: List[ProviderMatch] = []
    for key in _index_keys(req.name):
        for match in index.get(key, []):
            ident = (id(match.package), match.provide.name, match.provide.flags or "", match.provide.evr)
            if ident in seen:
                continue
            seen.add(ident)
            out.append(match)
    return out


def _requirement_note(req: Requirement, candidates: Sequence[ProviderMatch]) -> str:
    """Explain an unresolved capability without calling every case a missing repo."""
    shown: List[str] = []
    for match in candidates:
        if not capability_names_equal(match.provide.name, req.name):
            continue
        pev = match.provide.evr
        if pev is not None:
            ep = f"{pev[0]}:" if pev[0] and pev[0] != "0" else ""
            evr = f"{ep}{pev[1]}" + (f"-{pev[2]}" if pev[2] else "")
        else:
            evr = "unversioned"
        item = f"{match.package.nevra} provides {match.provide.name} {evr} [{match.package.repo.name}]"
        if item not in shown:
            shown.append(item)
        if len(shown) >= 3:
            break
    if shown:
        return "Providers exist, but none satisfy the requested version: " + "; ".join(shown)
    if _PYDIST_CAP_RE.fullmatch((req.name or "").strip()):
        canonical = canonical_capability_name(req.name)
        return (f"No enabled repository advertises Python virtual capability {canonical}. "
                "Python RPM dependencies are satisfied through RPM Provides (python3dist/pythonX.Ydist), "
                "not by guessing a python3-* package name. Check AppStream/CRB/EPEL or add the repository that owns the module.")
    if req.name == "python(abi)" or req.name.startswith("/usr/bin/python"):
        return ("No enabled repository provides the required Python interpreter/ABI capability. "
                "Check the target release/architecture and BaseOS/AppStream sources.")
    return "No matching provider in enabled repositories"


def should_ignore(req: Requirement) -> bool:
    return not req.name or req.name.startswith(("rpmlib(", "config(", "user(", "group("))


def evr_satisfies(provider: Requirement, req: Requirement, package: Optional[Package] = None) -> bool:
    if not req.flags or req.evr is None:
        return True
    pevr = provider.evr
    if pevr is None and package is not None and provider.name == package.name:
        pevr = package.evr
    if pevr is None:
        return False
    requested = req.evr
    flag = req.flags.upper()
    comparisons = {"EQ", "=", "GE", ">=", "GT", ">", "LE", "<=", "LT", "<"}
    if flag not in comparisons:
        return False
    # RPM treats an omitted release differently on each side. A requirement
    # without a release compares only epoch/version. A provide without a release
    # covers every release of that version, including both sides of an inequality.
    if not pevr[2] or not requested[2]:
        c = compare_evr((pevr[0], pevr[1], ""), (requested[0], requested[1], ""))
        if c == 0 and not pevr[2] and requested[2]:
            return True
    else:
        c = compare_evr(pevr, requested)
    return {"EQ": c == 0, "=": c == 0, "GE": c >= 0, ">=": c >= 0,
            "GT": c > 0, ">": c > 0, "LE": c <= 0, "<=": c <= 0,
            "LT": c < 0, "<": c < 0}[flag]


def package_satisfies(pkg: Package, req: Requirement) -> bool:
    own = Requirement(pkg.name, "EQ", pkg.epoch, pkg.version, pkg.release, "provides")
    if capability_names_equal(own.name, req.name) and evr_satisfies(own, req, pkg):
        return True
    arch_cap = _rpm_arch_capability(pkg)
    if arch_cap is not None and capability_names_equal(arch_cap.name, req.name) and evr_satisfies(arch_cap, req, pkg):
        return True
    for provide in pkg.provides:
        if capability_names_equal(provide.name, req.name) and evr_satisfies(provide, req, pkg):
            return True
    return not req.flags and req.name in pkg.files


def inventory_satisfies(inv: Optional[TargetInventory], req: Requirement) -> bool:
    if inv is None:
        return False
    seen: Set[int] = set()
    for key in _index_keys(req.name):
        for p in inv.capabilities.get(key, []):
            if id(p) in seen:
                continue
            seen.add(id(p))
            if evr_satisfies(p, req):
                return True
    return False


def _provider_rank(match: ProviderMatch, preferred_arch: str, requested_name: str) -> Tuple[int, int, int]:
    pkg = match.package
    exact_name = 0 if pkg.name == requested_name else 1
    arch_rank = 0 if pkg.arch == preferred_arch else 1 if pkg.arch == "noarch" else 2
    return (pkg.repo.priority, exact_name, arch_rank)


def choose_provider(matches: Iterable[ProviderMatch], preferred_arch: str, requested_name: str) -> Optional[ProviderMatch]:
    matches = list(matches)
    if not matches:
        return None
    best_rank = min(_provider_rank(m, preferred_arch, requested_name) for m in matches)
    candidates = [m for m in matches if _provider_rank(m, preferred_arch, requested_name) == best_rank]
    best = candidates[0]
    for m in candidates[1:]:
        c = compare_evr(m.package.evr, best.package.evr)
        if c > 0 or (c == 0 and m.package.nevra > best.package.nevra):
            best = m
    return best


def _detect_default_python_abi(packages: Sequence[Package]) -> Optional[str]:
    """Detect the distro default Python ABI from python3/python3-libs Provides.

    Generic python3dist(...) refers to the default Python 3 stack. We only use
    this ABI to create lookup aliases when the repository metadata exposes one
    form (generic or X.Y-specific) but not the other.
    """
    candidates: List[Tuple[int, Tuple[str, str, str], str]] = []
    for pkg in packages:
        if pkg.name not in {"python3", "python3-libs"}:
            continue
        for provide in pkg.provides:
            if provide.name != "python(abi)" or not provide.version:
                continue
            if not re.fullmatch(r"\d+\.\d+", provide.version):
                continue
            candidates.append((pkg.repo.priority, pkg.evr, provide.version))
    if not candidates:
        return None
    best_priority = min(x[0] for x in candidates)
    same = [x for x in candidates if x[0] == best_priority]
    best = same[0]
    for item in same[1:]:
        if compare_evr(item[1], best[1]) > 0:
            best = item
    return best[2]


def _python_default_alias(name: str, default_abi: Optional[str]) -> Optional[str]:
    if not default_abi:
        return None
    canonical = canonical_capability_name(name)
    m = _PYDIST_CAP_RE.fullmatch(canonical)
    if not m:
        return None
    prefix, dist = m.groups()
    if prefix == "python3dist":
        return f"python{default_abi}dist({dist})"
    if prefix == f"python{default_abi}dist":
        return f"python3dist({dist})"
    return None


def build_provider_index(packages: Sequence[Package], reporter: Optional[Reporter] = None) -> Dict[str, List[ProviderMatch]]:
    out: Dict[str, List[ProviderMatch]] = defaultdict(list)
    default_python_abi = _detect_default_python_abi(packages)
    if reporter and default_python_abi:
        reporter.log(f"Detected default Python ABI {default_python_abi}; enabling safe python3dist/python{default_python_abi}dist lookup aliases")
    for i, pkg in enumerate(packages, 1):
        own = Requirement(pkg.name, "EQ", pkg.epoch, pkg.version, pkg.release, "provides")
        for key in _index_keys(pkg.name):
            out[key].append(ProviderMatch(pkg, own))
        arch_cap = _rpm_arch_capability(pkg)
        if arch_cap is not None:
            for key in _index_keys(arch_cap.name):
                out[key].append(ProviderMatch(pkg, arch_cap))
        for p in pkg.provides:
            if p.name:
                keys = list(_index_keys(p.name))
                alias = _python_default_alias(p.name, default_python_abi)
                if alias:
                    keys.extend(_index_keys(alias))
                for key in dict.fromkeys(keys):
                    out[key].append(ProviderMatch(pkg, p))
        for f in pkg.files:
            if f:
                out[f].append(ProviderMatch(pkg, Requirement(f, kind="provides")))
        if reporter and i % 12000 == 0:
            reporter.log(f"Indexed {i:,}/{len(packages):,} package records")
    return out


def _find_root(name: str, version: Optional[str], index: Dict[str, List[ProviderMatch]],
               preferred_arch: str, role: Optional[str] = None,
               repo_name: Optional[str] = None, exact_arch: Optional[str] = None,
               source_scope: Optional[str] = None, repo_identity: Optional[str] = None) -> Optional[ProviderMatch]:
    """Find a root package under explicit provenance constraints.

    ``source_scope="distribution"`` means any repository in the distribution/base
    tier. This is intentionally different from ``role="dependency"``: several
    top-level repositories can share that backend role, and supplemental repositories
    may share it too. Workload/vendor roots instead use ``role``. Exact-package
    browser selections may additionally pin repository name and architecture.
    """
    matches = _provider_candidates(index, Requirement(name))
    if source_scope == "distribution":
        matches = [m for m in matches
                   if getattr(m.package.repo, "source_tier", "base") == "base"]
    if role:
        # An explicitly requested workload/vendor role is a constraint, not a hint.
        matches = [m for m in matches if m.package.repo.role == role]
    if repo_identity:
        matches = [m for m in matches if m.package.repo.source_identity == repo_identity]
    elif repo_name:
        matches = [m for m in matches if m.package.repo.name == repo_name]
    if exact_arch:
        matches = [m for m in matches if m.package.arch == exact_arch]
    if version and version != "Latest":
        matches = [m for m in matches if m.package.evr_text == version or m.package.version == version]
    return choose_provider(matches, preferred_arch, name)


_RICH_IF_RE = re.compile(r"^\((.+?)\s+if\s+(.+?)\)$")


def _rich_outer_body(text: str) -> Optional[str]:
    """Return the body of one complete parenthesized rich dependency.

    Capability names such as python3.9dist(chardet) contain parentheses of
    their own, so rich operators must be detected only at the outer expression
    depth rather than with a plain string split.
    """
    text = (text or "").strip()
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return None
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
            if depth == 0 and i != len(text) - 1:
                return None
    return text[1:-1].strip() if depth == 0 else None


def _split_top_level_keyword(body: str, keyword: str) -> List[str]:
    """Split on a whitespace-delimited rich operator at depth zero."""
    needle = f" {keyword} "
    depth = 0
    start = 0
    parts: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth < 0:
                return []
            i += 1
            continue
        if depth == 0 and body.startswith(needle, i):
            part = body[start:i].strip()
            if not part:
                return []
            parts.append(part)
            i += len(needle)
            start = i
            continue
        i += 1
    if depth != 0:
        return []
    if not parts:
        return []
    tail = body[start:].strip()
    if not tail:
        return []
    parts.append(tail)
    return parts


def _simple_requirement_from_text(text: str, kind: str = "requires") -> Optional[Requirement]:
    """Parse the simple leaf form used inside common RPM rich deps.

    Examples:
      container-selinux
      container-selinux >= 2:2.162.1
      glibc-gconv-extra(x86-64) = 2.34-275.el9_8

    This intentionally does not pretend to implement the complete RPM rich
    dependency grammar. Unsupported expressions remain fail-closed.
    """
    text = (text or "").strip()
    m = re.fullmatch(r"([^\s]+)(?:\s*(>=|<=|=|>|<)\s*([^\s]+))?", text)
    if not m:
        return None
    name, flags, evr_text = m.groups()
    if not evr_text:
        return Requirement(name=name, kind=kind)
    epoch, version, release = _parse_evr_text(evr_text)
    return Requirement(name=name, flags=flags, epoch=epoch, version=version, release=release, kind=kind)


def parse_simple_rich_if(req: Requirement) -> Optional[Tuple[Requirement, Requirement]]:
    """Return (consequence, condition) for `(A if B)` rich dependencies."""
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "if")
    if len(parts) != 2:
        return None
    consequence = _simple_requirement_from_text(parts[0], req.kind)
    condition = _simple_requirement_from_text(parts[1], "condition")
    if consequence is None or condition is None:
        return None
    return consequence, condition


def parse_simple_rich_or(req: Requirement) -> Optional[List[Requirement]]:
    """Parse the common RPM rich ``(A or B [or C])`` form.

    Simple top-level alternatives are supported. Each branch
    must still be a simple leaf requirement; nested boolean expressions remain
    fail-closed so Feathered never guesses at semantics it did not parse.
    """
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "or")
    if len(parts) < 2:
        return None
    leaves = [_simple_requirement_from_text(part, req.kind) for part in parts]
    if any(leaf is None for leaf in leaves):
        return None
    return [leaf for leaf in leaves if leaf is not None]


def parse_simple_rich_with(req: Requirement) -> Optional[List[Requirement]]:
    """Parse a simple RPM rich `with` expression into leaf requirements.

    RPM defines `with` as requiring every operand to be fulfilled by the SAME
    package. This is frequently emitted by Python dependency generators to
    encode bounded ranges, for example:

      (python3.9dist(chardet) < 5 with python3.9dist(chardet) >= 3.0.4)

    We support one or more simple leaf operands and keep the same-package
    semantics during provider selection. Nested boolean operands intentionally
    remain fail-closed.
    """
    body = _rich_outer_body(req.name)
    if body is None:
        return None
    parts = _split_top_level_keyword(body, "with")
    if len(parts) < 2:
        return None
    leaves = [_simple_requirement_from_text(part, req.kind) for part in parts]
    if any(leaf is None for leaf in leaves):
        return None
    return [leaf for leaf in leaves if leaf is not None]


def _package_satisfies_all(index: Dict[str, List[ProviderMatch]], pkg: Package, reqs: Sequence[Requirement]) -> bool:
    return all(_indexed_package_satisfies(index, pkg, req) for req in reqs)


def _inventory_package_satisfies(inv: Optional[TargetInventory], capabilities: Sequence[Requirement], req: Requirement) -> bool:
    if inv is None:
        return False
    for provide in capabilities:
        if capability_names_equal(provide.name, req.name) and evr_satisfies(provide, req):
            return True
    return False


def inventory_satisfies_same_package(inv: Optional[TargetInventory], reqs: Sequence[Requirement]) -> bool:
    """Evaluate rich `with` against one installed package, not globally."""
    if inv is None:
        return False
    for capabilities in inv.package_capabilities.values():
        if all(_inventory_package_satisfies(inv, capabilities, req) for req in reqs):
            return True
    return False


def _same_package_provider_candidates(index: Dict[str, List[ProviderMatch]], reqs: Sequence[Requirement]) -> List[ProviderMatch]:
    """Return packages that satisfy every rich `with` operand themselves."""
    if not reqs:
        return []
    seen_pkg: Set[int] = set()
    out: List[ProviderMatch] = []
    for first in _provider_candidates(index, reqs[0]):
        pkg = first.package
        ident = id(pkg)
        if ident in seen_pkg:
            continue
        seen_pkg.add(ident)
        if not _package_satisfies_all(index, pkg, reqs):
            continue
        # Keep a provider match for ranking/provenance. The package itself has
        # already been verified against every operand above.
        out.append(first)
    return out


def _rich_with_note(index: Dict[str, List[ProviderMatch]], reqs: Sequence[Requirement]) -> str:
    details: List[str] = []
    for leaf in reqs:
        candidates = _provider_candidates(index, leaf)
        satisfying = [m for m in candidates if evr_satisfies(m.provide, leaf, m.package)]
        if satisfying:
            sample = satisfying[0].package.nevra
            details.append(f"{format_requirement(leaf)} has provider {sample}")
        elif candidates:
            details.append(f"{format_requirement(leaf)} has providers, but none satisfy its version bound")
        else:
            details.append(f"{format_requirement(leaf)} has no provider")
    suffix = "; ".join(details[:4])
    return ("RPM rich 'with' requires all operands to be satisfied by one RPM, but no single enabled package satisfies the full expression"
            + (f": {suffix}" if suffix else ""))


def _rpm_arch_capability(pkg: Package) -> Optional[Requirement]:
    # RPM commonly exposes architecture-qualified package capabilities such as
    # glibc-gconv-extra(x86-64). Primary metadata normally includes them, but
    # synthesize the canonical package capability as a defensive fallback.
    arch_names = {
        "x86_64": "x86-64",
        "aarch64": "aarch64",
        "ppc64le": "ppc-64",
        "s390x": "s390-64",
    }
    suffix = arch_names.get(pkg.arch)
    if not suffix:
        return None
    return Requirement(f"{pkg.name}({suffix})", "EQ", pkg.epoch, pkg.version, pkg.release, "provides")


def format_requirement(req: Requirement) -> str:
    if req.flags and req.evr:
        epoch, version, release = req.evr
        rel = f"-{release}" if release else ""
        ep = f"{epoch}:" if epoch and epoch != "0" else ""
        return f"{req.name} {req.flags} {ep}{version}{rel}"
    return req.name


def _indexed_package_satisfies(index: Dict[str, List[ProviderMatch]], pkg: Package, req: Requirement) -> bool:
    if package_satisfies(pkg, req):
        return True
    for match in _provider_candidates(index, req):
        if match.package is pkg and evr_satisfies(match.provide, req, pkg):
            return True
    return False


def _selected_or_pending_satisfies(packages: Iterable[Package], req: Requirement,
                                    index: Optional[Dict[str, List[ProviderMatch]]] = None) -> bool:
    if index is None:
        return any(package_satisfies(pkg, req) for pkg in packages)
    return any(_indexed_package_satisfies(index, pkg, req) for pkg in packages)


def _constraint_key(req: Requirement) -> Tuple[object, ...]:
    return (canonical_capability_name(req.name), req.flags, req.evr)


def _satisfies_constraints(index: Dict[str, List[ProviderMatch]], pkg: Package,
                           constraints: Sequence[Requirement]) -> bool:
    return all(_indexed_package_satisfies(index, pkg, c) for c in constraints)


def resolve(root_requests: Sequence[RootInput], packages: Sequence[Package],
            preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter) -> ResolutionResult:
    from transaction_model import resolve_transaction
    return resolve_transaction(_resolve_once, root_requests, packages, preferred_arch,
                               options, reporter, 'rpm')


def _resolve_once(root_requests: Sequence[Tuple], packages: Sequence[Package],
            preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter,
            *, build_provider_index_fn=None) -> ResolutionResult:
    """Resolve package roots and their dependency closure.

    Runs the closure repeatedly, accumulating *version floors*: constraints
    that a previously selected package failed to satisfy. A single greedy pass
    can pick package X-1.0 for an unversioned requirement and only later meet
    a `Requires: X >= 2.0`; rather than declaring that unresolvable, the next
    pass carries `X >= 2.0` forward and selects a candidate that satisfies both
    requirements. Resolution stops when a pass discovers no new constraints, or
    when a constraint set is genuinely unsatisfiable (reported as unresolved).
    """
    constraints: Dict[str, List[Requirement]] = defaultdict(list)
    # Providers proven unworkable for a capability, so another can be tried.
    rejected: Set[Tuple[str, str]] = set()
    seen_keys: Set[Tuple[object, ...]] = set()
    # The loop below always runs at least once, so `result` is bound before use.
    result: ResolutionResult = ResolutionResult(selected=[], unresolved=[], roots=[])
    for attempt in range(1, max(1, options.max_resolution_passes) + 1):
        reporter.check_cancel()
        result, discovered = _resolve_pass(
            root_requests, packages, preferred_arch, options, reporter, constraints, rejected,
            build_provider_index_fn=build_provider_index_fn,
        )
        fresh = [(name, req) for name, req in discovered
                 if (name, _constraint_key(req)) not in seen_keys]
        if not fresh:
            if not result.unresolved and not result.conflicts:
                return result
            conflict_only = bool(result.conflicts) and not result.unresolved
            if not _reject_failed_provider(
                result,
                rejected,
                reporter,
                conflict_only=conflict_only,
            ):
                return result
            # Constraints are derived from the abandoned branch's selections,
            # so they are discarded with it and re-derived on the next pass.
            constraints.clear()
            seen_keys.clear()
            continue
        for name, req in fresh:
            seen_keys.add((name, _constraint_key(req)))
            constraints[name].append(req)
            reporter.log(f"Re-resolving with version floor {name} {format_requirement(req)} "
                         f"(pass {attempt + 1})")
    reporter.warn("Dependency resolution hit the pass limit; the reported closure may still "
                  "contain version conflicts. Review conflicts.txt before installing.")
    return result


def _reject_failed_provider(
    result,
    rejected: Set[Tuple[str, str]],
    reporter: Reporter,
    *,
    conflict_only: bool = False,
) -> bool:
    """Blame a failed closure on the provider choice that introduced it."""
    conflict_participants = set(getattr(result, "conflict_participants", ()))
    for capability, chosen, others in reversed(getattr(result, "provider_choices", [])):
        if conflict_only and chosen not in conflict_participants:
            continue
        if (capability, chosen) in rejected:
            continue
        remaining = [o for o in others if (capability, o) not in rejected]
        if not remaining:
            continue
        rejected.add((capability, chosen))
        reason = "a conflicting closure" if conflict_only else "an unresolvable closure"
        reporter.log(f"Provider '{chosen}' for '{capability}' led to {reason}; "
                     f"trying {' or '.join(remaining)} instead")
        return True
    return False


def _resolve_pass(root_requests: Sequence[Tuple], packages: Sequence[Package],
                  preferred_arch: str, options: BuildOptions[TargetInventory], reporter: Reporter,
                  constraints: Dict[str, List[Requirement]],
                  rejected: Optional[Set[Tuple[str, str]]] = None,
                  *, build_provider_index_fn=None
                  ) -> Tuple[ResolutionResult, List[Tuple[str, Requirement]]]:
    reporter.log("Building provider index...")
    index_builder = build_provider_index_fn or build_provider_index
    index = index_builder(packages, reporter)
    # Constraints are read-only in this pass; newly discovered floors are
    # returned separately. Build the filtered universe only if a root needs it,
    # then reuse it for the other roots. A new pass always starts fresh, including
    # after provider rejection. None distinguishes 'not built' from an empty index.
    constrained_index: Optional[Dict[str, List[ProviderMatch]]] = None
    # Constraints discovered during this pass, fed back into the next one.
    discovered: List[Tuple[str, Requirement]] = []
    rejected_set = rejected if rejected is not None else set()
    provider_choices: List[Tuple[str, str, List[str]]] = []

    def pick(matches, requested_name: str):
        """Choose a provider honouring version floors and past rejections."""
        matches = list(matches)
        filtered = [m for m in matches
                    if _satisfies_constraints(index, m.package, constraints.get(m.package.name, ()))]
        allowed = [m for m in filtered
                   if (requested_name, m.package.name) not in rejected_set]
        chosen = choose_provider(allowed or filtered or [], preferred_arch, requested_name)
        if chosen is not None:
            alternatives = sorted({m.package.name for m in filtered} - {chosen.package.name})
            if alternatives:
                provider_choices.append((requested_name, chosen.package.name, alternatives))
        return chosen
    roots: List[Package] = []
    root_names: Set[str] = set()
    # Declared before the root loop: missing roots are now recorded rather than
    # aborting, so the loop needs somewhere to record them.
    unresolved: List[Requirement] = []
    unresolved_notes: Dict[str, str] = {}
    skipped: Set[str] = set()
    roots_requested = bool(root_requests)
    for request in root_requests:
        if len(request) < 3:
            raise RuntimeError(f"Invalid root request: {request!r}")
        name, version, role = request[:3]
        repo_name = request[3] if len(request) >= 4 else None
        exact_arch = request[4] if len(request) >= 5 else None
        source_scope = request[5] if len(request) >= 6 else None
        repo_identity = request[6] if len(request) >= 7 else None
        match = _find_root(name, version, index, preferred_arch, role, repo_name, exact_arch, source_scope, repo_identity)
        if match and not _satisfies_constraints(index, match.package, constraints.get(match.package.name, ())):
            if constrained_index is None:
                constrained_index = index_builder([
                    p for p in packages if _satisfies_constraints(index, p, constraints.get(p.name, ()))], reporter)
            match = _find_root(name, version, constrained_index, preferred_arch, role, repo_name,
                               exact_arch, source_scope, repo_identity) or match
        if not match:
            # Report every missing root together rather than aborting on the
            # first. A preset lists tools that span several repositories, and
            # dying on one absent package hid the other 29 that were fine.
            detail = f"No provider found for '{name}'"
            if version:
                detail += f" version '{version}'"
            if repo_name:
                detail += f" in repository '{repo_name}'"
            if exact_arch:
                detail += f" for architecture '{exact_arch}'"
            if source_scope == "distribution":
                detail += " in the distribution repository set"
            if name in options.optional_roots:
                skipped.add(f"{name} (optional; not offered by the configured sources)")
                reporter.log(f"Skipping optional package '{name}': not present in any enabled source")
                continue
            requirement = Requirement(name, None, kind="root")
            unresolved.append(requirement)
            unresolved_notes[format_requirement(requirement)] = (
                detail + ". Enable a repository that carries it (EPEL and CRB/PowerTools hold "
                "many tools absent from BaseOS/AppStream), or remove it from the selection.")
            reporter.log("UNRESOLVED root: " + detail)
            continue
        roots.append(match.package)
        root_names.add(match.package.name)
        reporter.log(f"Root: {match.package.nevra} [{match.package.repo.name}]")

    if roots_requested and not roots:
        raise RuntimeError(
            "None of the selected packages were found in any enabled source. This usually means "
            "the sources are for a different release or architecture than the target, or that no "
            "source carrying operating-system packages is enabled.")
    if not options.include_dependencies:
        unique = {p.name: p for p in roots}
        return ResolutionResult(selected=sorted(unique.values(), key=lambda p: p.name), unresolved=unresolved, roots=roots,
                                unresolved_notes=unresolved_notes, skipped_installed=sorted(skipped),
                                reasons={p.nevra: "requested package" for p in unique.values()}), []

    selected_by_name: Dict[str, Package] = {}
    pending_by_name: Dict[str, Package] = {p.name: p for p in roots}
    dependency_parent: Dict[str, str] = {}
    queue = deque(roots)
    unresolved_keys: Set[Tuple[object, ...]] = set()
    reasons: Dict[str, str] = {p.nevra: "requested package" for p in roots}
    installed_satisfied: Set[str] = set()

    while queue:
        reporter.check_cancel()
        pkg = queue.popleft()
        pending_by_name.pop(pkg.name, None)
        existing = selected_by_name.get(pkg.name)
        if existing is not None:
            if existing.nevra != pkg.nevra:
                reporter.log(f"Keeping {existing.nevra}; ignoring alternate {pkg.nevra}")
            continue
        selected_by_name[pkg.name] = pkg

        reqs = list(pkg.requires)
        if options.include_recommends:
            reqs.extend(pkg.recommends)
        for req in reqs:
            if should_ignore(req):
                continue
            reason_override = None
            if req.name.startswith("("):
                rich_with = parse_simple_rich_with(req)
                if rich_with is not None:
                    all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                    if any(_package_satisfies_all(index, current, rich_with) for current in all_current):
                        continue
                    if inventory_satisfies_same_package(options.target_inventory, rich_with):
                        installed_satisfied.add(format_requirement(req))
                        continue
                    same_pkg_candidates = _same_package_provider_candidates(index, rich_with)
                    provider = pick(same_pkg_candidates, canonical_capability_name(rich_with[0].name))
                    if provider is None:
                        key = (req.name, req.flags, req.evr, "rich-with")
                        if key not in unresolved_keys:
                            unresolved_keys.add(key); unresolved.append(req)
                            unresolved_notes[format_requirement(req)] = _rich_with_note(index, rich_with)
                            reporter.log(f"UNRESOLVED rich WITH {format_requirement(req)} required by {pkg.nevra}: {unresolved_notes[format_requirement(req)]}")
                        continue
                    chosen = provider.package
                    already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
                    if already is not None:
                        if not _package_satisfies_all(index, already, rich_with):
                            for operand in rich_with:
                                discovered.append((chosen.name, operand))
                            key = (req.name, req.flags, req.evr, "rich-with-version-conflict")
                            if key not in unresolved_keys:
                                unresolved_keys.add(key); unresolved.append(req)
                                unresolved_notes[format_requirement(req)] = f"Selected package {already.nevra} does not satisfy every operand of this RPM rich 'with' expression"
                                reporter.log(f"UNRESOLVED rich WITH version constraint {format_requirement(req)}; selected {already.nevra}")
                        continue
                    pending_by_name[chosen.name] = chosen
                    dependency_parent.setdefault(chosen.name, pkg.name)
                    queue.append(chosen)
                    reasons.setdefault(chosen.nevra, f"required by {pkg.name}: {format_requirement(req)}")
                    reporter.log(f"RICH WITH -> {chosen.nevra} satisfies all operands of {format_requirement(req)}")
                    continue

                rich_or = parse_simple_rich_or(req)
                if rich_or is not None:
                    all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                    if any(_selected_or_pending_satisfies(all_current, branch, index)
                           for branch in rich_or):
                        continue
                    if any(inventory_satisfies(options.target_inventory, branch) for branch in rich_or):
                        installed_satisfied.add(format_requirement(req))
                        continue
                    branch_matches: List[ProviderMatch] = []
                    for branch in rich_or:
                        branch_matches.extend(
                            match for match in _provider_candidates(index, branch)
                            if evr_satisfies(match.provide, branch, match.package))
                    # De-duplicate identical packages that happen to satisfy more
                    # than one branch while preserving provider-ranking input.
                    seen_nevra = set()
                    candidates = []
                    for match in branch_matches:
                        if match.package.nevra not in seen_nevra:
                            seen_nevra.add(match.package.nevra)
                            candidates.append(match)
                    provider = pick(candidates, req.name)
                    if provider is None:
                        key = (req.name, req.flags, req.evr, "rich-or")
                        if key not in unresolved_keys:
                            unresolved_keys.add(key); unresolved.append(req)
                            branch_text = " or ".join(format_requirement(branch) for branch in rich_or)
                            unresolved_notes[format_requirement(req)] = (
                                f"No enabled package satisfies any branch of this RPM rich dependency: {branch_text}")
                            reporter.log(f"UNRESOLVED rich OR {format_requirement(req)} required by {pkg.nevra}")
                        continue
                    chosen = provider.package
                    already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
                    if already is not None:
                        # The same package name may already have been selected at
                        # a version that does not satisfy the branch represented
                        # by this provider; let the ordinary version-floor pass
                        # discover a correction where possible.
                        matching_branch = next((branch for branch in rich_or
                                                if _indexed_package_satisfies(index, already, branch)), None)
                        if matching_branch is None:
                            branch = next((branch for branch in rich_or
                                           if _indexed_package_satisfies(index, chosen, branch)), rich_or[0])
                            discovered.append((chosen.name, branch))
                            if req not in unresolved:
                                unresolved.append(req)
                                unresolved_notes[format_requirement(req)] = "Selected provider does not satisfy this rich OR dependency"
                        continue
                    pending_by_name[chosen.name] = chosen
                    dependency_parent.setdefault(chosen.name, pkg.name)
                    queue.append(chosen)
                    reasons.setdefault(chosen.nevra,
                                       f"required by {pkg.name}: {format_requirement(req)}")
                    reporter.log(f"RICH OR -> {chosen.nevra} satisfies {format_requirement(req)}")
                    continue

                parsed_rich = parse_simple_rich_if(req)
                if parsed_rich is None:
                    key = (req.name, req.flags, req.evr, "rich")
                    if key not in unresolved_keys:
                        unresolved_keys.add(key); unresolved.append(req)
                        unresolved_notes[format_requirement(req)] = "Unsupported/ambiguous RPM rich dependency expression"
                        reporter.log(f"UNRESOLVED unsupported rich dependency {format_requirement(req)}")
                    continue
                consequence, condition = parsed_rich
                all_current = list(selected_by_name.values()) + list(pending_by_name.values())
                condition_true = (_selected_or_pending_satisfies(all_current + list(getattr(options, "_transaction_candidates", [])), condition, index) or
                                  inventory_satisfies(options.target_inventory, condition))
                if options.target_inventory is not None and not condition_true:
                    # With a concrete target inventory, honor the `if` and do
                    # not collect the consequence when its condition is absent.
                    reporter.log(f"SKIP conditional dependency {format_requirement(consequence)}; target does not satisfy {format_requirement(condition)}")
                    continue
                # Without a target inventory we cannot know which standard OS
                # capabilities are already installed. For an offline COMPLETE
                # bundle, conservatively include the consequence so the bundle
                # works when the condition is present on the destination.
                req = consequence
                reason_override = f"conditional dependency of {pkg.name}: {format_requirement(consequence)} if {format_requirement(condition)}"
                reporter.log(f"RICH IF -> resolving {format_requirement(consequence)} (condition: {format_requirement(condition)})")
            all_current = list(selected_by_name.values()) + list(pending_by_name.values())
            if _selected_or_pending_satisfies(all_current, req, index):
                continue
            if inventory_satisfies(options.target_inventory, req):
                installed_satisfied.add(format_requirement(req))
                continue
            all_candidates = _provider_candidates(index, req)
            candidates = [m for m in all_candidates if evr_satisfies(m.provide, req, m.package)]
            provider = pick(candidates, canonical_capability_name(req.name))
            if provider is None:
                key = (canonical_capability_name(req.name), req.flags, req.evr, req.kind)
                if key not in unresolved_keys:
                    unresolved_keys.add(key); unresolved.append(req)
                    unresolved_notes[format_requirement(req)] = _requirement_note(req, all_candidates)
                    reporter.log(f"UNRESOLVED {format_requirement(req)} required by {pkg.nevra}: {unresolved_notes[format_requirement(req)]}")
                continue
            chosen = provider.package
            already = selected_by_name.get(chosen.name) or pending_by_name.get(chosen.name)
            if already is not None:
                if not _indexed_package_satisfies(index, already, req):
                    # Ask for another pass pinned to this constraint; if no
                    # candidate can satisfy every accumulated floor, the next
                    # pass reports it as unresolved and the build stays blocked.
                    discovered.append((chosen.name, req))
                    key = (req.name, req.flags, req.evr, "version-conflict")
                    if key not in unresolved_keys:
                        unresolved_keys.add(key); unresolved.append(req)
                        unresolved_notes[format_requirement(req)] = (
                            f"Selected package {already.nevra} does not satisfy this version constraint")
                        reporter.log(f"VERSION CONFLICT {format_requirement(req)}; selected {already.nevra}")
                continue
            pending_by_name[chosen.name] = chosen
            dependency_parent.setdefault(chosen.name, pkg.name)
            queue.append(chosen)
            reasons.setdefault(chosen.nevra, reason_override or f"required by {pkg.name}: {format_requirement(req)}")

    selected = sorted(selected_by_name.values(), key=lambda p: (p.repo.priority, p.name, p.nevra))

    conflicts: List[str] = []
    conflict_seen: Set[str] = set()
    conflict_participants: Set[str] = set()

    def mark_conflict_branch(package_name: str) -> None:
        """Mark a conflicting package and every dependency ancestor that selected it."""
        seen: Set[str] = set()
        current = package_name
        while current and current not in seen:
            seen.add(current)
            conflict_participants.add(current)
            current = dependency_parent.get(current, "")

    for pkg in selected:
        for req in pkg.conflicts:
            if should_ignore(req):
                continue
            for other in selected:
                if other.name == pkg.name:
                    continue
                if package_satisfies(other, req):
                    text = f"{pkg.nevra} conflicts with {other.nevra} via {format_requirement(req)}"
                    if text not in conflict_seen:
                        conflict_seen.add(text); conflicts.append(text)
                    mark_conflict_branch(pkg.name)
                    mark_conflict_branch(other.name)
            if inventory_satisfies(options.target_inventory, req):
                text = f"{pkg.nevra} conflicts with an installed target capability: {format_requirement(req)}"
                if text not in conflict_seen:
                    conflict_seen.add(text); conflicts.append(text)
                mark_conflict_branch(pkg.name)

    # `skipped` was seeded above with optional roots that were not offered by
    # any source; keep those entries rather than starting a fresh list.
    # Target-aware mode uses capabilities during resolution. Exact package
    # matches are reported for visibility, but roots are never omitted.
    if options.target_inventory:
        for pkg in selected:
            if pkg.name not in root_names and pkg.nevra in options.target_inventory.nevras:
                skipped.add(pkg.nevra)
        if skipped:
            selected = [p for p in selected if p.nevra not in set(skipped)]

    outcome = ResolutionResult(
        selected=selected, unresolved=unresolved, roots=roots,
        skipped_installed=sorted(skipped), conflicts=conflicts,
        reasons=reasons, installed_satisfied=sorted(installed_satisfied),
        unresolved_notes=unresolved_notes,
    )
    outcome.provider_choices = provider_choices
    outcome.conflict_participants = sorted(conflict_participants)
    return outcome, discovered


def package_versions(packages: Sequence[Package], name: str, role: Optional[str], preferred_arch: str) -> List[str]:
    vals = [p for p in packages if p.name == name and (not role or p.repo.role == role)
            and p.arch in {preferred_arch, "noarch"}]
    vals.sort(key=cmp_to_key(lambda a, b: -compare_evr(a.evr, b.evr)))
    seen: Set[str] = set(); out: List[str] = []
    for p in vals:
        if p.evr_text not in seen:
            seen.add(p.evr_text); out.append(p.evr_text)
    return out


def _parse_evr_text(text: str) -> Tuple[str, str, str]:
    text = (text or "").strip()
    if not text or text == "(none)":
        return ("0", "", "")
    epoch = "0"
    if ":" in text:
        maybe_epoch, rest = text.split(":", 1)
        if maybe_epoch.isdigit():
            epoch, text = maybe_epoch, rest
    if "-" in text:
        version, release = text.rsplit("-", 1)
    else:
        version, release = text, ""
    return epoch, version, release
