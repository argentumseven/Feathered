"""Run Feathered's regression corpus in isolated pytest batches.

Production validation first collects the exact node set, then runs it in fresh
subprocess batches while preserving each pytest return code. Batching limits
cross-test process state and makes failures easier to attribute; no test is
omitted. The earlier Linux "batch-boundary stall" was traced to retry backoff
on the optional APT InRelease probe rather than to a proven pytest/Tk finalizer
deadlock.
"""
from __future__ import annotations
import os
import re
import subprocess
import sys
import shutil

BATCH_SIZE = 20


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")
    return env


def _pytest_command(*args: str) -> list[str]:
    command = [sys.executable, "-m", "pytest", *args]
    # Windows production builders run directly. Linux development/CI hosts can
    # opt into a virtual X server for Tk slices without changing release logic.
    if os.name != "nt" and os.environ.get("FEATHERED_USE_XVFB") == "1" and shutil.which("xvfb-run"):
        return ["xvfb-run", "-a", *command]
    return command


_COLLECTED_RE = re.compile(r"^(\d+) tests? collected")


def _collect() -> list[str]:
    """Return the exact node set, reconciled against pytest's own count.

    Scraping stdout is the weak link in this gate: if the parse silently drops
    node IDs, the batches still pass and the gate still reports success while
    having run a subset of the corpus. pytest prints its own collected total,
    so compare against it and refuse to proceed on any mismatch.
    """
    proc = subprocess.run(
        _pytest_command("--collect-only", "-q"),
        text=True, capture_output=True, env=_env()
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)

    nodes: list[str] = []
    reported: int | None = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        match = _COLLECTED_RE.match(stripped)
        if match:
            reported = int(match.group(1))
            continue
        if "::" in stripped and not stripped.startswith(("=", "<", "ERROR", "WARNING")):
            nodes.append(stripped)

    if not nodes:
        raise SystemExit("release gate collected zero tests")
    if reported is None:
        raise SystemExit(
            "release gate could not read pytest's collected-test count; refusing to run "
            "a gate whose node set cannot be reconciled"
        )
    if reported != len(nodes):
        raise SystemExit(
            f"release gate parsed {len(nodes)} node IDs but pytest reported {reported} "
            "collected tests; refusing to run an incomplete gate"
        )
    if len(set(nodes)) != len(nodes):
        raise SystemExit("release gate parsed duplicate node IDs; refusing to run")
    return nodes


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(arg in {"-h", "--help"} for arg in argv):
        print("usage: release_test_runner.py [-h|--help]")
        print("Collect the complete pytest corpus and run it in isolated fail-closed batches.")
        return 0
    if argv:
        print(f"release_test_runner.py: unrecognized argument: {argv[0]}", file=sys.stderr)
        return 2
    nodes = _collect()
    print(f"Feathered release test gate: {len(nodes)} tests collected; isolated batches of {BATCH_SIZE}.", flush=True)
    executed = 0
    for start in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[start:start + BATCH_SIZE]
        number = start // BATCH_SIZE + 1
        print(f"\n--- batch {number}: tests {start + 1}-{start + len(batch)} ---", flush=True)
        code = subprocess.call(_pytest_command("-p", "release_pytest_exit", "-q", *batch), env=_env())
        if code:
            print(f"Release gate FAILED in batch {number} with pytest status {code}.", flush=True)
            return code
        executed += len(batch)
    if executed != len(nodes):
        print(f"Release gate FAILED: executed {executed} of {len(nodes)} collected tests.", flush=True)
        return 1
    print(f"\nFeathered release test gate PASSED: {executed} tests.", flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
