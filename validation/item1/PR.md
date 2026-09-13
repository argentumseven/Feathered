Make the release gate reconcile actual pytest outcomes

The previous gate accepted skipped batches as executed and called os.\_exit before
pytest could print assertion diagnostics or run the required-test finish hook.

This PR replaces forced exit with structured setup/call/teardown evidence and
parent reconciliation. Collection skips, deselection, xfail/xpass, crashes,
timeouts, missing/stale reports and incomplete phase sequences fail the gate.
Batch selections use JSON and argument files so long IDs do not exceed argv limits.

The runner retains normal pytest output and records commit, source-tree digest,
environment and subprocess termination. Windows capability skips are limited by
file and reason, counted separately, and covered by the required Linux full-corpus
job. CI retains reports even when the gate fails. VALIDATION.md points to generated
results rather than a stale handwritten count.

Validation:

* Three regression tests fail against unchanged 7222d24 before the repair.
* New recorder on unchanged application baseline: 1,255 passed, zero skips.
* Repaired commit 7b745fb7186de5885d9b63f221acc3deef08da5f: 1,290 passed, zero skips.
* 35 focused gate tests passed; mypy 45 roots, Ruff and 39 host rejection cases passed.
* Generated installer syntax passed for RPM, vendor-signed RPM, APT and Arch.

Linux/Tk/Xvfb, Python 3.12.14, pytest 9.1.1. Windows execution, remote CI,
frozen/signing/gpgv, native oracle runs and live upstream refresh were not run.
No resolver, package publication, transport or application workflow changes.

This is item 1 only. The implementation instruction requires this PR to merge
before item 2 starts. Revert this one commit to roll it back.

The complete source archive includes item1.patch for git am on a clean branch
based on 7222d24. Do not apply that patch to the already-updated extracted source.

Remote status: no PR has been opened or merged.

