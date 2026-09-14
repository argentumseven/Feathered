# Shared bundle writer evidence

Final result: 1,390 passed; no skipped, deselected, xfailed or xpassed tests.
The authoritative per-test records and source identity are in
`../bundle-refactor-verified/summary.json`.

35 additional test cases extend the prior 1,355-test build-boundary tree.
The 15 golden cases were captured before production extraction. Three Arch
callback-failure cases failed before their fix (reporter-before.txt); all nine
family/callback cases passed afterward. Focused output and failure checks passed.
Mypy passed across 50 roots; all 47 malformed host capability probes were rejected.
Ruff, generated installer shell syntax and all 225 source hashes passed.

Failed intermediate gate attempts are retained alongside this directory:
- bundle-delegation-gate: local Xvfb keyboard setup failure, corrected externally.
- bundle-delegation-gate-rerun: obsolete source-text assurance assertion, replaced
  by checks of the real files emitted by both public provenance writers.
- bundle-refactor-gate-first: obsolete source-text waiver assertion, replaced by
  actual waiver-file checks through all three public bundle writers.
- bundle-refactor-gate: stale invocation evidence, rejected by the release runner;
  the final run uses the separate bundle-refactor-verified directory.

The patches apply in order to aa3a685f4725f7b12c2d96be252a77c94097ad12.
The delivered ZIP is a complete application source tree, not a patches-only build.
Windows launchers/frozen binaries were not executed locally. The upstream Windows
bootstrap issue described in BUILD-BOUNDARY.md remains outside this batch.
