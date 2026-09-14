# Provider-index and core extraction evidence

The authoritative complete gate is ../provider-index-gate/SUMMARY.md.

profile-before/after.json contain cProfile summaries and individual index timings.
benchmark-*.json retain three unprofiled runs of each tree; benchmark-summary.json
and benchmark.txt give the comparison. Result equality covers the fields recorded
by profile_providers.py; it is not a native package-manager acceptance test.

To reproduce in a dependency-equipped Python environment:

    python profile_providers.py SOURCE_TREE REPORT_JSON 12000
    python benchmark_providers.py UPDATED_TREE BASELINE_TREE

The second command writes reports alongside the benchmark scripts. It disables
profiling for timing and compares all recorded result fields and non-index logs.
Use a separate writable directory when preserving an earlier evidence set.
The baseline source is the previous complete signing-digests archive; the
baseline-source-manifest.json here records its source files.

regressions-before.txt captured two excess-rebuild failures and eleven passing
cases before the optimization. The subsequently added empty-filter snapshot was
captured by importing core from the untouched baseline copy. No prior golden was
regenerated to fit changed behavior. hashing-before.txt records the sixteen core
hash entry-point contracts before extraction. focused-after.txt covers 113 cases
including resolver, hashing, transaction and original bundle-output fixtures.

mypy.txt covers 56 roots; contracts.txt checks the existing positive/negative host
capabilities. The new module is also included in the full gate's Tk-blocked imports.
archive-check.txt records ZIP extraction/import checks, not native Windows execution.
