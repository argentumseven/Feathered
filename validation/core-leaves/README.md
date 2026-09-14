# Core leaf extraction evidence

The complete result is ../core-leaves-gate/SUMMARY.md. Focused test counts here
are independent views and must not be added to the gate total.

contracts-before.txt: 55 cases run with core imported from the untouched previous
source copy. contracts-after.txt: 85 updated cases including those contracts,
existing provider snapshots and original bundle-output goldens.
unchanged-corpus.json records the byte-identical original large test file and
provider/bundle snapshots. core_leaf_contracts.json in tests/fixtures was captured
before the extraction; it was not regenerated to fit changed behavior.

The benchmark compares the previous provider-index delivery with this batch.
Run profile_providers.py SOURCE_TREE REPORT_JSON [CATALOG_SIZE] for profiling;
run benchmark_providers.py UPDATED_TREE BASELINE_TREE for three unprofiled runs
per tree, writing reports alongside these scripts. Use a disposable writable
copy of the scripts when retaining this evidence set. No network is involved.
The first trial's summary/log are retained separately; final raw runs are the
benchmark-before/after JSON files. Equality covers the fields explicitly recorded
by the benchmark, not every possible package or native package-manager outcome.

mypy.txt covers 59 roots. contracts.txt records the existing host-contract gate.
archive-check.txt describes extraction/import checks, not a Windows-native run.
The final Ruff check includes the copied evidence scripts; the older profiling
helper's closure lint finding has been corrected with explicit default bindings.
