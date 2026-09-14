# Evidence for signing navigation and digest reuse

The complete result is ../signing-digest-gate/SUMMARY.md. These focused logs
are supplementary and do not replace the full gate.

navigation-before.txt: two failures and one pass on the starting tree.
navigation-after.txt: all six cases executed successfully after repair.
An intervening display-harness failure yielded six skips; it was fixed and
rerun, not accepted as evidence of working GUI behavior.

digest-characterization.txt: original output/event goldens and failure tests.
digest-tests.txt: 16 ledger/invalidation/sealing cases plus all 15 goldens.
benchmark-results.json: raw six-run results, including complete normalized
output file hashes. baseline-source-manifest.json identifies the prior source.
benchmark.py: standalone reproduction, with a guard requiring a new disposable
work directory. run_benchmark.py records the local alternating-run orchestration;
its workspace paths need adaptation elsewhere. Fixture payloads are synthetic,
not native packages; build timing includes actual writer operations.

Source-manifest and final gate checks bind the delivered source. Evidence files
are intentionally outside source-manifest scope. The complete ZIP is separately
checked for CRC, uniqueness, source integrity and extracted imports.
