# Recorded release-test outcomes

Status: failed

Commit: 405c2d077257fb5151f706e66d6ef296acc87ed0
Tracked source edits present: False
Source-tree SHA-256: 031fbb1df3fd39e9e2c296b4e647be0981797f25ced6f08b515bb716c061b04b
Python: 3.12.14; pytest: 9.1.1
Environment: Linux-6.18.44-x86_64-with-glibc2.39
Finished: 2026-09-13T11:54:34.094988+00:00

Collected: 1381

| Outcome | Count |
|---|---|
| failed | 1 |
| passed | 599 |

Permitted Windows capability skips: 0 (never counted as passes).

Per-test phases, skip reasons and subprocess termination records are in summary.json and batch reports.

Failure: Batch 30 failed: subprocess status 1; unexpected outcomes {'tests/test_assurance_semantics.py::test_both_provenance_writers_emit_the_plain_text_legend': 'failed'}
