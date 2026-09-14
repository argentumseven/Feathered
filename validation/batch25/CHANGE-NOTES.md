# Items 2-5 implementation batch

Repository provenance stays visible. Display redaction preserves scheme, host,
port, path and ordinary query fields, hiding authentication secrets. Execution
receives the original credential-bearing source URL and source identity.

- **12f8619 - item 2:** CLI show, dry-run and failure diagnostics use existing
  credential redactors. README explains credential-bearing saved URLs accurately.
- **bc2595a - item 3:** recognized spec fields are decoded explicitly; malformed
  booleans, shapes and versions report field paths. Direct preparation inputs
  share validation. This deliberately rejects previously accepted malformed
  input. Valid v1/v2 migrations, v3 round trips and incomplete drafts remain.
- **83fb07b - item 4a:** available/absent/indeterminate probes, partial-outage
  retention, per-check evidence and atomic observation writes.
- **f542ea2 - item 4b:** shared knowledge refresh owner, generations, persistent
  reconciliation and OS writer lease. Sticky policy-change flags survive restart;
  downloaded prose never becomes executable compatibility policy.
- **217e02d - item 5:** 100-event GUI budget, adjacent-progress coalescing, typed
  query completions and bounded replaceable Kubernetes queries. Existing build
  control locking and full selection-context checks remain. Other query producers
  keep their existing guards; their coordinator migration is deferred.

The final full-corpus results and source identity are recorded by the release
runner in ../release-gate/SUMMARY.md and summary.json. Focused before/after evidence
is included here. Development-only display setup failures and an accidentally
broad mypy configuration were corrected before the final gate; they are not
counted as passes. The early item-4 focused non-GUI run intentionally excluded
its then-pending stale-writer regression; the later 132-test GUI run included it,
and the final release gate includes the entire corpus without deselection.

This batch uses Linux/Python 3.12 with a real Tk virtual display. It does not
establish Windows launcher execution, signed/frozen builds, live repository
availability, or remote GitHub CI results. The complete ZIP includes the app and
all source modules; it is not a signed Windows binary. Local commits and their
patch series are included for review and rollback. No remote PR or merge is
claimed.

Remaining instruction scope: items 6-9 (typed build boundaries, measured backend
deduplication, efficiency, and core extraction). Those require their own behavior
fixtures and are not silently bundled into this change.
