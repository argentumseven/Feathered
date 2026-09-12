# Discovery ownership and cache recovery

Repository availability distinguishes successful checks, authoritative HTTP
404/410 absence, and indeterminate failures (including throttling and outages).
A partial refresh keeps unconfirmed cached versions with their older observation
time, adds successful discoveries, and removes only confirmed absences. Optional
per-minor checks in the cache carry their own timestamp and reason; existing
caches without those fields remain readable. Typed minors and exact package pins
are not changed by refresh.

Release knowledge has one GUI refresh owner shared by package families. Its
completion carries a request generation. The persistent refresh API serializes
threads and holds an OS advisory lock from cache reconciliation through atomic
replacement. Separate application instances sharing a cache do not wait for a
network refresh: a busy instance retains cached data, reports an incomplete
refresh, and uses the existing bounded retry schedule. OS locks release on exit;
the small lock file is intentionally retained. This policy assumes a local
filesystem supporting OS advisory locks, as used by the application's state
folder. Direct `save()` is a serialization helper; production refresh writes go
through `refresh()`.

Refresh reconciles the newest recorded source observations and retains historical
release records. Policy-change flags are sticky across refreshes and restarts;
network data cannot clear them. Downloaded policy prose remains evidence for
human review and never replaces executable compatibility rules.

## UI processing budget

The event pump dequeues at most 100 events per callback, coalesces only adjacent
progress updates with the same kind and label, then yields to Tk. A nonempty
queue resumes after 1 ms; an idle queue is polled after 100 ms. Decision events,
acknowledgements, terminal results, and ordering barriers are never coalesced.
Control re-locking remains after each dispatched handler.

Kubernetes knowledge, repository probes, and package-build queries now use a
small typed completion envelope and a shared coordinator: two active jobs,
one pending replacement per named operation, and at most eight operation names.
Inputs are captured before dispatch. New patch requests cancel obsolete work
cooperatively through the existing Reporter; both request generations and the
existing full context comparison guard application of results. Destroying the
root cancels active and pending queries. Transports without cancellation support
finish their bounded request but their obsolete completion is ignored. Legacy
tuple consumers can still unpack completion payloads.

This is an incremental migration. Builds retain their existing operation lease;
distribution refresh and other older query producers retain their existing
context guards and are serviced by the bounded event pump. They are not claimed
to have migrated to the new query coordinator in this batch.
