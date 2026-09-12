Feathered mirror catalogs

These JSON files are the local, user-editable source for exact-mirror evidence choices.
They are intentionally sidecar data, not hard-coded Python constants. Edit them with Notepad
or use Feathered's manual-evidence dialog to persist an exact mirror override.

US-only automatic evidence policy:
- Feathered automatically offers a catalog mirror as independent exact-mirror evidence only when
  its country field is exactly "US". Non-US and unknown-geography catalog mirrors are ignored.
- The bundled distribution catalogs are intentionally pruned to US mirrors only.
- There is no automatic foreign fallback. If a distribution has no suitable US public mirror,
  Feathered reports no automatic same-archive mirror evidence for that source.
- User-persisted exact_overrides remain operator-controlled and may point anywhere. They are not
  classified as independent mirror authority unless country="US" and independent_operator=true.

Important semantics:
- A distribution mirror can independently corroborate repository metadata/artifact bytes.
- It does not create a second signing authority; signatures are still issued by the distribution.
- independent_operator=true means the mirror transport/copy is operated separately, not that it
  is an independent package-signing authority.
- RHEL, Photon, Docker/vendor repositories, and custom repositories may not have public mirror
  directories. Do not substitute an unrelated distribution mirror for those archives.

Each distribution file records the authoritative mirror-directory source used for the
2026-08-30 US-only snapshot. The files remain intentionally editable by the local operator.
