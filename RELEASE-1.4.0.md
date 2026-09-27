# Feathered 1.4.0

This release includes the supplied refactoring and beta-option marking work,
plus native dark Windows title bars and fixes from the source/security review.

- Dark Windows window captions that match the app.
- Beta/development options clearly marked, with stable options preferred by default.
- Improved workload version refresh, RPM module handling, installed-conflict checks,
  and Arch epoch filename handling from the supplied update.
- Hardened credential redaction and authenticated redirect confinement.
- Correct confirmation-dialog fallback behavior and a repaired static-analysis gate.

See `CHANGELOG.md` for the complete changes and `REVIEW-1.4.0.md` for findings,
validation evidence, and remaining release gates.
