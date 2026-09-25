#!/usr/bin/env bash
# Run from the root of your Feathered clone, after copying the files in this
# folder over the repository (or after `git apply feathered-review-fixes.patch`).
set -euo pipefail

# Files that are obsolete or misleading (the patch they describe is already applied).
git rm -q --ignore-unmatch MERGE_NOTES.md SHA256SUMS.txt feathered-security-fixes.patch

# Stop tracking generated gate evidence. Your local copy is left on disk;
# validation/ is now in .gitignore and CI publishes it as workflow artifacts.
git rm -r -q --cached --ignore-unmatch validation

git add -A
python -m pytest -q
git commit -m "Review follow-ups: installer signature policy, verifier staging, transport retries, provenance digest axis, job pool starvation, repo hygiene"
git push origin HEAD
