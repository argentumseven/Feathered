#!/usr/bin/env bash
# Historical filename: this 1.4.0 source archive ALREADY contains the fixes.
# This command validates the archive. It deliberately does not modify Git,
# reapply a historical patch, commit, or push changes to any remote.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if command -v python3 >/dev/null 2>&1; then
    py=python3
elif command -v python >/dev/null 2>&1; then
    py=python
else
    printf '%s\n' 'Python is required to verify the source manifest.' >&2
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    printf '%s\n' 'sha256sum (GNU coreutils) is required to verify the legacy checksum list.' >&2
    exit 1
fi

"$py" verify_source_checksums.py
sha256sum -c SHA256SUMS.txt
printf '%s\n' 'Checksums match. No files were applied, committed, or pushed.'
