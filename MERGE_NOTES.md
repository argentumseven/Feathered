# Feathered targeted security/UNC fixes

These changes are intentionally narrow and are based on the current `main` source reviewed on 2026-09-21.

## Changed files

- `openpgp_verifier.py`
  - Re-hashes every authenticated GnuPG sidecar even when the size/mtime cache fingerprint matches.
  - Prevents same-size, restored-mtime replacement of an auxiliary verifier file from bypassing the integrity policy during a long-running process.
- `package_acquisition.py`
  - Uses the repository's existing `file_url_to_path()` helper for `file:` package payloads.
  - Preserves the hostname in legacy `file://server/share/...` UNC URLs.
- `tests/test_security_regressions.py`
  - Reproduces the verifier-cache bypass.
  - Reproduces the legacy UNC package-acquisition failure.

## Apply

Either copy the two top-level Python files over the repository versions and add the test file, or apply:

```sh
git apply feathered-security-fixes.patch
```

## Validate

Run the targeted regression tests first:

```sh
python -m pytest -q tests/test_security_regressions.py
```

Then run Feathered's full release test gate from the repository root:

```sh
python release_test_runner.py
```

The targeted tests were also run against a reconstruction of the old behavior: both failed as expected. Against these patched files, both passed.

## Scope note

No provenance-policy defaults, resolver behavior, network credential handling, installer behavior, or release workflow logic are changed by this patch.
