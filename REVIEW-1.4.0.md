# Feathered 1.4.0 review

Reviewed 27 September 2026. Input: `Feathered-refactored-v21-beta-marking.zip`.
GitHub comparison base: `argentumseven/Feathered`, main commit
`c26dfa8a1be9fe7b88de8351a947604c3b155ad2`.

## Fixed findings

| Finding | Impact and fix |
| --- | --- |
| Encoded credential query names escaped text redaction | `%74oken` and equivalent spellings could expose credentials in logs and warnings, especially short or newly encountered values. Text redaction now decodes field names, consistently with URL/transport handling. Overlapping registered secrets are removed longest-first to avoid leaving a suffix. |
| Redirect policy checked only base repository credentials | A credentialed child URL or authenticated request could cross origins when the repository's base URL was public. Checks now include the actual request URL, Authorization, and Cookie headers. Same-origin redirects and explicitly approved CDN origins remain supported. |
| Themed dialog fallback mishandled decisions | Native yes/no booleans were compared to strings, losing affirmative answers; OK/Cancel and Retry/Cancel failures could silently choose their default. Native answers now map correctly, partially created dialogs are destroyed, and failed custom policy dialogs return no affirmative choice. |
| Repository-selection typing failed the pinned static gate | Conditional lambdas returned tuples of different lengths. A consistent three-element ordering key retains selection behavior and passes the configured mypy version. |

These are reproduced findings, not a claim that every possible defect has been excluded.

## Requested changes

- Version 1.4.0 in the runtime identity, README, dependency-lock headings, launcher guidance, and changelog. All supplied unreleased changes are included under 1.4.0.
- Windows native dark title bars on the main window and Tk Toplevel dialogs. Windows 11 receives the app's exact header and text colors; supported Windows 10 builds use the immersive dark frame with an older-attribute fallback.
- Native minimize, maximize, move, resize, and close controls remain OS-managed. Unsupported platforms keep their native decoration. Windows common file dialogs and Linux window-manager title bars are outside this change.

The implementation uses the DWM attributes documented at
https://learn.microsoft.com/en-us/windows/win32/api/dwmapi/ne-dwmapi-dwmwindowattribute.
Actual Windows appearance has not been visually verified in this Linux environment.

## Validation

- Full regression run with a virtual display: **2,191 passed, 3 failed** out of 2,194.
- The source-manifest failure coincided with cleanup of test-created temporary files. After the tree settled, **all 10 source-manifest tests passed**. This verifies the remaining non-signing failure; 2,192 distinct tests have passed across these runs.
- The two remaining tests are OpenPGP signing round trips. GnuPG cannot start its agent because this environment rejects socket creation (`Operation not permitted`). These tests were not disabled or weakened. They must pass in normal CI before certifying a signed release.
- All **26 new regression tests passed**, covering credential handling, dialog decisions, and the native-title-bar ABI/fallback paths.
- Ruff 0.14.2: passed. Mypy 1.18.2: passed for the configured 88 modules.
- Host-contract checks: valid capabilities accepted and all 53 malformed cases rejected.
- Python source compilation and generated RPM, signed-RPM, APT, and Arch installer shell syntax: passed.
- pip-audit checked all 14 dependencies pinned in `requirements-build.lock`: **no known vulnerabilities reported**. This is an advisory-database check, not proof of absence of vulnerabilities; it does not assess the Windows interpreter, staged GnuPG binaries, or native OS packages.

## Publishing status and remaining gates

No changes have been pushed to GitHub. Public read access works, but authenticated push access is unavailable in this session. No v1.4.0 tag or GitHub Release has been created.

The existing Windows production workflow requires its Windows, native package-manager, Linux-client, and static gates, plus release signing secrets. Those remote gates have not been run for this update. No Windows executable has been built or signed here. The existing workflow uploads build artifacts; it does not itself create a GitHub Release entry.

The delivered source archive includes a fresh `SOURCE-SHA256.json`; verify it with `python verify_source_checksums.py`. The adjacent patch applies to the GitHub comparison base using `git am`, preserving repository history and historical validation files.
