# Platform and dispatch batch evidence

Final complete-corpus result: 1,428 passed, zero skips or deselections. The
per-test phase records and modified-source identity are in ../platform-gate/.
The run records tracked edits against base 720749d; it does not claim a merge.

- 22 dispatch cases passed before and after consolidation; all 15 prior writer
  snapshots still passed. The full corpus adds 38 cases to the prior 1,390.
- Mypy passed across 54 configured roots. All 50 malformed capability/type probes
  were rejected, including mixed backend/inventory types. Ruff and generated
  installer syntax checks passed.
- Real Linux setup installed the pinned wheels with package-index access disabled.
  A successful repeated setup created a new permanent environment and retained
  the previous one. Unit regressions verify failed-upgrade rollback and locking.
- The actual installed GUI opened under Xvfb on Ubuntu 24.04 / CPython 3.12.14.
  Its CLI declined trust with exit 2 and published with exit 0, without a display,
  preserving a genuine DEB's bytes, checksum and provenance.
- GIO parsed and launched the generated desktop entry from a source path containing
  spaces, a quote, a dollar sign and a percent sign. Its argument recorder confirmed
  that the literal source path reached the GUI launcher intact.
- Native APT conformance did NOT pass locally: runner restrictions denied
  setgroups/setuid before the fixture repository could be read. DNF/pacman are
  unavailable. The unchanged required native CI jobs remain the acceptance gates.
- Windows execution, frozen/signed builds and the new Debian/Ubuntu CI matrix
  have not run in this workspace. Windows fixes address source-level quoting and
  process-environment problems and add diagnostic retention; the earlier remote
  bootstrap failure is not claimed resolved.

cumulative.patch includes tracked edits AND new source files from base 720749d.
The deliverable is also a complete source ZIP; no patch application is required.
