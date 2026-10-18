# Feathered 1.4.1

Feathered 1.4.1 repairs offline Linux workload acquisition and repository planning across APT, RPM/DNF/YUM and pacman, including dependency-complete bundles, repository mirroring and disconnected use.

- Resolve advertised virtual package roots, restoring Debian workloads using `dnsutils` and `postgresql-contrib`.
- Handle the nested RPM requirements used by current enterprise Linux packages, conditional OR predicates and parenthesized versioned requirements. Captured installed-state checks use the same semantics.
- Preserve valid provider fallback and limit retries to the failing dependency chain.
- Isolate vendor-source failures to the workloads that need them, generate the selected Kubernetes repository correctly, and prefer observed stable distro releases.
- Use native `syslog-ng` packages and init companions on Arch/Artix logging presets.

The source archive supports the Linux GUI and CLI and Windows source launchers. The Windows x64 archive is signed with a release-specific, self-signed Feathered code-signing certificate. Windows does not automatically trust this publisher; this certificate is not a publicly trusted CA identity. The public certificate is provided as a download and inside the Windows archive. Its private key stays on the ephemeral build worker and is removed after signing.

Extract the entire Windows archive before launching; it includes the authenticated OpenPGP verifier, required sidecars and `SIGNING-NOTICE.txt`. `SHA256SUMS.txt` covers the source archive, Windows archive and public certificate. Each archive includes its own integrity metadata. The existing `v1.4.1` source tag is preserved.

Windows publication uses corrected release automation for PyInstaller data paths, bounded GnuPG downloads and authenticated payload extraction. `RELEASE-MANIFEST.json` records both the unchanged application source commit and the automation commit. The source archive retains the original tagged builder; use the recorded automation builder when rebuilding the Windows application.

The Java preset still requires Java 17. A target whose configured repositories no longer supply it needs a compatible Java 17 source; this release does not silently substitute another Java major. Other unavailable packages and unsupported repository combinations remain explicit failures. The live workload matrix is a compatibility observation, separate from the mandatory release gates.

See `CHANGELOG.md` for the complete changes and `VALIDATION.md` for the release verification policy.
