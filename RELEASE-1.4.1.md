# Feathered 1.4.1

Feathered 1.4.1 repairs offline Linux workload acquisition and repository planning across APT, RPM/DNF/YUM and pacman, including dependency-complete bundles, repository mirroring and disconnected use.

- Resolve advertised virtual package roots, restoring Debian workloads using `dnsutils` and `postgresql-contrib`.
- Handle the nested RPM requirements used by current enterprise Linux packages, conditional OR predicates and parenthesized versioned requirements. Captured installed-state checks use the same semantics.
- Preserve valid provider fallback and limit retries to the failing dependency chain.
- Isolate vendor-source failures to the workloads that need them, generate the selected Kubernetes repository correctly, and prefer observed stable distro releases.
- Use native `syslog-ng` packages and init companions on Arch/Artix logging presets.

The source archive supports the Linux GUI and CLI and Windows source launchers. The Windows x64 archive contains the signed executable, authenticated OpenPGP verifier and required sidecars; extract the entire archive before launching. `SHA256SUMS.txt` covers both downloadable archives, and each archive includes its own integrity metadata.

The Java preset still requires Java 17. A target whose configured repositories no longer supply it needs a compatible Java 17 source; this release does not silently substitute another Java major. Other unavailable packages and unsupported repository combinations remain explicit failures. The live workload matrix is a compatibility observation, separate from the mandatory release gates.

See `CHANGELOG.md` for the complete changes and `VALIDATION.md` for the release verification policy.
