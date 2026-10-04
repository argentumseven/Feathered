# Feathered offline package and air-gap guides

Feathered downloads Linux packages, dependency-complete workloads, and complete repositories for transfer into offline and air-gapped Linux environments.

These guides organize the same Feathered capabilities by the problem an operator is trying to solve.

## Common tasks

- [Download RPM packages and dependencies for offline RHEL-family systems](OFFLINE-RPM-DNF-YUM.md)
- [Download DEB packages and dependencies for offline Debian or Ubuntu](OFFLINE-APT-DEBIAN-UBUNTU.md)
- [Build an offline pacman repository for Arch Linux or Artix Linux](OFFLINE-PACMAN-ARCH.md)
- [Download Linux packages from a connected Windows workstation for an air-gapped Linux system](AIRGAP-WINDOWS-WORKSTATION.md)

## What Feathered produces

Depending on the selected acquisition mode and target, Feathered can produce:

- native RPM/YUM/DNF repositories;
- native APT repositories;
- native pacman repositories;
- dependency-complete workload or exact-package publications;
- complete repository mirrors;
- differential bundles against a previous Feathered baseline;
- manifests, checksums, provenance, and receiver-side verification material;
- an offline installer when the selected workflow supports direct target consumption.

Feathered performs connected-side package analysis so the required content can cross the air gap, but the target system's native package manager remains authoritative for the final transaction.

For the complete behavior and security model, see the project [README](../README.md), [CLI documentation](../CLI.md), [validation documentation](../VALIDATION.md), and [security policy](../SECURITY.md).
