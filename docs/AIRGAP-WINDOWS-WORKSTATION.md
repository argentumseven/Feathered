# Download Linux packages on Windows for an offline or air-gapped Linux system

Feathered is designed to let a connected workstation acquire Linux package content before that content crosses into a disconnected network.

A common deployment model is a connected Windows workstation that prepares native Linux package repositories for RHEL-family, Debian-family, or Arch-family targets.

## What the Windows workstation can prepare

Depending on the selected Feathered target and acquisition mode, the connected workstation can prepare:

- RPM/YUM/DNF repositories;
- APT repositories;
- pacman repositories;
- dependency-complete workload bundles;
- selected package/version bundles;
- complete repository mirrors;
- differential bundles against a previous Feathered baseline;
- provenance, checksums, manifests, and receiver-side verification material.

The generated repository is then transferred by whatever controlled media or transfer process the environment permits.

## Choose the target before downloading

Linux package artifacts are distribution-, release-, and architecture-specific. Feathered therefore builds for an explicit target profile rather than treating an RPM or DEB as universally portable.

Built-in target families include:

- RHEL, Rocky Linux, AlmaLinux, CentOS Stream, Fedora, and VMware Photon OS;
- Ubuntu, Debian, and Devuan;
- Arch Linux and Artix Linux;
- custom RPM and APT repositories.

The receiver verifies the target release before a direct-install workflow proceeds. Feathered is not intended to mix packages from different operating-system releases.

## Optional target inventory

For tighter planning, Feathered can consume an inventory captured from the disconnected target.

Copy the inventory collector files to the target, run:

```bash
bash target_inventory.sh target-inventory.txt
```

and move the resulting inventory back to the connected Feathered workstation.

The inventory can let planning account for installed packages, package relationships, architecture, and relevant package-manager state. Inventory is optional; it is not required for every workflow.

## GUI workflow

From the Feathered application:

1. Select the target distribution, release, and architecture.
2. Choose **Workload**, **Choose packages**, or **Entire repository (mirror)**.
3. Select the allowed package sources.
4. Optionally load target inventory.
5. Select the provenance/keying policy appropriate for the environment.
6. Build the bundle.
7. Transfer the output to the disconnected network.
8. Consume it with the target's native package manager or stage it into an internal repository server.

## Headless workflow

Saved build specifications can be inspected and executed without Tk:

```bash
python feathered_cli.py show --spec build.json
python feathered_cli.py build --spec build.json --out ./bundles
```

Portable build specifications exclude local private-key paths. Runtime credentials and local trust material can be supplied separately.

See [CLI.md](../CLI.md) for the complete headless interface.

## Windows release security model

Frozen Windows releases use a staged GnuPG `gpgv` verifier. Bundle signing separately requires `gpg` and an operator secret key. Production build tooling authenticates the staged verifier inputs and prevents a frozen build from silently falling back to an arbitrary verifier on `PATH`.

For receiver-side trust, the strongest workflow distributes `trusted_receiver.py` and the operator public keyring through a trusted channel separate from the transferred bundle.

## Related guides

- [Offline RPM / DNF / YUM](OFFLINE-RPM-DNF-YUM.md)
- [Offline APT / Debian / Ubuntu](OFFLINE-APT-DEBIAN-UBUNTU.md)
- [Offline pacman / Arch](OFFLINE-PACMAN-ARCH.md)
- [Main README](../README.md)
