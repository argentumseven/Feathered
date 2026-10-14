# Security policy

Feathered processes repository metadata, package payloads, signing material, repository credentials, and transfer artifacts. Security reports should not be filed as public issues when they contain exploit details, credentials, private keys, entitlement material, or information that would materially increase exploitation risk.

Use GitHub's private vulnerability reporting feature for this repository when it is available. Otherwise contact the repository maintainer through a private channel before publishing technical details.

A useful report includes:

- affected Feathered version or commit;
- package family and workflow involved;
- whether the issue affects acquisition, verification, publication, transfer, or receiver behavior;
- a minimal reproduction when safe to provide;
- expected and observed behavior;
- any relevant repository metadata or artifact hashes with secrets removed.

Do not include private keys, entitlement certificates, repository passwords, bearer tokens, or signed-URL secrets in a report.

Custom repository URLs may use vendor-specific query parameters for bearer credentials. Configure those field names in the repository's Endpoint query credentials settings so Feathered applies credential detection and redaction to them. Same-origin inheritance is a separate opt-in and should be enabled only for bearer fields that the repository expects to be copied to child metadata and package URLs.

## Receiver and repository boundaries

`trusted_receiver.py --install` copies a transferred bundle into root-owned read-only staging before verification and installation. Package-manager inputs are consumed only from that staged tree. Repository-maintenance scans reject symbolic links inside the selected repository root.

Running `install-offline.sh` directly from a bundle is supported and is the default. Its checksum and sealed-index verification detect corruption and mistakes, but they run inside a script that travels with the bundle, so they are not a trust anchor against someone who can modify the transfer medium. That threat model is what `trusted_receiver.py` is for: it is distributed separately and verifies the bundle before anything from it is executed. Feathered does not require either path; choose according to who can write to the medium.
