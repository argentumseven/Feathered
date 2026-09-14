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

## Receiver and repository boundaries

`trusted_receiver.py --install` copies a transferred bundle into root-owned read-only staging before verification and installation. Package-manager inputs are consumed only from that staged tree. Repository-maintenance scans reject symbolic links inside the selected repository root.
