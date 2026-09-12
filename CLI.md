# Command-line builds

`feathered_cli.py build` prepares and executes a saved build without Tk or a
display. The GUI and CLI share source validation, build-option construction,
publication rules, and the execution runner.

```bash
python feathered_cli.py show --spec build.json
python feathered_cli.py build --spec build.json --out ./bundles
```

The spec contains explicit repository rows. Replay does not discover or enable
additional repositories and does not read your GUI's local configuration.
Recapture older specs to include repository tiers, target scoping, managed
workload-source flags, evidence relationship hints, and vendor requirements.
Older specs remain readable, but fields that were never saved cannot be
recovered automatically. An old spec with an unscoped "Require" vendor label
requires recapture or explicit runtime vendor profiles.

A captured form can be an incomplete draft. `capture()` preserves the selected
values, including an empty release; it does not infer a release from the build
host or a repository suite such as `stable`. For non-Arch targets, build
preparation rejects an empty release with exit code 5 before metadata/trust
review. Select the target release before saving a request intended to build.
A valid request with declined trust findings returns 2; accepting those findings
allows the build to proceed. The wizard already requires a release before
leaving the target stage.

`--dry-run` describes saved settings without fetching or writing. It does not
resolve package versions, validate inventories, or predict a publication plan.

## Explicit decisions

Unanswered decisions decline. These choices are independent:

| Option | Permission |
|---|---|
| `--accept-trust-findings` | Accept the reported metadata/trust findings; findings are retained in bundle provenance. Hard verification failures still fail. |
| `--accept-conflict-notices` | Accept reported conflict notices and dependency waivers. This does not authorize incomplete unresolved roots. |
| `--accept-package-only` | Accept a workload's explicitly derived root-artifact-only capability. It does not claim dependency closure. |
| `--existing-output sibling` | Publish beside an occupied destination. Mirrors always need a fresh sibling. |
| `--existing-output add` | Use the existing additive staging/publication mechanism for non-mirror bundles. |
| `--existing-metadata regenerate` | Regenerate metadata over old and new payloads during additive publication. |
| `--existing-metadata keep` | Keep the existing repository metadata, which will not index newly added payloads. |

Existing-output and existing-metadata policies default to `cancel`. Trust and
conflict consent do not authorize output reuse. For example:

```bash
python feathered_cli.py build --spec build.json --existing-output sibling
```

`--timeout SECONDS` covers preparation and execution. Cancellation is
cooperative: blocking backend I/O must reach a checkpoint, so it can take
longer than the specified duration to return. The CLI leaves no background
build running after return. A completed publication remains a success if it
has already committed. Separate mirror folders remain independent publications;
a later failure can leave earlier completed mirror folders available.

## Local credentials and vendor trust

Certificate and keyring paths are supplied separately from portable settings:

```bash
python feathered_cli.py build --spec build.json --runtime-config runtime.json
```

Example runtime configuration (replace the identity with one printed by `show`):

```json
{
  "repository_credentials": {
    "repo-sha256:SOURCE_ID_FROM_SHOW": {
      "client_cert": "/secure/entitlement.pem",
      "client_key": "/secure/entitlement-key.pem",
      "ca_cert": "/secure/repository-ca.pem",
      "keyring": "/secure/repository-signers.gpg"
    }
  },
  "vendor_signature_profiles": {
    "redhat": {"policy": "require", "keyring": "/secure/vendor-signers.gpg"}
  },
  "resolution_pass_budget": 8
}
```

Omit unused fields and sections. Repository credentials are matched by stable
source identity; a credential entry for an absent source is rejected. Vendor
policies are `record` or `require`. A saved required-vendor policy cannot be
relaxed by a runtime `record` setting. Required-vendor identities are portable;
local keyring paths are not. Endpoint and evidence URLs are preserved as saved
and may themselves contain credentials.

## API and outcomes

```python
from core import Reporter
from feathered_app.build_api import PreparationInputs, execute_build
from feathered_app.build_services import BuildServices

outcome = execute_build(spec, BuildServices(Reporter(log=print)),
                        PreparationInputs(), timeout=3600)
print(outcome.status.value, outcome.message, outcome.output_path)
```

`prepare_build(spec, services, inputs)` is also available when a caller needs
to inspect the validated `PreparedBuild` before invoking
`build_runner.run(prepared.host, prepared.plan)`. Preparation can load metadata
and inventory files but does not publish a bundle. Both host and plan belong to
one invocation; do not reuse them concurrently. A custom workload catalogue can
be supplied through `PreparationInputs.workloads` by API callers.

| Exit code | Meaning |
|---|---|
| 0 | Bundle published, with an existing output directory |
| 1 | Execution/internal failure |
| 2 | Required decision declined |
| 4 | Cooperative timeout |
| 5 | Invalid request or cancellation |

Code 3 is reserved from the older display-dependent CLI. It is no longer
produced. API outcomes distinguish invalid requests from cancellation even
though both retain CLI code 5. Missing pinned packages now produce an invalid
request outcome before execution; they never fall back to another version.

See `VALIDATION.md` for the current release-check summary and reproduction commands.
