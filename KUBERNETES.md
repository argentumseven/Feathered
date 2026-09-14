# Kubernetes workloads and VKS node additions

## Workflow

1. On **Linux Distribution**, choose the actual OS release and architecture.
   The optional platform note describes the environment and is included with
   the bundle; it does not select package versions.
2. On **Content**, choose an offered workload:
   - **Kubernetes node (kubeadm, self-managed)** acquires kubelet, kubeadm,
     kubectl, cri-tools and kubernetes-cni. The last two have independent package
     versions; they are not pinned to the Kubernetes minor.
   - **Kubernetes client tools (kubectl)** acquires the client.
   - **VKS node OS package additions** uses the ordinary exact-package chooser
     for additions such as cryptsetup. A captured installed inventory is optional and can be used to pin the existing node baseline.
3. For Kubernetes workloads, choose **Kubernetes minor repository**, then
   **Package patch / build**. The minor selects the community RPM or flat DEB
   repository. Full package versions, including packaging revisions, load
   automatically in the second selector. **Latest** follows the repository; an
   explicit build pins kubelet, kubeadm and kubectl together for the node workload,
   or kubectl alone for the client workload. The node selector lists builds shared
   by its three components. CRI and CNI packages keep independent versions. The
   ordinary exact-package chooser still exposes all packages and versions.
4. On **Repositories**, inspect the generated source and configure the distribution
   sources for OS dependencies. An explicitly configured custom Kubernetes source
   remains operator-owned; it is not overwritten when the minor changes. A
   component from a different minor is reported as an advisory. Optional oldest
   and newest API server minor fields accept values such as `33`; complete
   Kubernetes versions with vendor suffixes are also understood. Leave them blank
   to evaluate against the chosen minor as an explicit assumption, not observed
   cluster state.
5. Analyze and inspect **Workload advisories** on Review. Each finding names the
   package, version, severity and reason. Informational and advisory findings do
   not block acquisition. A conflict, such as inconsistent API server bounds or
   kubeadm outside the selected minor, requires **I have reviewed these advisories**.
   Changed findings reset the GUI acknowledgement. Normal source, dependency and
   signing requirements still apply.
6. Build the bundle. The manifest and ASSURANCE.txt record observations, assumptions,
   actual source URLs, findings, acknowledgement and limits. Additive publication
   and complete repository mirroring remain available. An evaluation of newly
   acquired packages does not establish compatibility of retained additive files.

## Version discovery and repository layout

The program refreshes release facts from the Kubernetes project's own website
repository: data/releases/schedule.yaml and data/releases/eol.yaml. Published
release minors seed repository discovery; future scheduled releases are excluded.
A known newer minor is probed even after gaps in older repositories, so the old
probe ceiling is no longer a ceiling for discovered upstream releases. Full
patch/build versions still come from actual package metadata, not the release
schedule. The repository's historical 1.24 floor does not restrict recorded API
server versions.

A bundled subset of observed release facts provides immediate initial choices.
A valid local cache takes precedence. Updates run off the UI thread; source URLs,
observation times and digest scope accompany the facts. Valid data replaces the
cache atomically. Failed, oversized or malformed responses preserve the last
usable data; a later successful refresh repairs an unreadable cache. Normal
refresh is six-hourly while the workflow is active. Failures retry after 1, 5,
then 15 minutes, capped at 15 minutes. Refresh minors requests an immediate check.
Retries wait while a build is active and while another workload is selected.
No refresh changes a selected minor, exact package pin or operator-owned source.
Previously observed repositories remain available when a whole probe run fails.

API server input is validated syntactically, without a hardcoded 20-60 range.
Unknown and end-of-life versions receive notices; they are still usable. Upstream
end of life does not establish a vendor's support status. Review/manifest metadata
records the release knowledge used for the evaluation. Headless builds make no
release-knowledge network requests and use the bundled observation; GUI builds
freeze their current knowledge with the prepared workload context. Saved build
specs preserve requested versions, not a requirement for the network to be up.

The refresh also fingerprints upstream version-skew and kubeadm Markdown. A
changed fingerprint produces a persistent review notice; no remote text is
executed or converted into new policy. The bundled kubeadm fingerprint allows
comparison with this build. The first successful version-skew-document fetch
establishes its comparison fingerprint; later changes remain flagged. A changed
page may reflect wording rather than changed semantics: the notice requires
review, not automatic adoption. New kubeadm/control-plane inferences are advisory
because the operation and prior kubeadm version have not been supplied. Existing
explicit selection/cluster-consistency conflicts retain their acknowledgement.


Generated URLs use `https://pkgs.k8s.io/core:/stable:/v1.<minor>/rpm/` or `deb/`.
Changing the minor updates the generated row without duplicating it. Operator
verification policy remains attached to the row. OS dependencies retain their
normal distribution sources; runtime and CNI package versions are independent.
No CRI-O repository or runtime choice is silently added.

Flat APT sources read Release/InRelease and Packages indexes at their root.
They retain signature verification, Release-index digest/size checks and explicit
unverified-index accounting. A missing Architectures declaration is reported;
package records are still filtered by the requested architecture. Flat layout is
part of the saved repository identity and is preserved during replay.

References: [community package repository selection](https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/change-package-repository/)
and [Kubernetes version skew policy](https://kubernetes.io/releases/version-skew-policy/).
The HA calculation intersects the permitted windows against every entered API
server; checking only the oldest server can admit unsupported older components.
These checks describe package relationships and do not approve an upgrade plan.

## VKS additions and the inventory baseline

This workload is offered for Photon 5.0, Ubuntu 22.04/24.04 and RHEL 9 targets.
That product availability rule is not a declaration that every corresponding
VKS image or added package is vendor-supported.

Installed inventory is optional. When inventory from the intended node is loaded,
including package detail records from target_inventory.sh with
target_inventory_details.py, **Pin to inventory baseline** can keep the build aligned
with that captured package set. With a usable inventory and pinning enabled, rolling
update rows are excluded, installed capabilities participate in resolution, and
publication refuses replacements of captured installed versions. Without inventory,
pinning has no baseline to apply and does not block the build; Feathered resolves a
complete repository-derived closure instead. Pinning does not reconstruct unavailable
historical archives.

Managed node binaries, runtimes, kernels and cluster add-ons receive advisories.
They remain selectable. Development packages such as kernel-headers, kernel-devel
and linux-headers-generic are not classified as kernel binaries. Direct installs
may be replaced by node rollout; use the platform's supported image/add-on process
for durable changes and verify its requirements for your release.

Alongside the normal bundle and installer, VKS additions emit
**imagebaker-image.yaml**. The name is editable on Content. This is an explicitly
UNVALIDATED draft: OS identity and root package names are populated, Kubernetes
settings remain a placeholder, and repository references describe the emitted
local metadata. Reconcile all fields with your Image Baker/VKS schema and builder
network paths before use. Feathered does not submit it to a cluster or claim that
Image Baker will accept it. Draft and assurance files are written before bundle
indexing so they participate in the final checksum file set.

## Saved builds and limits

Schema 3 records workload settings, API server bounds, baseline preference,
acknowledgement, image name, platform note and flat source layout. Schema 1/2
specs migrate without modifying the input document. Former Kubernetes target
settings map to workload context; VKr/image identifiers become recorded notes.
Exact selections and their full version/source pins are preserved. A former
workload-wide patch constraint becomes a repository minor and a migration note;
use Package patch / build or the exact chooser to select a particular build. Invalid former version
text is reported rather than silently discarded. No JSON cluster-version import
or environment/purpose target card remains.

The manifest records what was observed. It does not certify vendor support,
cluster upgrade readiness, container-image availability, CNI/CSI compatibility,
Image Baker schema compatibility or installation success. Review the exact
validation evidence and unexecuted platform gates in VALIDATION.md.
