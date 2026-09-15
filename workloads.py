from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


from source_model import RootSourcePolicy, SourcePlan


ARCH_PACKAGE_OVERRIDES: Dict[str, List[str]] = {
    "docker": ["docker", "docker-buildx", "docker-compose"],
    "container-tools": ["podman", "buildah", "skopeo"],
    "podman": ["podman"],
    "podman-docker": ["podman", "podman-docker"],
    "buildah": ["buildah"],
    "skopeo": ["skopeo"],
    "podman-build-stack": ["podman", "buildah", "skopeo"],
    "web-nginx": ["nginx"],
    "web-apache": ["apache"],
    "db-postgresql": ["postgresql"],
    "db-mariadb": ["mariadb"],
    "python-runtime": ["python", "python-pip", "python-setuptools", "python-wheel", "python-virtualenv"],
    "java-runtime": ["jre17-openjdk-headless"],
    "ansible": ["ansible", "python", "openssh"],
    "kernel-dev": ["linux-headers", "dkms", "base-devel"],
    "cockpit": ["cockpit"],
    "time-sync": ["chrony"],
    "git-scm": ["git", "git-lfs"],
    "net-diagnostics": ["tcpdump", "bind", "traceroute", "mtr", "iputils", "nmap",
                        "openbsd-netcat", "socat", "curl", "wget", "lsof", "strace", "psmisc",
                        "iproute2", "net-tools", "ethtool", "iperf3", "iftop", "whois",
                        "inetutils", "openssl", "conntrack-tools", "bridge-utils", "ngrep",
                        "arp-scan", "sysstat", "tcpflow"],
    # openscap and aide are AUR-only on Arch; official-repo names only here.
    "security-audit": ["audit", "apparmor", "clamav", "fail2ban",
                       "openssl", "gnupg", "sudo", "logrotate", "rsyslog"],
    "storage-tools": ["lvm2", "mdadm", "nfs-utils", "xfsprogs", "e2fsprogs", "btrfs-progs",
                      "parted", "gptfdisk", "dosfstools", "cryptsetup", "multipath-tools",
                      "open-iscsi", "smartmontools", "hdparm", "sg3_utils", "nvme-cli",
                      "rsync", "quota-tools", "autofs", "sysstat", "lsscsi", "udisks2"],
    "build-toolchain": ["base-devel", "cmake", "ninja", "gdb", "valgrind", "ccache",
                        "binutils", "elfutils", "strace", "git", "python"],
    "sysadmin-essentials": ["vim", "nano", "tmux", "screen", "less", "bash-completion", "htop",
                            "procps-ng", "psmisc", "sysstat", "lsof", "tree", "unzip", "zip",
                            "tar", "gzip", "bzip2", "xz", "rsync", "wget", "curl", "jq",
                            "man-db", "which", "file", "dos2unix", "sudo"],
    # bcc-tools is the official Arch BPF tooling package; "bpf" does not exist.
    # nmon is AUR-only and is omitted rather than shipped as a guaranteed miss.
    "monitoring-agents": ["sysstat", "htop", "iotop", "atop", "perf", "bcc-tools",
                          "numactl", "procps-ng", "lm_sensors", "smartmontools", "net-snmp",
                          "rsyslog", "logrotate", "chrony"],
    "pki-tls": ["openssl", "ca-certificates", "nss", "gnutls", "gnupg", "p11-kit"],
}


# Artix splits service init scripts into <service>-<init> companion packages
# (galaxy). For presets that install a long-running service, the chosen init's
# companion is a required root: the daemon without its service script is not a
# working installation. Package names verified against the preset's own arch
# mappings; the coverage report surfaces any companion a given init lacks.
ARTIX_SERVICE_COMPANIONS: Dict[str, List[str]] = {
    "docker": ["docker"],
    "web-nginx": ["nginx"],
    "web-apache": ["apache"],
    "db-postgresql": ["postgresql"],
    "db-mariadb": ["mariadb"],
    "time-sync": ["chrony"],
    "ansible": ["openssh"],
    "security-audit": ["fail2ban", "clamav", "rsyslog"],
    "monitoring-agents": ["rsyslog"],
}


@dataclass(frozen=True)
class WorkloadComponent:
    """Semantic workload component with an ordered approved package identity set."""
    key: str
    rpm_candidates: List[str]
    deb_candidates: Optional[List[str]] = None
    required: bool = True
    repository_role: Optional[str] = None

    def candidates_for(self, package_family: str) -> List[str]:
        values = self.deb_candidates if package_family == "deb" and self.deb_candidates else self.rpm_candidates
        return [str(x).strip() for x in values if str(x).strip()]


@dataclass(frozen=True)
class WorkloadProfile:
    key: str
    label: str
    packages: List[str]
    description: str
    version_package: Optional[str] = None
    version_role: Optional[str] = "dependency"
    versioned_packages: List[str] = field(default_factory=list)
    requires_docker_repo: bool = False
    # 1.0.48 generalizes workload-bound
    # repositories.  A workload declares repository *roles* it needs; the
    # distribution profile supplies concrete templates for those roles.  The
    # legacy Docker flag remains readable for old workloads.json files.
    repository_roles: List[str] = field(default_factory=list)
    # Optional per-root mapping for workloads that mix packages from several
    # vendor sources or combine vendor roots with distribution-native roots.
    package_repository_roles: Dict[str, str] = field(default_factory=dict)
    docker_rootless_extra: bool = False
    verification_commands: List[str] = field(default_factory=list)
    supported_distros: Optional[List[str]] = None
    # Debian and RPM families frequently name the same software differently
    # (httpd vs apache2, gcc-c++ vs build-essential). When set, these replace
    # `packages` for deb targets; otherwise `packages` is used for both.
    deb_packages: Optional[List[str]] = None
    # Packages that are genuinely useful but are not carried by every mirror or
    # every family (EPEL-only tools, universe-only tools, kernel-tied packages).
    # Their absence is reported and skipped rather than failing the build, so a
    # preset stays usable against a minimal source set.
    optional_packages: List[str] = field(default_factory=list)
    # Optional semantic component catalog. Existing workloads synthesize one
    # component per package, preserving the legacy behavior while allowing a
    # signed/organisation catalog to provide ordered replacement candidates.
    components: List[WorkloadComponent] = field(default_factory=list)
    catalog_revision: int = 1
    catalog_sha256: str = "builtin"
    catalog_signature_verified: bool = False

    def required_repository_roles(self) -> List[str]:
        """Repository roles this workload needs in addition to the OS base.

        Keep the legacy Docker flag as a compatibility input, but expose one
        generic contract to the application so future vendor/workload sources
        do not require Docker-specific UI or resolver branches.
        """
        roles = [str(x).strip() for x in self.repository_roles if str(x).strip()]
        roles.extend(str(x).strip() for x in self.package_repository_roles.values() if str(x).strip())
        roles.extend(str(component.repository_role).strip() for component in self.components
                     if component.repository_role and str(component.repository_role).strip())
        if self.requires_docker_repo and "docker" not in roles:
            roles.append("docker")
        return list(dict.fromkeys(roles))

    def repository_role_for(self, package_name: str) -> Optional[str]:
        """Explicit workload/vendor repository role for a requested root.

        An unmapped root is distribution-native.  ``version_role`` is only a
        version-discovery hint and must not be promoted into package provenance:
        Podman, for example, may be discovered across distribution repositories
        whose backend role is ``dependency`` without belonging to one concrete
        ``dependency`` repository.  A legacy workload that declares exactly one
        required vendor role still applies that role to all roots.
        """
        mappings = self.package_repository_roles or {}
        mapped = mappings.get(package_name)
        if mapped:
            return mapped
        # Once a workload uses per-package source mappings, omission is
        # meaningful: the unmapped root is distribution-native. This is what
        # allows one composite workload to mix OS packages with vendor roots.
        if mappings:
            return None
        roles = self.required_repository_roles()
        if len(roles) == 1:
            return roles[0]
        return None

    def root_source_kind(self, package_name: str) -> str:
        """Return ``workload`` for explicit vendor roots, else ``distribution``."""
        return "workload" if self.repository_role_for(package_name) else "distribution"

    def component_requirements(self, package_family: str) -> List[WorkloadComponent]:
        """Return semantic components, synthesizing legacy fixed package lists."""
        if self.components:
            return list(self.components)
        optional = self.optional_for(package_family) if self.optional_packages else set()
        return [WorkloadComponent(
            key=name,
            rpm_candidates=[name],
            deb_candidates=[name] if package_family == "deb" else None,
            required=name not in optional,
            # Arch's official packages are distribution-native. In particular,
            # the Docker preset must not seed Docker's RPM/APT repository role.
            repository_role=None if package_family == "arch" else self.repository_role_for(name),
        ) for name in self.packages_for(package_family)]

    def source_plan(self, package_family: str, roots: Optional[List[str]] = None) -> SourcePlan:
        """Derive the authoritative repository-source contract for this workload."""
        policies: List[RootSourcePolicy] = []
        if roots is not None:
            components = [WorkloadComponent(
                key=name, rpm_candidates=[name], deb_candidates=[name] if package_family == "deb" else None,
                required=name not in self.optional_for(package_family),
                repository_role=None if package_family == "arch" else self.repository_role_for(name)) for name in roots]
        else:
            components = self.component_requirements(package_family)
        for component in components:
            candidates = component.candidates_for(package_family)
            if not candidates:
                continue
            primary = candidates[0]
            role = component.repository_role or self.repository_role_for(primary)
            policies.append(RootSourcePolicy(
                package=primary,
                source_kind="workload" if role else "distribution",
                role=role,
                component=component.key,
                candidates=tuple(candidates),
                optional=not component.required,
            ))
        return SourcePlan(policies)

    def candidate_names_for(self, package_family: str, package_name: str) -> List[str]:
        """Approved identities for the component containing ``package_name``."""
        for component in self.component_requirements(package_family):
            candidates = component.candidates_for(package_family)
            if package_name == component.key or package_name in candidates:
                return candidates
        return [package_name] if package_name else []

    def catalog_fingerprint(self, package_family: str) -> str:
        """Stable SHA-256 for the workload definition that drove materialization."""
        configured = str(self.catalog_sha256 or "")
        if len(configured) == 64 and all(c in "0123456789abcdefABCDEF" for c in configured):
            return configured.lower()
        plan = self.source_plan(package_family)
        payload = {
            "key": self.key,
            "revision": int(self.catalog_revision or 1),
            "family": package_family,
            "roots": [
                {"component": root.component, "primary": root.package,
                 "candidates": list(root.candidates or (root.package,)),
                 "source_kind": root.source_kind, "role": root.role,
                 "optional": root.optional}
                for root in plan.roots],
            "version_package": self.version_package,
            "versioned_packages": list(self.versioned_packages),
            "verification_commands": list(self.verification_commands),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def optional_for(self, package_family: str) -> set:
        """Optional names relevant to this family."""
        names = set(self.packages_for(package_family))
        return {n for n in self.optional_packages if n in names}

    @property
    def has_version_axis(self) -> bool:
        """True when one version number meaningfully describes this workload.

        Docker Engine has a version. "Network diagnostics" does not: it is a
        set of unrelated tools that each move independently, so offering a
        single version selector for it is meaningless and misleading.
        """
        return bool(self.version_package)

    def packages_for(self, package_family: str) -> List[str]:
        """Primary package names appropriate to the target's package family."""
        if self.components:
            return [candidates[0] for component in self.components
                    for candidates in [component.candidates_for(package_family)] if candidates]
        if package_family == "arch":
            if self.custom:
                return []
            return list(ARCH_PACKAGE_OVERRIDES.get(self.key, []))
        if package_family == "deb" and self.deb_packages:
            return list(self.deb_packages)
        return list(self.packages)
    custom: bool = False
    # Contextual package workloads use the exact-package chooser but retain
    # workload policy, dependency-mode choices and workload-specific output.
    contextual_packages: bool = False
    version_axis: str = 'package'
    supported_releases: Dict[str, List[str]] = field(default_factory=dict)

    def supports_target(self, distro: str, release: str) -> bool:
        if self.supported_distros is not None and distro not in self.supported_distros:
            return False
        allowed = self.supported_releases.get(distro)
        return allowed is None or any(release == v or release.startswith(v + '.') for v in allowed)



def _builtins() -> List[WorkloadProfile]:
    return [
        WorkloadProfile(
            key="docker",
            label="Docker Engine",
            packages=["docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"],
            description="Docker CE engine, CLI, containerd, Buildx and Compose plugin. Docker packages come from Docker's repository for the selected RPM or APT family; OS dependencies come from the target distribution sources.",
            version_package="docker-ce",
            version_role="docker",
            versioned_packages=["docker-ce", "docker-ce-cli"],
            requires_docker_repo=True,
            repository_roles=["docker"],
            package_repository_roles={
                "docker-ce": "docker", "docker-ce-cli": "docker",
                "containerd.io": "docker", "docker-buildx-plugin": "docker",
                "docker-compose-plugin": "docker",
            },
            docker_rootless_extra=True,
            verification_commands=[
                "sudo systemctl daemon-reload",
                "sudo systemctl enable --now docker",
                "sudo docker version",
                "sudo docker compose version",
            ],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="container-tools",
            label="Container Tools suite (Podman/Buildah/Skopeo)",
            packages=["container-tools"],
            deb_packages=["podman", "buildah", "skopeo", "crun", "uidmap", "slirp4netns",
                          "containers-storage", "fuse-overlayfs"],
            description="Distribution container-tools meta-package. On RHEL/EL this is the broad container-tooling bundle and normally brings Podman, Buildah, Skopeo and supporting libraries.",
            version_package="container-tools",
            version_role="dependency",
            versioned_packages=["container-tools"],
            verification_commands=["podman --version", "buildah --version", "skopeo --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream"],
        ),
        WorkloadProfile(
            key="podman",
            label="Podman",
            packages=["podman"],
            description="Podman container engine from the target distribution repositories. Dependency closure includes the matching runtime, networking, security-policy and storage libraries exposed by that repository set.",
            version_package="podman",
            version_role="dependency",
            versioned_packages=["podman"],
            verification_commands=["podman --version", "podman info"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="podman-docker",
            label="Podman + Docker command compatibility",
            packages=["podman", "podman-docker"],
            description="Podman plus the distribution's podman-docker compatibility package. This intentionally conflicts with a real Docker CLI on distributions where podman-docker owns the docker command.",
            version_package="podman",
            version_role="dependency",
            versioned_packages=["podman"],
            verification_commands=["podman --version", "docker --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="buildah",
            label="Buildah",
            packages=["buildah"],
            description="OCI image-building tool from the target distribution repositories.",
            version_package="buildah",
            version_role="dependency",
            versioned_packages=["buildah"],
            verification_commands=["buildah --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="skopeo",
            label="Skopeo",
            packages=["skopeo"],
            description="Container image copy/inspect utility from the target distribution repositories; useful for preparing and moving images into disconnected environments.",
            version_package="skopeo",
            version_role="dependency",
            versioned_packages=["skopeo"],
            verification_commands=["skopeo --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="podman-build-stack",
            label="Podman + Buildah + Skopeo",
            packages=["podman", "buildah", "skopeo"],
            description="Explicit core container stack without using the broader container-tools meta-package.",
            version_package="podman",
            version_role="dependency",
            versioned_packages=["podman"],
            verification_commands=["podman --version", "buildah --version", "skopeo --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="web-nginx",
            label="Web server - nginx",
            packages=["nginx"],
            description="nginx web server and its distribution dependencies. On EL targets nginx "
                        "lives in AppStream; on Debian/Ubuntu it is in main.",
            version_package="nginx",
            verification_commands=["sudo systemctl enable --now nginx", "nginx -v"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="web-apache",
            label="Web server - Apache httpd",
            packages=["httpd", "mod_ssl"],
            deb_packages=["apache2"],
            description="Apache HTTP Server with TLS support. Named httpd/mod_ssl on RPM families "
                        "and apache2 on Debian and Ubuntu.",
            version_package="httpd",
            verification_commands=["sudo systemctl enable --now httpd", "httpd -v"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="db-postgresql",
            label="Database - PostgreSQL",
            packages=["postgresql-server", "postgresql-contrib"],
            deb_packages=["postgresql", "postgresql-contrib"],
            description="PostgreSQL server plus the contrib extensions. Uses the distribution's "
                        "own PostgreSQL, not the upstream PGDG repository.",
            version_package="postgresql-server",
            verification_commands=["sudo postgresql-setup --initdb", "sudo systemctl enable --now postgresql"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="db-mariadb",
            label="Database - MariaDB",
            packages=["mariadb-server"],
            description="MariaDB server and client tooling from the distribution repositories.",
            version_package="mariadb-server",
            verification_commands=["sudo systemctl enable --now mariadb", "mariadb --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="python-runtime",
            label="Python runtime and packaging",
            packages=["python3", "python3-pip", "python3-devel", "python3-setuptools"],
            deb_packages=["python3", "python3-pip", "python3-dev", "python3-venv", "python3-setuptools"],
            description="Python 3 with pip, venv and development headers. Note this bundles the "
                        "interpreter only - Python wheels are not OS packages and are not collected.",
            version_package="python3",
            verification_commands=["python3 --version", "python3 -m pip --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="java-runtime",
            label="Java runtime (OpenJDK 17)",
            packages=["java-17-openjdk-headless"],
            deb_packages=["openjdk-17-jre-headless"],
            description="Headless OpenJDK 17 runtime. Choose the JDK packages instead if the "
                        "target needs to compile Java.",
            version_package="java-17-openjdk-headless",
            verification_commands=["java -version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="ansible",
            label="Ansible control node",
            packages=["ansible-core", "python3-jmespath"],
            deb_packages=["ansible", "python3-jmespath"],
            description="Ansible for configuring other hosts inside the enclave. Collections are "
                        "not OS packages; download them separately with ansible-galaxy on a "
                        "connected host.",
            version_package="ansible-core",
            verification_commands=["ansible --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="kernel-dev",
            label="Kernel headers and DKMS",
            packages=["kernel-devel", "kernel-headers", "dkms"],
            deb_packages=["linux-headers-generic", "dkms"],
            optional_packages=["kernel-devel", "kernel-headers", "linux-headers-generic", "dkms"],
            description="Needed to build out-of-tree kernel modules (storage, network or "
                        "virtualisation drivers) on a disconnected host. Headers must match the "
                        "running kernel, so confirm the target's kernel version first.",
            version_package="dkms",
            verification_commands=["uname -r", "dkms status"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="cockpit",
            label="Cockpit web console",
            packages=["cockpit", "cockpit-system", "cockpit-storaged", "cockpit-networkmanager",
                      "cockpit-selinux", "cockpit-packagekit"],
            deb_packages=["cockpit", "cockpit-system", "cockpit-storaged", "cockpit-networkmanager",
                          "cockpit-packagekit"],
            optional_packages=["cockpit-selinux", "cockpit-packagekit", "cockpit-storaged", "cockpit-networkmanager"],
            description="Browser-based host administration, useful where an enclave has no "
                        "terminal access to its servers.",
            version_package="cockpit",
            verification_commands=["sudo systemctl enable --now cockpit.socket"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch"],
        ),
        WorkloadProfile(
            key="time-sync",
            label="Time synchronisation (chrony)",
            packages=["chrony"],
            description="chrony NTP client. Clock drift inside an isolated network breaks "
                        "Kerberos, TLS validation and log correlation.",
            version_package="chrony",
            verification_commands=["sudo systemctl enable --now chronyd", "chronyc sources"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="git-scm",
            label="Git and version control",
            packages=["git", "git-lfs"],
            description="Git with large-file support, for running an internal repository or "
                        "working with code inside the enclave.",
            version_package="git",
            verification_commands=["git --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="net-diagnostics",
            label="Network diagnostics and packet analysis",
            packages=["tcpdump", "wireshark-cli", "bind-utils", "traceroute", "mtr", "iputils", "nmap", "nmap-ncat", "socat", "curl", "wget", "lsof", "strace", "ltrace", "psmisc", "iproute", "net-tools", "ethtool", "iperf3", "iftop", "whois", "telnet", "openssl", "conntrack-tools", "bridge-utils", "ngrep", "arp-scan", "sysstat", "tcpflow"],
            deb_packages=["tcpdump", "tshark", "dnsutils", "traceroute", "mtr-tiny", "iputils-ping", "iputils-arping", "nmap", "netcat-openbsd", "socat", "curl", "wget", "lsof", "strace", "ltrace", "psmisc", "iproute2", "net-tools", "ethtool", "iperf3", "iftop", "whois", "telnet", "openssl", "conntrack", "bridge-utils", "ngrep", "arp-scan", "sysstat", "tcpflow"],
            optional_packages=["wireshark-cli", "tshark", "ngrep", "arp-scan", "tcpflow", "iftop", "telnet", "conntrack-tools", "conntrack", "bridge-utils", "ltrace"],
            description="Packet capture and decode (tcpdump, tshark), DNS lookup, path and latency tracing, port and service scanning, socket and syscall inspection, throughput measurement, and link-layer tools. tshark is the command-line Wireshark; the GUI is not included because disconnected servers rarely have a desktop -- capture here and analyse the pcap elsewhere.",
            version_package=None,
            verification_commands=["tcpdump --version", "tshark --version", "dig -v", "mtr --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="security-audit",
            label="Security auditing, hardening and malware scanning",
            packages=["audit", "aide", "openscap-scanner", "openscap-utils", "scap-security-guide", "policycoreutils", "policycoreutils-python-utils", "setools-console", "libselinux-utils", "checkpolicy", "libpwquality", "clamav", "clamav-update", "rkhunter", "fail2ban", "openssl", "gnupg2", "sudo", "logrotate", "rsyslog"],
            deb_packages=["auditd", "audispd-plugins", "aide", "aide-common", "openscap-scanner", "apparmor-utils", "apparmor-profiles", "libpam-pwquality", "clamav", "clamav-freshclam", "rkhunter", "chkrootkit", "lynis", "fail2ban", "debsums", "openssl", "gnupg", "sudo", "logrotate", "rsyslog"],
            optional_packages=["rkhunter", "chkrootkit", "lynis", "fail2ban", "clamav", "clamav-update", "clamav-freshclam", "debsums", "aide", "aide-common", "openscap-scanner", "openscap-utils", "scap-security-guide", "apparmor-profiles", "setools-console", "audispd-plugins"],
            description="Audit daemon and rules, file integrity monitoring (AIDE), SCAP policy scanning, mandatory access control tooling (SELinux on RPM, AppArmor on Debian), rootkit and malware scanners, password quality enforcement and log handling. Several of these live in EPEL on RHEL-family targets, so enable EPEL on the Sources stage if they do not resolve.",
            version_package=None,
            verification_commands=["sudo systemctl enable --now auditd", "oscap --version", "aide --version", "freshclam --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="storage-tools",
            label="Storage, filesystem and disk management",
            packages=["lvm2", "mdadm", "nfs-utils", "xfsprogs", "e2fsprogs", "btrfs-progs", "parted", "gdisk", "dosfstools", "cryptsetup", "device-mapper-multipath", "iscsi-initiator-utils", "smartmontools", "hdparm", "sg3_utils", "nvme-cli", "rsync", "quota", "autofs", "sysstat", "lsscsi", "udisks2"],
            deb_packages=["lvm2", "mdadm", "nfs-common", "xfsprogs", "e2fsprogs", "btrfs-progs", "parted", "gdisk", "dosfstools", "cryptsetup", "multipath-tools", "open-iscsi", "smartmontools", "hdparm", "sg3-utils", "nvme-cli", "rsync", "quota", "autofs", "sysstat", "lsscsi", "udisks2"],
            optional_packages=["btrfs-progs", "nvme-cli", "sg3_utils", "sg3-utils", "lsscsi", "udisks2", "device-mapper-multipath", "multipath-tools", "iscsi-initiator-utils", "open-iscsi", "quota", "autofs", "gdisk"],
            description="Volume management, software RAID, network and local filesystems, partitioning, encryption, multipath and iSCSI, SMART health monitoring, and I/O statistics. Covers both provisioning new storage and diagnosing a failing disk on a host you cannot easily reach.",
            version_package=None,
            verification_commands=["lvm version", "mdadm --version", "smartctl --version", "iostat -V"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="build-toolchain",
            label="Build toolchain (compilers, autotools, debuggers)",
            packages=["gcc", "gcc-c++", "make", "cmake", "ninja-build", "automake", "autoconf", "libtool", "pkgconf-pkg-config", "bison", "flex", "patch", "diffutils", "gdb", "valgrind", "ccache", "binutils", "elfutils", "strace", "rpm-build", "git", "python3-devel", "glibc-devel", "kernel-headers"],
            deb_packages=["build-essential", "cmake", "ninja-build", "automake", "autoconf", "libtool", "pkg-config", "bison", "flex", "patch", "diffutils", "gdb", "valgrind", "ccache", "binutils", "elfutils", "strace", "dpkg-dev", "fakeroot", "git", "python3-dev", "libc6-dev"],
            optional_packages=["ccache", "valgrind", "ninja-build", "elfutils", "rpm-build", "fakeroot"],
            description="C and C++ compilers, both major build systems (make/autotools and cmake/ninja), parser generators, a debugger and memory checker, and the packaging tools for the target's own format (rpm-build or dpkg-dev). One of the largest closures here and one of the most common gaps on a minimal disconnected build host.",
            version_package=None,
            verification_commands=["gcc --version", "make --version", "cmake --version", "gdb --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="sysadmin-essentials",
            label="System administration essentials",
            packages=["vim-enhanced", "nano", "tmux", "screen", "less", "bash-completion", "htop", "procps-ng", "psmisc", "sysstat", "lsof", "tree", "unzip", "zip", "tar", "gzip", "bzip2", "xz", "rsync", "wget", "curl", "jq", "man-db", "which", "file", "dos2unix", "sudo", "policycoreutils"],
            deb_packages=["vim", "nano", "tmux", "screen", "less", "bash-completion", "htop", "procps", "psmisc", "sysstat", "lsof", "tree", "unzip", "zip", "tar", "gzip", "bzip2", "xz-utils", "rsync", "wget", "curl", "jq", "man-db", "file", "dos2unix", "sudo"],
            optional_packages=["htop", "tree", "jq", "dos2unix", "nano", "bash-completion", "tmux", "screen"],
            description="The tools an administrator reaches for within five minutes of logging into a host and finding them absent: an editor, a terminal multiplexer, process and resource inspection, archive handling, and JSON parsing. Small individually, tedious to discover one at a time across an air gap.",
            version_package=None,
            verification_commands=["vim --version | head -1", "tmux -V", "htop --version", "jq --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="monitoring-agents",
            label="Monitoring and performance analysis",
            packages=["sysstat", "htop", "iotop", "atop", "nmon", "perf", "bcc-tools", "numactl", "procps-ng", "lm_sensors", "smartmontools", "net-snmp", "net-snmp-utils", "rsyslog", "logrotate", "chrony"],
            deb_packages=["sysstat", "htop", "iotop", "atop", "nmon", "linux-tools-generic", "bpfcc-tools", "numactl", "procps", "lm-sensors", "smartmontools", "snmpd", "snmp", "rsyslog", "logrotate", "chrony"],
            optional_packages=["atop", "nmon", "iotop", "bcc-tools", "bpfcc-tools", "perf", "linux-tools-generic", "lm_sensors", "lm-sensors", "net-snmp", "net-snmp-utils", "snmpd", "snmp", "numactl"],
            description="Local performance and health telemetry: CPU/IO/memory statistics, per-process resource use, kernel tracing, hardware sensors and SNMP exposure. Intended for a host with no external monitoring reachable, where diagnosis has to happen on the box itself.",
            version_package=None,
            verification_commands=["sar -V", "iostat -V", "htop --version"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="pki-tls",
            label="PKI, certificates and TLS tooling",
            packages=["openssl", "ca-certificates", "nss-tools", "gnutls-utils", "gnupg2", "p11-kit", "openssl-perl", "crypto-policies-scripts"],
            deb_packages=["openssl", "ca-certificates", "libnss3-tools", "gnutls-bin", "gnupg", "p11-kit", "ssl-cert"],
            optional_packages=["nss-tools", "libnss3-tools", "gnutls-utils", "gnutls-bin", "p11-kit", "openssl-perl", "crypto-policies-scripts", "ssl-cert"],
            description="Certificate generation, inspection and trust-store management, plus GnuPG. Needed on any host that terminates TLS or validates an internal certificate authority, and commonly missing from minimal images.",
            version_package=None,
            verification_commands=["openssl version", "update-ca-trust --help || update-ca-certificates --help"],
            supported_distros=["rhel", "rocky", "alma", "centos-stream", "fedora", "ubuntu", "debian", "arch", "artix", "devuan"],
        ),
        WorkloadProfile(
            key="custom",
            label="Custom packages",
            packages=[],
            description="Enter one or more package names. The selected RPM or APT backend resolves and validates their dependency closure.",
            custom=True,
        ),        WorkloadProfile('kubernetes-node', 'Kubernetes node (kubeadm, self-managed)',
            ['kubelet', 'kubeadm', 'kubectl', 'cri-tools', 'kubernetes-cni'],
            'Choose a Kubernetes minor to select its community repository. OS dependencies use the Linux target sources. Container images and cluster setup are separate.',
            verification_commands=['kubeadm version', 'kubelet --version', 'kubectl version --client'],
            version_package='kubelet', version_role='kubernetes', version_axis='kubernetes-minor',
            versioned_packages=['kubelet', 'kubeadm', 'kubectl'],
            repository_roles=['kubernetes'], package_repository_roles={n: 'kubernetes' for n in ['kubelet','kubeadm','kubectl','cri-tools','kubernetes-cni']},
            supported_distros=['rhel','rocky','alma','centos-stream','fedora','ubuntu','debian']),
        WorkloadProfile('kubernetes-client', 'Kubernetes client tools (kubectl)', ['kubectl'],
            'Choose the minor repository for kubectl. Compatibility findings are advisory; exact package builds remain visible.',
            verification_commands=['kubectl version --client'],
            version_package='kubectl', version_role='kubernetes', version_axis='kubernetes-minor',
            versioned_packages=['kubectl'],
            repository_roles=['kubernetes'], package_repository_roles={'kubectl':'kubernetes'},
            supported_distros=['rhel','rocky','alma','centos-stream','fedora','ubuntu','debian','photon']),
        WorkloadProfile('vks-node-additions', 'VKS node OS package additions', [],
            'Customize a VKS node image with target OS packages. Feathered applies VKS-specific policy and Image Baker output while keeping the normal package chooser and dependency resolver available.',
            custom=True, contextual_packages=True, supported_distros=['photon','ubuntu','rhel'],
            supported_releases={'photon':['5.0'], 'ubuntu':['22.04','24.04'], 'rhel':['9']}),


    ]


def _external_catalog_paths() -> List[Path]:
    """Locations searched for an optional organisation workload catalog.

    Deliberately anchored to the application directory rather than the current
    working directory: a stray workloads.json in whatever folder the app was
    launched from should not silently redefine which packages get bundled.
    """
    paths: List[Path] = []
    try:
        if getattr(sys, "frozen", False):
            paths.append(Path(sys.executable).resolve().parent / "workloads.json")
    except Exception:
        pass
    paths.extend([
        Path(__file__).resolve().parent / "workloads.json",
    ])
    # Preserve order while removing duplicates.
    out: List[Path] = []
    seen = set()
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key); out.append(p)
    return out


def _parse_component(row: dict, position: int) -> WorkloadComponent:
    key = str(row.get("id", row.get("key", ""))).strip()
    raw_candidates = row.get("candidates", [])
    if isinstance(raw_candidates, dict):
        rpm = raw_candidates.get("rpm", [])
        deb = raw_candidates.get("deb", [])
    else:
        rpm = raw_candidates
        deb = []
    rpm = row.get("rpm_candidates", rpm)
    deb = row.get("deb_candidates", deb)
    rpm_candidates = [str(x).strip() for x in (rpm or []) if str(x).strip()]
    deb_candidates = [str(x).strip() for x in (deb or []) if str(x).strip()]
    if not key or not rpm_candidates:
        raise ValueError(f"component {position} needs a non-empty id/key and rpm candidate list")
    return WorkloadComponent(
        key=key,
        rpm_candidates=rpm_candidates,
        deb_candidates=deb_candidates or None,
        required=bool(row.get("required", True)),
        repository_role=(str(row.get("repository_role")).strip() if row.get("repository_role") else None),
    )


def _verify_external_catalog_signature(path: Path) -> bool:
    """Verify an optional detached workload-catalog signature fail-closed.

    Convention: ``workloads.json.sig`` plus ``workloads-catalog.gpg`` beside
    the catalog. If either trust artifact is present, both are required and the
    signature must verify. An entirely unsigned local catalog remains accepted
    for backwards compatibility and is recorded as unsigned in provenance.
    """
    signature = path.with_name(path.name + ".sig")
    keyring = path.with_name("workloads-catalog.gpg")
    if not signature.exists() and not keyring.exists():
        return False
    if not signature.is_file() or not keyring.is_file():
        raise ValueError(
            "signed workload catalog is incomplete; workloads.json.sig and "
            "workloads-catalog.gpg must both be present")
    # Import lazily to keep workload-model imports light and, more importantly,
    # route verifier selection through core's authenticated production policy.
    # Frozen builds must never fall back to an arbitrary executable from PATH.
    import core
    try:
        core.verify_openpgp(
            path.read_bytes(), signature.read_bytes(), str(keyring),
            "Workload catalog", core.Reporter())
    except Exception as exc:
        raise ValueError("workload catalog signature verification failed: " + str(exc)) from exc
    return True


def _parse_external(path: Path) -> List[WorkloadProfile]:
    signature_verified = _verify_external_catalog_signature(path)
    raw = path.read_bytes()
    catalog_sha256 = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode("utf-8"))
    rows = data.get("workloads", data if isinstance(data, list) else [])
    result: List[WorkloadProfile] = []
    if not isinstance(rows, list):
        raise ValueError("workloads.json must contain a list or a {'workloads': [...]} object")
    for position, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"entry {position} is not an object")
        key = str(row.get("key", "")).strip()
        label = str(row.get("label", "")).strip()
        components = [_parse_component(x, i) for i, x in enumerate(row.get("components", []) or [], 1)
                      if isinstance(x, dict)]
        packages = [str(x).strip() for x in row.get("packages", []) if str(x).strip()]
        if components and not packages:
            packages = [c.rpm_candidates[0] for c in components if c.rpm_candidates]
        if not key or not label or not packages:
            raise ValueError(f"entry {position} ({key or label or 'unnamed'}) needs a non-empty "
                             "'key', 'label' and either 'packages' or 'components'")
        result.append(WorkloadProfile(
            key=key,
            label=label,
            packages=packages,
            description=str(row.get("description", "User-defined package set.")),
            version_package=(str(row.get("version_package")).strip() if row.get("version_package") else None),
            # Match the built-in default rather than falling back to None,
            # which silently changed how versions were searched.
            version_role=(str(row.get("version_role")).strip() if row.get("version_role") else "dependency"),
            versioned_packages=[str(x).strip() for x in row.get("versioned_packages", []) if str(x).strip()],
            requires_docker_repo=bool(row.get("requires_docker_repo", False)),
            repository_roles=[str(x).strip() for x in row.get("repository_roles", []) if str(x).strip()],
            package_repository_roles={str(k).strip(): str(v).strip() for k, v in
                                      dict(row.get("package_repository_roles", {}) or {}).items()
                                      if str(k).strip() and str(v).strip()},
            # Previously dropped, so an external entry overriding a built-in key
            # silently lost this behaviour.
            docker_rootless_extra=bool(row.get("docker_rootless_extra", False)),
            verification_commands=[str(x) for x in row.get("verification_commands", []) if str(x).strip()],
            supported_distros=[str(x) for x in row.get("supported_distros", [])] or None,
            deb_packages=[str(x).strip() for x in row.get("deb_packages", []) if str(x).strip()] or None,
            optional_packages=[str(x).strip() for x in row.get("optional_packages", []) if str(x).strip()],
            contextual_packages=bool(row.get("contextual_packages", False)),
            components=components,
            catalog_revision=int(row.get("catalog_revision", data.get("catalog_revision", 1)) or 1),
            catalog_sha256=catalog_sha256,
            catalog_signature_verified=signature_verified,
        ))
    return result


def load_workloads(diagnostics: Optional[List[str]] = None) -> Dict[str, WorkloadProfile]:
    """Load the workload catalog, merging any organisation-supplied entries.

    A malformed catalog must not make the app unusable, but it must not be
    invisible either: previously a typo in workloads.json meant the built-in
    package set was bundled while the operator believed their own set had been
    used. Failures are appended to `diagnostics` for the caller to surface.
    """
    notes = diagnostics if diagnostics is not None else []
    rows = _builtins()
    # External entries with the same key replace built-ins, making the catalog
    # editable without changing resolver code.
    by_key: Dict[str, WorkloadProfile] = {x.key: x for x in rows}
    for path in _external_catalog_paths():
        if not path.is_file():
            continue
        try:
            items = _parse_external(path)
        except Exception as exc:
            notes.append(f"Ignored workload catalog {path}: {exc}. "
                         "The built-in workload list is being used instead.")
            continue
        for item in items:
            by_key[item.key] = item
        notes.append(f"Loaded {len(items)} workload definition(s) from {path}")
    # Keep built-in order, append genuinely new external entries.
    ordered: Dict[str, WorkloadProfile] = {}
    for item in rows:
        if item.key in by_key:
            ordered[item.key] = by_key[item.key]
    for key, item in by_key.items():
        if key not in ordered:
            ordered[key] = item
    return ordered


def workload_by_label(catalog: Dict[str, WorkloadProfile], label: str) -> WorkloadProfile:
    for item in catalog.values():
        if item.label == label:
            return item
    return catalog.get("custom") or next(iter(catalog.values()))
