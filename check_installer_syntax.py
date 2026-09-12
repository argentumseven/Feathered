"""Shell-syntax evidence for the installers Feathered emits.

Runs bash -n over a generated install-offline.sh for each package family.
Reuses the regression suite's own fixture constructors so the scripts checked
here are the scripts Feathered actually emits, not hand-written approximations.
Output is captured into validation/shell-syntax.txt when the release evidence
is regenerated.
"""
import hashlib, subprocess, sys, tempfile
from pathlib import Path
sys.path.insert(0, ".")
from test_feather import *
import apt_core, arch_core, core
from core import RepoSpec, BuildOptions, Reporter, Package

rows = []


def check(family, out):
    script = out / "install-offline.sh"
    if not script.is_file():
        rows.append((family, None, "no install-offline.sh emitted"))
        return
    proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    rows.append((family, proc.returncode == 0, proc.stderr.strip()))


with tempfile.TemporaryDirectory() as td:
    base = Path(td)

    # RPM
    root = base / "rpm"; root.mkdir()
    payload = root / "demo.rpm"; payload.write_bytes(b"rpm-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/")
    pkg = Package("demo", "x86_64", "0", "1", "1", "demo.rpm", "sha256",
                  hashlib.sha256(payload.read_bytes()).hexdigest(), repo,
                  size=payload.stat().st_size)
    out = root / "bundle"
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), out,
                      BuildOptions(retries=1), Reporter(), {"workload": "syntax-check"})
    check("RPM", out)

    # RPM, vendor-signed variant. The unsigned fixture above never reaches the
    # gpgcheck=1 branch or the key-preflight loop, so a shell syntax error
    # there would ship unnoticed.
    import installer as _installer, provenance as _prov

    class _SignedEntry:
        assurance = _prov.VERIFIED_VENDOR
        signer = "Fixture Vendor"
        repository = "fixture"

        def __init__(self, key_id):
            self.signing_key_id = key_id

    signed_out = root / "bundle-signed"
    signed_out.mkdir()
    (signed_out / "metadata").mkdir()
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), signed_out,
                      BuildOptions(retries=1), Reporter(), {"workload": "syntax-check"})
    _installer.write_installer(
        signed_out, signed_out / "metadata",
        core.ResolutionResult([pkg], [], [pkg]),
        BuildOptions(retries=1), 'rpm', {"workload": "syntax-check"},
        provenance_entries=[_SignedEntry("0xFD431D51B4B5F9B4"),
                            _SignedEntry("rsa4096 key ABCDEF0123456789:")])
    check("RPM (vendor-signed)", signed_out)

    # APT
    root = base / "apt"; root.mkdir()
    payload = root / "demo.deb"; payload.write_bytes(b"deb-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/", repo_format="apt", suite="stable",
                    components="main")
    deb = apt_core.DebPackage("demo", "amd64", "1.0", "demo.deb", "sha256",
                              hashlib.sha256(payload.read_bytes()).hexdigest(), repo,
                              size=payload.stat().st_size)
    out = root / "bundle"
    apt_core.write_bundle(apt_core.DebResolutionResult([deb], [], [deb]), out,
                          BuildOptions(retries=1), Reporter(), {"workload": "syntax-check"})
    check("APT", out)

    # Arch
    root = base / "arch"; root.mkdir()
    payload = root / "demo-1.0-x86_64.pkg.tar.zst"; payload.write_bytes(b"arch-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/", repo_format="arch")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    apkg = arch_core.ArchPackage(
        name="demo", arch="x86_64", version="1.0",
        location="demo-1.0-x86_64.pkg.tar.zst", checksum_type="sha256",
        checksum=digest, repo=repo, digests={"sha256": digest},
        size=payload.stat().st_size)
    apkg.provides = [arch_core.ArchRelation("demo", "=", "1.0", "provides")]
    out = root / "bundle"
    arch_core.write_bundle(arch_core.ArchResolutionResult([apkg], [], [apkg]), out,
                           BuildOptions(retries=1), Reporter(), {"workload": "syntax-check"})
    check("Arch", out)

print("Generated installer shell syntax (bash -n on the emitted install-offline.sh):")
for family, ok, detail in rows:
    label = {True: "PASS", False: "FAIL", None: "N/A"}[ok]
    print(f"  {label} {family}" + (f" - {detail}" if detail else ""))
