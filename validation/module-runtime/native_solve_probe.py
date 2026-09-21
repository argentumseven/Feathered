"""Local DNF dependency solve check; does not run RPM's chroot transaction test."""
from pathlib import Path
import subprocess, tempfile, sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import native_conformance
from native_dnf_modules import run_modular_conformance
original = subprocess.run

def download_only(command, *args, **kwargs):
    if isinstance(command, list) and command and command[0] == 'dnf':
        command = [part for part in command if part not in ('--setopt=tsflags=test',)]
        command.insert(1, '--downloadonly')
    return original(command, *args, **kwargs)

subprocess.run = download_only
print('Local DNF module checks: dependency resolution and downloads only.', flush=True)
print('RPM transaction testing is unavailable: the sandbox denies chroot.', flush=True)
with tempfile.TemporaryDirectory(prefix='module-solve-') as path:
    print(run_modular_conformance(Path(path), native_conformance._make_rpm))
