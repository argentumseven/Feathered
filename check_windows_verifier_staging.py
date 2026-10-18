"""Exercise the real Windows staging boundary with a corrupted installer."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    script = Path(__file__).with_name('stage_gpgv.ps1').resolve()
    with tempfile.TemporaryDirectory(prefix='Feathered verifier check ') as folder:
        root = Path(folder)
        bad = root / 'corrupt-installer.exe'
        bad.write_bytes(b'not the authenticated GnuPG installer')
        destination = root / 'existing destination'
        destination.mkdir()
        marker = destination / 'keep.txt'
        marker.write_bytes(b'preserve existing output')
        env = dict(os.environ, FEATHERED_GNUPG_INSTALLER=str(bad),
                   FEATHERED_BUILD_TEMP=str(root / 'staging directory with spaces'))
        result = subprocess.run(
            ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-File', str(script),
             '-Destination', str(destination)], env=env,
            capture_output=True, text=True, timeout=30)
        if result.returncode == 0 or 'SHA-256 mismatch' not in result.stdout + result.stderr:
            raise RuntimeError(f'Corrupt installer was not rejected by the digest gate: {result.stdout}{result.stderr}')
        if list(destination.iterdir()) != [marker] or marker.read_bytes() != b'preserve existing output':
            raise RuntimeError('Rejected installer modified existing verifier output')
    print('Corrupt installer rejected before extraction; existing output preserved.')


if __name__ == '__main__':
    main()
