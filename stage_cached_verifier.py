"""Reuse preflight extraction only when every PE matches the pinned installer.

Component hashes were measured after authenticating installer SHA-256 below:
https://github.com/argentumseven/Feathered/actions/runs/39174707588
This avoids opening/copying the installer a second time in the batch builder.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from verifier_stage_snapshot import inventory

INSTALLER_SHA256 = '2E5841E345D56F05199351BFCF585D28C6DC2326C8F76962F1E402F41F6D10E9'
COMPONENTS: dict[str, str] = {
    "gpgv.exe": "2f594d6ca46b34094e3c1b4ea6b462b20807b8dd34840d2dfcc2c4599dcab25b",
    "libassuan-9.dll": "0a9d955632ca759f30beb8b9f4e5b717cdb8145b0411e3e347d37bfe509c7efb",
    "libgcrypt-20.dll": "eefc7f8b5a1117e73603bb863abdfff8db0b6fb27574f1e62988147a085984dc",
    "libgpg-error-0.dll": "8aafdabc6db036c9fb3b6f138ece2764ce3116226f544231122fdecd0fb3b035",
    "libksba-8.dll": "17e4b843a4df8715c027e656f4a40ee1857c9c5bd709ba5783b7278f8696d1f5",
    "libnpth-0.dll": "5c2c3eed2f877ceaa3ec992941dc0b53d72013462ae68adb3191dbcf84c89eb5",
    "libntbtls-0.dll": "f6495b39fe6b700e30a2ddc0943c100b0263281b35ff64d477b2adfc4aa28778",
    "libsqlite3-0.dll": "59d46fb1e2bbde849e6fad2f73ecf184e48d99dc37d6d31c5e8f0fef7c482a71",
    "zlib1.dll": "7391114b4629b84f006de4d20cb310c3af7ae1cad896f60337215ed91bde766e"
}


def authenticate(root: Path) -> None:
    files = inventory(root)
    files.pop('VERIFIER-VERSION.txt', None)
    if not COMPONENTS or files != COMPONENTS:
        raise RuntimeError('Cached verifier does not match the pinned installer component hashes')


def stage(source: Path, destination: Path) -> None:
    authenticate(source)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError('Preserve the existing verifier destination before retrying')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix='verifier-', dir=destination.parent))
    try:
        for name in COMPONENTS:
            shutil.copyfile(source / name, temporary / name, follow_symlinks=False)
        authenticate(temporary)
        result = subprocess.run(
            [str((temporary / 'gpgv.exe').resolve()), '--version'],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=True,
        )
        (temporary / 'VERIFIER-VERSION.txt').write_bytes(result.stdout)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    stage(args.source, args.destination)
    print('Staged verifier from exact pinned component hashes; execution passed.', flush=True)


if __name__ == '__main__':
    main()
