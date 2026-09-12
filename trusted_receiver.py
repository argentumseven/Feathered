"""Verify a sealed bundle before executing any code from it.

Obtain this bootstrap and the operator public keyring through a trusted channel.
Usage: python3 trusted_receiver.py BUNDLE_DIRECTORY OPERATOR_KEYRING [--install]
"""
import os
from pathlib import Path
import subprocess
import sys


def verify(directory, keyring, install=False):
    directory, keyring = Path(directory).resolve(), Path(keyring).resolve(strict=True)
    for filename in ['bundle-index.json', 'verify-bundle.py']:
        subprocess.run(['gpgv', '--keyring', str(keyring), str(directory / (filename + '.asc')),
                        str(directory / filename)], check=True, cwd=directory)
    subprocess.run([sys.executable, str(directory / 'verify-bundle.py')], check=True, cwd=directory)
    if install:
        env = dict(os.environ, FEATHERED_OPERATOR_KEYRING=str(keyring))
        subprocess.run(['bash', str(directory / 'install-offline.sh')], check=True, cwd=directory, env=env)


if __name__ == '__main__':
    if len(sys.argv) not in {3, 4} or (len(sys.argv) == 4 and sys.argv[3] != '--install'):
        raise SystemExit(__doc__)
    verify(sys.argv[1], sys.argv[2], '--install' in sys.argv[3:])
