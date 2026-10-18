"""Detect changes to authenticated verifier staging while source tests run.

The pinned installer check authenticates the initial files. This local snapshot
only detects subsequent changes; it is not an independent authentication root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat


def inventory(root: Path) -> dict[str, str]:
    files = {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise RuntimeError(f'Verifier staging contains a link/reparse point: {path}')
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            files[path.relative_to(root).as_posix()] = digest.hexdigest()
        elif not stat.S_ISDIR(info.st_mode):
            raise RuntimeError(f'Verifier staging contains a nonregular entry: {path}')
    if 'gpgv.exe' not in files or not any(name.lower().endswith('.dll') for name in files):
        raise RuntimeError('Verifier staging is incomplete')
    return files


def record(root: Path, snapshot: Path) -> None:
    files = inventory(root)
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text(json.dumps({'schema': 1, 'files': files}, sort_keys=True) + '\n', encoding='utf-8')


def verify(root: Path, snapshot: Path) -> None:
    expected = json.loads(snapshot.read_text(encoding='utf-8'))
    if expected != {'schema': 1, 'files': inventory(root)}:
        raise RuntimeError('Authenticated verifier staging changed during the source gates')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['record', 'verify'])
    parser.add_argument('root', type=Path)
    parser.add_argument('snapshot', type=Path)
    args = parser.parse_args()
    {'record': record, 'verify': verify}[args.operation](args.root, args.snapshot)
    print(f'Verifier staging snapshot {args.operation} passed.', flush=True)


if __name__ == '__main__':
    main()
