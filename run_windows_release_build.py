"""Run the native release builder without a nested PowerShell output pipeline."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', required=True, type=Path)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=1200)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('The release batch builder requires Windows.')
    batch = args.batch.resolve(strict=True)
    # cmd /s /c needs the outer quote pair around a quoted executable path.
    # These paths come from the worker, never from package metadata.
    command = os.environ['COMSPEC']
    if any(c in str(batch) + command for c in '"\r\n%'):
        parser.error('Unsupported characters in the native builder path.')
    argv = f'"{command}" /d /s /c ""{batch}" --release"'
    args.log.parent.mkdir(parents=True, exist_ok=True)
    with args.log.open('wb') as output:
        process = subprocess.Popen(
            argv, executable=command, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + args.timeout
        offset = 0
        with args.log.open('rb') as progress:
            try:
                while True:
                    progress.seek(offset)
                    chunk = progress.read()
                    offset = progress.tell()
                    if chunk:
                        print(chunk.decode('utf-8', errors='replace'), end='', flush=True)
                    status = process.poll()
                    if status is not None:
                        # Include anything written between the final read and exit.
                        print(progress.read().decode('utf-8', errors='replace'), end='', flush=True)
                        return status
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(argv, args.timeout)
                    time.sleep(1)
            finally:
                if process.poll() is None:
                    subprocess.run(
                        ['taskkill.exe', '/pid', str(process.pid), '/t', '/f'],
                        stdin=subprocess.DEVNULL, check=False,
                    )
                    process.wait(timeout=30)


if __name__ == '__main__':
    raise SystemExit(main())
