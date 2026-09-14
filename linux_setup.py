"""Install pinned dependencies and optional user shortcuts without system pip.

Each environment is created at its permanent path. A successful dependency and
entry-point probe precedes switching `current`; failed upgrades retain the old
runtime. Existing environments remain available for manual rollback/removal.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Iterator
import uuid
import venv

ROOT = Path(__file__).resolve().parent
MANAGED = '# Managed by Feathered Linux setup\n'
DESKTOP_MARKER = 'X-Feathered-Managed=true\n'


def desktop_argument(value: str) -> str:
    """Apply Exec quoting, then desktop-entry string escaping (two layers)."""
    if any(ch in value for ch in '\n\r\x00'):
        raise ValueError('Launcher paths must not contain newlines or NUL.')
    quoted = ''.join('\\' + ch if ch in '\\"`$' else ch for ch in value)
    return '"' + quoted.replace('\\', '\\\\').replace('%', '%%') + '"'


def shortcuts(root: Path, bin_dir: Path, desktop_dir: Path, cli_only: bool) -> dict[Path, tuple[str, int]]:
    result = {}
    for command, mode in (('feathered', 'cli'), ('feathered-gui', 'gui')):
        if cli_only and mode == 'gui':
            continue
        script = root / f'run_{mode}.sh'
        result[bin_dir / command] = ('#!/bin/sh\n' + MANAGED +
            f'exec /bin/sh {shlex.quote(str(script))} "$@"\n', 0o755)
    if not cli_only:
        # The executable is a fixed path; the source path is a quoted argument,
        # so even '=' in an extraction directory is valid per the Exec grammar.
        result[desktop_dir / 'org.feathered.Feathered.desktop'] = (
            '[Desktop Entry]\nType=Application\nName=Feathered\n'
            'Comment=Build verified offline Linux package bundles\n'
            'Exec=/bin/sh ' + desktop_argument(str(root / 'run_gui.sh')) + '\n'
            'Icon=applications-system\nTerminal=false\nCategories=System;Utility;\n' + DESKTOP_MARKER,
            0o644)
    return result


def check_shortcuts(files: dict[Path, tuple[str, int]]) -> None:
    for path in files:
        if path.is_symlink():
            raise ValueError(f'Refusing to replace shortcut symlink: {path}')
        if path.exists():
            text = path.read_text(encoding='utf-8')
            if not (text.startswith('#!/bin/sh\n' + MANAGED) or
                    (text.startswith('[Desktop Entry]\n') and DESKTOP_MARKER in text.splitlines(keepends=True))):
                raise ValueError(f'Refusing to overwrite a file not managed by Feathered: {path}')


def atomic_text(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.feathered-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def installation_lock(root: Path) -> Iterator[None]:
    lock = root / '.venv' / 'install.lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError(f'Another setup may be running. If it stopped, remove {lock} and retry.') from None
    try:
        yield
    finally:
        lock.rmdir()


def install(root: Path, *, cli_only: bool, wheelhouse: Path | None,
            files: dict[Path, tuple[str, int]]) -> Path:
    for name in ('requirements.txt', 'app.py', 'feathered_cli.py', 'linux_launch.py', 'feathered_app/__init__.py'):
        if not (root / name).is_file():
            raise ValueError(f'Incomplete source folder: missing {name}. Extract the complete archive.')
    if wheelhouse is not None and not wheelhouse.is_dir():
        raise ValueError(f'Wheel directory does not exist: {wheelhouse}')
    check_shortcuts(files)
    with installation_lock(root):
        current = root / '.venv' / 'current'
        if current.exists() and not current.is_symlink():
            raise ValueError(f'Refusing to replace an unmanaged runtime path: {current}')
        previous = os.readlink(current) if current.is_symlink() else None
        candidate = root / '.venv' / 'environments' / uuid.uuid4().hex
        saved: dict[Path, tuple[str, int] | None] = {}
        pending = current.with_name('current-' + uuid.uuid4().hex)
        switched = False
        try:
            print('Preparing an isolated Python environment...', flush=True)
            venv.EnvBuilder(with_pip=True).create(candidate)
            python = candidate / 'bin' / 'python'
            if not cli_only:
                subprocess.run([str(python), '-I', '-c', 'import tkinter'], check=True)
            command = [str(python), '-I', '-m', 'pip', 'install', '--disable-pip-version-check',
                       '--only-binary=:all:', '-r', str(root / 'requirements.txt')]
            if wheelhouse is not None:
                command.extend(['--no-index', '--find-links', str(wheelhouse)])
            subprocess.run(command, check=True)
            subprocess.run([str(python), '-I', '-c', 'import zstandard, yaml'], check=True)
            subprocess.run([str(python), '-I', str(root / 'feathered_cli.py'), '--help'],
                           check=True, stdout=subprocess.DEVNULL)
            # Recheck before publication in case setup took a long time.
            check_shortcuts(files)
            for path, (text, mode) in files.items():
                saved[path] = (path.read_text(encoding='utf-8'), path.stat().st_mode & 0o777) if path.exists() else None
                atomic_text(path, text, mode)
            pending.symlink_to(candidate.relative_to(current.parent), target_is_directory=True)
            pending.replace(current)
            switched = True
            return python
        finally:
            pending.unlink(missing_ok=True)
            if not switched:
                for path, content in reversed(list(saved.items())):
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_text(path, *content)
                shutil.rmtree(candidate, ignore_errors=True)
            elif previous:
                print(f'Previous environment retained for rollback: {previous}')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Install Feathered GUI and CLI for the current Linux user.')
    parser.add_argument('--cli-only', action='store_true', help='omit Tk checks and desktop/GUI shortcuts')
    parser.add_argument('--no-shortcuts', action='store_true', help='install dependencies only; use the source launchers')
    parser.add_argument('--wheelhouse', type=Path, help='install only from this local wheel directory, without a package index')
    parser.add_argument('--bin-dir', type=Path, default=Path.home() / '.local/bin')
    data_home = Path(os.environ.get('XDG_DATA_HOME', ''))
    if not data_home.is_absolute():
        data_home = Path.home() / '.local/share'
    parser.add_argument('--desktop-dir', type=Path, default=data_home / 'applications')
    args = parser.parse_args(argv)
    if not sys.platform.startswith('linux') or sys.version_info < (3, 10):
        parser.error('Use Linux with Python 3.10 or newer.')
    try:
        files = {} if args.no_shortcuts else shortcuts(ROOT, args.bin_dir.expanduser().resolve(),
                                                      args.desktop_dir.expanduser().resolve(), args.cli_only)
        install(ROOT, cli_only=args.cli_only, wheelhouse=args.wheelhouse, files=files)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'Setup failed: {exc}', file=sys.stderr)
        print('On Ubuntu/Debian, install python3 and python3-venv; add python3-tk for the GUI. '
              'An existing runtime remains selected when setup fails.', file=sys.stderr)
        return 1
    print('Installed. CLI: bash run_cli.sh --help' + ('' if args.cli_only else '; GUI: bash run_gui.sh'))
    if files:
        print(f'Commands installed in {args.bin_dir.expanduser().resolve()}. Add this directory to PATH if needed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
