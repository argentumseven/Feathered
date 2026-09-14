"""Linux entry point: CLI remains independent of Tk and preserves caller paths."""
from __future__ import annotations
import sys
import importlib
from collections.abc import Callable
from typing import Protocol, cast
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


class DesktopWindow(Protocol):
    def destroy(self) -> None: ...
    def mainloop(self) -> None: ...


def main(mode: str, args: list[str]) -> int:
    if mode not in {'cli', 'gui'}:
        print('Choose cli or gui.', file=sys.stderr)
        return 5
    try:
        import zstandard, yaml  # noqa: F401
    except ImportError as exc:
        print(f'Missing Python dependency: {exc}. Run bash install_linux.sh again.', file=sys.stderr)
        return 5
    if mode == 'cli':
        cli_main = cast(Callable[[list[str]], int], importlib.import_module('feathered_cli').main)
        return cli_main(args)
    if args not in ([], ['--check']):
        print('Usage: feathered-gui [--check]', file=sys.stderr)
        return 5
    try:
        import tkinter as tk
    except ImportError:
        print('The GUI requires Tk. Install python3-tk and rerun bash install_linux.sh. '
              'The CLI does not require Tk.', file=sys.stderr)
        return 5
    # The legacy Tk composition root is loaded only for GUI launches. Keep the
    # launch boundary limited to the two lifecycle operations it actually uses.
    factory = cast(Callable[[], DesktopWindow], importlib.import_module('app').App)
    try:
        window = factory()
    except tk.TclError as exc:
        print(f'Cannot open the GUI: {exc}. Start it in a desktop session, '
              'or use feathered for a headless build.', file=sys.stderr)
        return 5
    if args == ['--check']:
        window.destroy()
        print('Feathered GUI startup check passed.')
    else:
        window.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else '', sys.argv[2:]))
