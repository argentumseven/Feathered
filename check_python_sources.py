"""Compile every in-scope Python source file without creating bytecode.

The release tree has grown beyond a small hand-maintained module list.  This
gate derives its coverage from the same source-scope rules used by
SOURCE-SHA256.json, so newly extracted modules are checked automatically.
"""
from __future__ import annotations

import argparse
import tokenize
from pathlib import Path
from typing import Iterator, Tuple

from source_manifest import iter_source_files

ROOT = Path(__file__).resolve().parent


def python_sources(root: Path) -> Iterator[Tuple[str, Path]]:
    root = Path(root).resolve()
    for relative in iter_source_files(root):
        if relative.endswith(".py"):
            yield relative, root / relative


def check_python_sources(root: Path) -> list[str]:
    failures: list[str] = []
    count = 0
    for relative, path in python_sources(root):
        count += 1
        try:
            with tokenize.open(str(path)) as handle:
                source = handle.read()
            compile(source, relative, "exec", dont_inherit=True)
        except (OSError, SyntaxError, UnicodeError) as exc:
            failures.append(f"{relative}: {exc}")
    if failures:
        for failure in failures:
            print(f"PYTHON SOURCE ERROR: {failure}")
    else:
        print(f"Python source syntax gate passed ({count} files).")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=str(ROOT))
    args = parser.parse_args()
    return 1 if check_python_sources(Path(args.root)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
