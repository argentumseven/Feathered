"""Move methods between classes without a regex.

Written after a regex-based extraction silently broke `_mirror_layout` in 1.2.12:
slicing from ``\\n    def NAME(`` left the preceding ``@property`` decorator
orphaned, which then attached itself to the next method in the destination file.
The method became a property, and nothing noticed until it was called.

An AST knows where a function actually begins -- decorators included -- so this
cannot make that mistake. It also refuses to move a method that carries a
decorator, because a decorated method usually depends on something at the class
or module level that a bare move would leave behind; those need a human.

Not part of the runtime application. This development helper moves methods
between application modules while preserving indentation and refusing unsafe
decorated-method moves.

    python tools/move_methods.py --from feathered_app/application/x.py \\
        --class XMixin --to feathered_app/new.py --names _a _b --check
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import List, Tuple


def _class_node(tree: ast.Module, name: str) -> ast.ClassDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    raise SystemExit(f"ERROR: no class {name} in the source file")


def extract(source: str, class_name: str, names: List[str]) -> Tuple[str, List[str]]:
    """Return ``(remaining_source, [method_source, ...])``.

    Spans come from the AST, so a decorator is part of the method it decorates
    and can never be left behind or picked up by the following one.
    """
    tree = ast.parse(source)
    klass = _class_node(tree, class_name)
    lines = source.splitlines(keepends=True)

    wanted = {}
    for node in klass.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in names:
            continue
        if node.decorator_list:
            raise SystemExit(
                f"ERROR: {node.name} is decorated; move it by hand. A decorator "
                "usually depends on class or module context this tool does not "
                "carry across.")
        # decorator_list is empty, so lineno is the `def` itself; end_lineno is
        # inclusive and 1-based.
        wanted[node.name] = (node.lineno - 1, node.end_lineno)

    missing = [name for name in names if name not in wanted]
    if missing:
        raise SystemExit(f"ERROR: not found in {class_name}: {', '.join(missing)}")

    bodies = []
    for name in names:  # preserve the order the caller asked for
        start, end = wanted[name]
        bodies.append("".join(lines[start:end]).rstrip("\n"))

    for start, end in sorted(wanted.values(), reverse=True):
        del lines[start:end]
    return "".join(lines), bodies


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source", type=Path, required=True)
    parser.add_argument("--class", dest="class_name", required=True)
    parser.add_argument("--names", nargs="+", required=True)
    parser.add_argument("--to", type=Path, help="append to this module's last class")
    parser.add_argument("--check", action="store_true",
                        help="report what would move and exit without writing")
    args = parser.parse_args(argv)

    source = args.source.read_text(encoding="utf-8")
    remaining, bodies = extract(source, args.class_name, args.names)

    if args.check or args.to is None:
        for name, body in zip(args.names, bodies):
            print(f"{name}: {len(body.splitlines())} lines")
        print(f"{len(bodies)} method(s) would move; source would lose "
              f"{len(source.splitlines()) - len(remaining.splitlines())} lines")
        return 0

    ast.parse(remaining)  # never leave the source unparseable
    args.source.write_text(remaining, encoding="utf-8")
    destination = args.to.read_text(encoding="utf-8").rstrip("\n")
    merged = destination + "\n\n" + "\n\n".join(bodies) + "\n"
    ast.parse(merged)
    args.to.write_text(merged, encoding="utf-8")
    print(f"moved {len(bodies)} method(s) into {args.to}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
