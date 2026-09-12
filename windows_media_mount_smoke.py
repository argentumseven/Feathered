"""Windows release smoke probe for Feathered's real disc-image mount path.

This helper is intentionally UI-free: it invokes MediaMixin._mount_disc_image
with a tiny probe object while replacing message-box calls with captured text.
The surrounding PowerShell gate is responsible for dismounting the ISO even if
this process fails after Windows attached the image.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from feathered_app.application.media import MediaMixin
import feathered_app.application.media as media_module


class _MountProbe(MediaMixin):
    def __init__(self) -> None:
        self.logs: list[str] = []

    def _log(self, message: str) -> None:
        self.logs.append(str(message))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Exercise Feathered's actual Windows ISO mount implementation.")
    parser.add_argument("--iso", required=True, type=Path)
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("ERROR: windows_media_mount_smoke.py must run on Windows.", file=sys.stderr)
        return 2

    try:
        image = args.iso.resolve(strict=True)
    except OSError as exc:
        print(f"ERROR: ISO fixture is not readable: {exc}", file=sys.stderr)
        return 2

    infos: list[str] = []
    errors: list[str] = []
    original_info = media_module.messagebox.showinfo
    original_error = media_module.messagebox.showerror
    media_module.messagebox.showinfo = lambda *a, **k: infos.append(str(a[-1]) if a else "")
    media_module.messagebox.showerror = lambda *a, **k: errors.append(str(a[-1]) if a else "")
    try:
        probe = _MountProbe()
        root = probe._mount_disc_image(image)
    finally:
        media_module.messagebox.showinfo = original_info
        media_module.messagebox.showerror = original_error

    if root is None:
        detail = errors[-1] if errors else "_mount_disc_image returned no drive root"
        print(f"ERROR: Feathered mount path failed: {detail}", file=sys.stderr)
        return 1
    if not root.is_dir():
        print(f"ERROR: Feathered returned a drive root that is not accessible: {root}", file=sys.stderr)
        return 1

    print(f"Feathered _mount_disc_image mounted {image} at {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
