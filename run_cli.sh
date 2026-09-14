#!/bin/sh
set -eu
FEATHERED_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
FEATHERED_RUNTIME=${FEATHERED_PYTHON:-"$FEATHERED_ROOT/.venv/current/bin/python"}
if [ ! -f "$FEATHERED_ROOT/linux_launch.py" ] || [ ! -f "$FEATHERED_ROOT/feathered_app/__init__.py" ]; then
    echo 'ERROR: Extract the complete Feathered archive, preserving its subfolders.' >&2
    exit 5
fi
if ! command -v "$FEATHERED_RUNTIME" >/dev/null 2>&1; then
    echo 'ERROR: Run bash install_linux.sh from the extracted Feathered folder first.' >&2
    exit 5
fi
exec "$FEATHERED_RUNTIME" "$FEATHERED_ROOT/linux_launch.py" cli "$@"
