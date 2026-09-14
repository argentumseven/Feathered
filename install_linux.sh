#!/bin/sh
set -eu
FEATHERED_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec "${FEATHERED_PYTHON:-python3}" "$FEATHERED_ROOT/linux_setup.py" "$@"
