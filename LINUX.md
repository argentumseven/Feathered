# Ubuntu and Debian: GUI and CLI

Feathered uses the same Tk GUI, saved specifications, build engine and CLI on
Linux and Windows. The Linux distribution is the complete source ZIP with a
per-user installer. It installs the pinned Python dependencies into an isolated
environment; it does not install Python packages into the OS interpreter.

The platform matrix targets Debian 12 and Ubuntu 22.04/24.04, with Python 3.10 or
newer. The GUI requires a desktop session with Tk support (X11 or XWayland). The
CLI requires neither Tk nor a display.

## Install both interfaces

Extract the complete archive into a directory you own and intend to keep. Keep
all subdirectories together. Install the OS prerequisites:

```bash
sudo apt-get update
sudo apt-get install python3 python3-venv python3-tk ca-certificates gnupg
```

From the extracted Feathered directory:

```bash
bash install_linux.sh
bash run_gui.sh
bash run_cli.sh --help
```

Setup adds the Feathered application-menu entry and these commands under
`~/.local/bin`:

- `feathered-gui`: launch the existing desktop GUI.
- `feathered`: run the existing command-line interface.

Add `~/.local/bin` to PATH if your session does not already include it. The desktop
entry uses an absolute source path and does not depend on PATH. `XDG_DATA_HOME`
controls the application-menu entry's location; `--bin-dir` and `--desktop-dir`
provide explicit alternatives. `--no-shortcuts` installs only the runtime, leaving
both source launchers available.

Existing files not managed by this installer are not overwritten. Setup does not
copy the source into a different installation prefix; keep the extracted folder.

## CLI-only machines

```bash
sudo apt-get install python3 python3-venv ca-certificates gnupg
bash install_linux.sh --cli-only
bash run_cli.sh show --spec build.json
bash run_cli.sh build --spec build.json --out ./bundles
```

CLI-only setup omits the Tk check and creates only the `feathered` command. Add
`python3-tk` and rerun setup without `--cli-only` to enable the GUI later. Switching
to CLI-only setup does not delete previously created desktop shortcuts.

Arguments and exit codes are passed through unchanged. Relative specification,
runtime-configuration and output paths are resolved from the caller's working
directory. Launching never downloads dependencies automatically. The CLI retains
its explicit trust, conflict and output-reuse decisions; see [CLI.md](CLI.md).

## Offline dependency installation

On a connected Linux machine matching the destination's CPU architecture and
Python minor version, prepare the wheels:

```bash
python3 -m pip download --require-hashes --only-binary=:all: -r requirements-runtime.lock -d wheels
```

Transfer the complete source archive and that wheel directory to the workstation:

```bash
bash install_linux.sh --wheelhouse /path/to/wheels
# Or add --cli-only on a headless workstation.
```

This mode disables package-index access. OS prerequisites must already be
installed or supplied separately through the organization's OS package process.
The runtime lock authenticates the accepted dependency wheels. A missing compatible wheel or hash fails installation rather than silently selecting another version or contacting an index. The shipped lock covers CPython 3.10 through 3.14 on Windows x86-64 and glibc Linux x86-64.

## Updates, rollback and removal

Rerun setup after replacing the source or moving the extracted directory. Setup
creates a fresh environment at its permanent path under `.venv/environments/`,
installs dependencies, probes imports and CLI startup, then changes
`.venv/current`. A failed attempt keeps the previously selected runtime and
restores any shortcuts it changed. An installation lock rejects a concurrent
setup against the same source directory.

Old environments remain in place. Setup prints the previous environment's path;
retain it if you need to roll back the dependency environment. This does not roll
back source changes: retain the previous complete archive for a full rollback.
Python environments are not portable between moved folders or machines.

To remove the installation, remove its generated `feathered`/`feathered-gui`
commands, `org.feathered.Feathered.desktop` entry, and extracted source folder.
GUI settings remain under `$XDG_CONFIG_HOME/feathered` (normally
`~/.config/feathered`); output bundles remain where you chose to save them.

Advanced users can set `FEATHERED_PYTHON` to an explicit interpreter when running
the source launchers. That interpreter must have the required dependencies.

## Validation

`bash run_gui.sh --check` constructs and closes the actual application window.
For a complete installed-client check, install `dpkg-dev` and run:

```bash
.venv/current/bin/python check_linux_installation.py
# Headless variant:
.venv/current/bin/python check_linux_installation.py --cli-only
```

The check creates a real DEB and local APT repository, invokes the installed CLI
from a different working directory, verifies declined/accepted trust exit codes,
and compares bundled bytes, checksums and provenance. The GUI variant opens the
same App used by normal launches. Xvfb can supply a display in CI.

Local evidence in this batch covers Ubuntu 24.04 with CPython 3.12.14. The added
CI matrix tests Debian 12 and Ubuntu 22.04/24.04 using their system interpreters,
including a CLI installation before Tk is installed. Those new matrix jobs have
not yet run remotely. Native `.deb` application packaging remains separate work.

The setup design follows Python's [virtual-environment lifecycle rules](https://docs.python.org/3/library/venv.html)
and the desktop entry's [argument-escaping rules](https://specifications.freedesktop.org/desktop-entry-spec/latest/exec-variables.html).
