"""Generate one receiver workflow from the resolved transaction contract."""
from pathlib import Path
import shlex
import sys

SEAL_CHECK = '''
if [ -f bundle-index.json ]; then
  : "${FEATHERED_OPERATOR_KEYRING:?Set FEATHERED_OPERATOR_KEYRING to your trusted operator public keyring}"
  gpgv --keyring "$FEATHERED_OPERATOR_KEYRING" bundle-index.json.asc bundle-index.json
  gpgv --keyring "$FEATHERED_OPERATOR_KEYRING" verify-bundle.py.asc verify-bundle.py
  python3 verify-bundle.py
fi
'''


def write_installer(output, directory, result, options, family, metadata):
    import core
    from transaction_model import installation_roots
    output, directory = Path(output), Path(directory)
    sub = directory.relative_to(output).as_posix()
    source = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'receiver_preflight.py'
    (output / 'receiver-preflight.py').write_bytes(source.read_bytes())
    # Pin the full computed transaction. Installed-baseline artifacts are checked
    # by the preflight; native solving remains authoritative for reverse deps.
    from types import SimpleNamespace
    args = installation_roots(SimpleNamespace(roots=result.selected), family)
    (directory / 'TRANSACTION-ARGS.txt').write_text('\n'.join(args) + '\n', encoding='utf-8')
    script = '''#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
command -v python3 >/dev/null 2>&1 || {
  echo 'ERROR: python3 is required on the target to verify and install this bundle.' >&2
  exit 1
}
# A file: URL is a URL, not a path. An unencoded space, '#' or '%' in the bundle
# directory makes APT reparse the sources.list line into a different suite and
# ignore this repository entirely, and makes the dnf/pacman URLs invalid. Air-gap
# bundles routinely land on removable media such as /media/user/My Passport, so
# encode the path rather than assuming it is URL-safe. Paths made only of
# [A-Za-z0-9/._~-] are returned unchanged, so this cannot alter a working case.
HERE_URL="$(python3 -c 'import sys, urllib.parse
sys.stdout.write(urllib.parse.quote(sys.argv[1]))' "$HERE")"
if [ -z "$HERE_URL" ]; then
  echo 'ERROR: could not express the bundle path as a file: URL.' >&2
  exit 1
fi
''' + (SEAL_CHECK.replace('[ -f bundle-index.json ]', 'true') if options.sign_bundle_index else SEAL_CHECK) + f'''
python3 receiver-preflight.py {shlex.quote(sub + '/INSTALLATION-CONTRACT.json')}
( cd {shlex.quote(sub)} && sha256sum -c SHA256SUMS.txt )
# REQUESTED-ROOTS.txt records intent; TRANSACTION-ARGS.txt pins the whole resolved plan.
mapfile -t PLAN < <(sed '/^[[:space:]]*$/d' {shlex.quote(sub + '/TRANSACTION-ARGS.txt')})
if [ "${{#PLAN[@]}}" -eq 0 ]; then
  echo 'ERROR: no resolved transaction recorded' >&2
  exit 1
fi
'''
    if family == 'deb':
        script += '''
TMP_APT="$(mktemp -d)"
trap 'rm -rf "$TMP_APT"' EXIT
chmod 755 "$TMP_APT"
mkdir -p "$TMP_APT/lists/partial"
printf 'deb [trusted=yes] file:%s feathered main\\n' "$HERE_URL" > "$TMP_APT/feathered.list"
APT_OPTS=(-o "Dir::Etc::sourcelist=$TMP_APT/feathered.list" -o Dir::Etc::sourceparts=-
          -o "Dir::State::lists=$TMP_APT/lists" -o Acquire::Languages=none)
sudo apt-get "${APT_OPTS[@]}" update
# `apt-get update` reports success for a source it parsed into a suite that does
# not exist, so confirm the bundle index was actually read before installing.
# Deliberately not piped into grep: under `set -o pipefail` an early-exiting
# reader can SIGPIPE apt-get and fail the check on a healthy repository.
APT_INDEXES="$(sudo apt-get "${APT_OPTS[@]}" indextargets || true)"
case "$APT_INDEXES" in
  *"Created-By: Packages"*) ;;
  *)
    echo "ERROR: APT did not index the bundled repository at $HERE." >&2
    echo "       Check that dists/feathered exists and is readable, and that the" >&2
    echo "       bundle path contains no characters APT cannot address." >&2
    exit 1
    ;;
esac
# Native solver checks retained installed packages and reverse dependencies.
sudo apt-get "${APT_OPTS[@]}" --simulate --no-remove install "${PLAN[@]}"
sudo apt-get "${APT_OPTS[@]}" --no-remove install "${PLAN[@]}"
'''
    elif family == 'rpm':
        script += '''
PM=dnf
command -v dnf >/dev/null 2>&1 || PM=yum
TMP_REPOS="$(mktemp -d)"
trap 'rm -rf "$TMP_REPOS"' EXIT
cat >"$TMP_REPOS/feathered.repo" <<EOF
[feathered]
name=Feathered offline bundle
baseurl=file://$HERE_URL
enabled=1
gpgcheck=0
repo_gpgcheck=0
skip_if_unavailable=False
EOF
# DNF performs its native dependency/module/transaction checks before installation.
# No automatic erasure, module switch, or remote repository fallback is allowed.
# skip_if_unavailable=False keeps an unreadable bundle repository a hard failure
# rather than an empty transaction resolved against nothing.
sudo "$PM" --setopt="reposdir=$TMP_REPOS" --setopt="cachedir=$TMP_REPOS/cache" --disablerepo='*' --enablerepo=feathered install "${PLAN[@]}"
'''
    else:
        signed = all(p.pgpsig for p in result.selected)
        level = 'Required DatabaseOptional TrustedOnly' if signed else 'Optional DatabaseOptional TrustedOnly'
        if not signed:
            script += '''
if [ "${FEATHERED_ALLOW_UNSIGNED:-0}" != 1 ]; then
  echo 'ERROR: some package records lack signatures. Review provenance; set FEATHERED_ALLOW_UNSIGNED=1 only if you accept those unsigned artifacts.' >&2
  exit 1
fi
'''
        script += f'''
TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF"' EXIT
cat >"$TMP_CONF" <<EOF
[options]
Architecture = auto
SigLevel = {level}
LocalFileSigLevel = {level}
[feathered]
Server = file://$HERE_URL/packages
EOF
# The builder includes every repository-managed installed package in the plan.
# Synchronization and a whole-system upgrade are one native transaction.
sudo pacman --config "$TMP_CONF" -Syu "${{PLAN[@]}}"
'''
    script += f'\npython3 receiver-preflight.py {shlex.quote(sub + "/INSTALLATION-CONTRACT.json")} --post\n'
    for cmd in core.meta_str_list(metadata, 'verification_commands'):
        script += 'echo ' + shlex.quote('Suggested workload check: ' + cmd) + '\n'
    path = output / 'install-offline.sh'
    path.write_text(script, encoding='utf-8', newline='\n')
    core.make_executable(path)
