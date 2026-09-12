#!/usr/bin/env bash
# Collect the installed-package inventory of a disconnected target so the
# builder can avoid bundling dependencies the target already satisfies.
#
# Correctness note: this file is used to REMOVE packages from a bundle, so a
# false "already installed" is worse than a false "missing". Everything below
# errs toward reporting less.
set -euo pipefail

OUT="${1:-target-inventory.txt}"
TMP="$(mktemp "${OUT}.XXXXXX")"
# Never leave a half-written or error-bearing inventory behind: the builder
# cannot tell a truncated file from a target with very little installed.
trap 'rm -f "$TMP"' EXIT

{
  echo "# FEATHER-INVENTORY-V1"
  echo "META|generated|$(date --iso-8601=seconds 2>/dev/null || date)"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "META|id|${ID:-unknown}"
    echo "META|version_id|${VERSION_ID:-unknown}"
    echo "META|codename|${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
  fi
  echo "META|arch|$(uname -m)"

  if command -v pacman >/dev/null 2>&1 && { [ "${ID:-}" = "arch" ] || pacman -Q pacman >/dev/null 2>&1; }; then
    FAMILY=arch
    echo "META|package_family|arch"
    # pacman -Q emits exactly name + installed version. Architecture is not
    # needed for Feathered's conservative installed-package satisfaction check.
    pacman -Q | awk -v arch="$(uname -m)" '{print "PAC|" $1 "|" $2 "|" arch}'
  elif command -v rpm >/dev/null 2>&1 && rpm -q rpm >/dev/null 2>&1; then
    FAMILY=rpm
    echo "META|package_family|rpm"
    rpm -qa --qf 'PKG|%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n[PROVIDE|%{PROVIDENAME}|%{PROVIDEFLAGS:depflags}|%{PROVIDEVERSION}\n]'
  elif command -v dpkg-query >/dev/null 2>&1; then
    FAMILY=deb
    echo "META|package_family|deb"
    # Report only packages that are actually unpacked and configured.
    # A bare `dpkg-query -W` also lists packages in the 'rc' state (removed,
    # config files retained) and 'un' placeholders created by other packages'
    # dependency relationships. Treating those as installed made the resolver
    # drop dependencies that are NOT present on the target, producing bundles
    # that fail to install after they had already crossed the air gap.
    dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Version}|${Architecture}|${Provides}|${Multi-Arch}\n' \
      | awk -F'|' '$1 ~ /^(ii|hi)/ { sub(/^[^|]*\|/, ""); print "DEB|" $0 }'
  else
    echo "No supported pacman, RPM, or dpkg package database found" >&2
    exit 2
  fi
  DETAILS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/target_inventory_details.py"
  if command -v python3 >/dev/null 2>&1 && [ -f "$DETAILS" ]; then
    python3 "$DETAILS" "$FAMILY"
  fi
} > "$TMP"

# Only publish the inventory once collection has fully succeeded.
mv "$TMP" "$OUT"
trap - EXIT
echo "Wrote $OUT"
printf 'Records: %s\n' "$(grep -c -E '^(PKG|DEB|PAC)\|' "$OUT" || true)"
