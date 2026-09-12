#!/usr/bin/env bash
# Run every native conformance tier, using containers for the package managers
# this host does not have.
#
# The APT, DNF and pacman tiers are the only evidence that Feathered's three
# hand-written resolvers produce closures the real package managers accept. Two
# of them have historically reported SKIP on every machine anyone ran them on,
# which is the same as not having them. This script gives each tier a host that
# can actually execute it.
#
#   ./run_native_conformance.sh              # all tiers, containers as needed
#   ./run_native_conformance.sh apt          # one tier
#   CONTAINER=docker ./run_native_conformance.sh
#
# Requires podman or docker for the DNF and pacman tiers. The APT tier runs
# natively on a Debian/Ubuntu host and in a container otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTAINER="${CONTAINER:-}"
if [[ -z "$CONTAINER" ]]; then
    if command -v podman >/dev/null 2>&1; then CONTAINER=podman
    elif command -v docker >/dev/null 2>&1; then CONTAINER=docker
    fi
fi

APT_IMAGE="${FEATHERED_APT_IMAGE:-debian:12}"
DNF_IMAGE="${FEATHERED_DNF_IMAGE:-rockylinux/rockylinux:9}"
PACMAN_IMAGE="${FEATHERED_PACMAN_IMAGE:-archlinux:base}"

TIERS=("${@:-apt dnf pacman}")
read -r -a TIERS <<< "${TIERS[*]}"

fail=0

note() { printf '\n=== %s ===\n' "$*"; }

need_container() {
    if [[ -z "$CONTAINER" ]]; then
        echo "ERROR: neither podman nor docker is available; cannot run the $1 tier here." >&2
        echo "       Install one, or run this tier on a native $1 worker." >&2
        return 1
    fi
}

# --minimal deps: python3 plus the tier's package manager and build tooling.
run_in() {
    local image="$1" tier="$2" setup="$3"
    "$CONTAINER" run --rm \
        -v "$ROOT:/src:ro" \
        -w /work \
        "$image" \
        bash -c "set -eux
                 $setup
                 cp -r /src/. /work/
                 python3 -m pip install --quiet --break-system-packages zstandard==0.25.0 \
                   || python3 -m pip install --quiet zstandard==0.25.0
                 python3 native_conformance.py --require $tier"
}

for tier in "${TIERS[@]}"; do
    case "$tier" in
        apt)
            note "APT tier"
            if command -v dpkg-deb >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
                ( cd "$ROOT" && python3 native_conformance.py --require apt ) || fail=1
            else
                need_container apt || { fail=1; continue; }
                run_in "$APT_IMAGE" apt \
                    "apt-get update -qq && apt-get install -y -qq python3 python3-pip dpkg-dev" \
                    || fail=1
            fi
            ;;
        dnf)
            note "DNF tier"
            need_container dnf || { fail=1; continue; }
            run_in "$DNF_IMAGE" dnf \
                "dnf -y install python3 python3-pip rpm-build createrepo_c >/dev/null" \
                || fail=1
            ;;
        pacman)
            note "pacman tier"
            need_container pacman || { fail=1; continue; }
            run_in "$PACMAN_IMAGE" pacman \
                "pacman -Sy --noconfirm python python-pip >/dev/null" \
                || fail=1
            ;;
        *)
            echo "unknown tier: $tier (expected apt, dnf or pacman)" >&2
            fail=1
            ;;
    esac
done

if (( fail )); then
    echo
    echo "Native conformance FAILED. Feathered's claim that its closures are complete is"
    echo "unproven for at least one package manager; do not ship on this result."
    exit 1
fi

echo
echo "Native conformance passed for: ${TIERS[*]}"
