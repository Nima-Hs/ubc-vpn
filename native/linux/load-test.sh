#!/usr/bin/env bash
# Shows that the built library loads on another distribution with only the
# declared package dependencies installed. Expects the fake gateway to be
# listening on the host at 127.0.0.1:4444.
# Usage: load-test.sh <stage-dir> <version> <image> <install command>
set -euo pipefail

stage=$(cd "$1" && pwd)
version=$2
image=$3
install=$4
here=$(cd "$(dirname "$0")" && pwd)

docker run --rm --network host \
    -v "$stage:/opt/ubc-vpn:ro" -v "$here:/recipe:ro" \
    "$image" bash -euo pipefail -c "
        $install
        if ldconfig -p | grep libopenconnect; then
            echo 'error: a system libopenconnect is installed' >&2
            exit 1
        fi
        ldd /opt/ubc-vpn/bin/oc-probe /opt/ubc-vpn/lib/libopenconnect.so.5
        if ldd /opt/ubc-vpn/bin/oc-probe | grep 'not found'; then
            exit 1
        fi
        bash /recipe/check-probe.sh '$version' /opt/ubc-vpn/bin/oc-probe probe https://127.0.0.1:4444
    "
