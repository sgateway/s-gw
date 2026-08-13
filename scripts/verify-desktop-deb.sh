#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || "$1" != /workspace/*.deb ]]; then
  echo "usage: verify-desktop-deb.sh /workspace/<installer>.deb" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  "$1" \
  dbus-x11 \
  libgl1-mesa-dri \
  mesa-vulkan-drivers \
  xauth \
  xvfb

useradd --create-home --shell /bin/bash desktopqa

set +e
runuser -u desktopqa -- env \
  HOME=/home/desktopqa \
  dbus-run-session -- \
  xvfb-run -a \
  timeout 8s \
  /usr/bin/s-gw-desktop \
    --node-path /usr/lib/s-gw/runtime/node/bin/node \
    --cli-path /usr/lib/s-gw/runtime/package/dist/cli.js \
    --instance-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --background \
  >/tmp/s-gw-desktop-smoke.log 2>&1
status=$?
set -e

if [[ $status -ne 124 ]]; then
  cat /tmp/s-gw-desktop-smoke.log >&2
  echo "The installed desktop app exited before the bounded launch smoke completed (exit $status)." >&2
  exit 1
fi
