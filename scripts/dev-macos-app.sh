#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-run}"
APP_NAME="s-gw"
BUNDLE_ID="com.s-gw.sgw.app"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_BUNDLE="$ROOT_DIR/dist/$APP_NAME.app"
APP_BINARY="$APP_BUNDLE/Contents/MacOS/$APP_NAME"
NODE_BIN="$(command -v node || true)"

pkill -x "$APP_NAME" >/dev/null 2>&1 || true

(cd "$ROOT_DIR" && npx tsc -p tsconfig.json && npm run build:macos-app)

open_app() {
  if [ -n "$NODE_BIN" ]; then
    /usr/bin/open -n \
      --env "SGW_REPO_ROOT=$ROOT_DIR" \
      --env "SGW_CLI_PATH=$ROOT_DIR/dist/cli.js" \
      --env "SGW_NODE_PATH=$NODE_BIN" \
      "$APP_BUNDLE"
    return
  fi

  /usr/bin/open -n \
    --env "SGW_REPO_ROOT=$ROOT_DIR" \
    --env "SGW_CLI_PATH=$ROOT_DIR/dist/cli.js" \
    "$APP_BUNDLE"
}

case "$MODE" in
  run)
    open_app
    ;;
  --debug|debug)
    lldb -- "$APP_BINARY"
    ;;
  --logs|logs)
    open_app
    /usr/bin/log stream --info --style compact --predicate "process == \"$APP_NAME\""
    ;;
  --telemetry|telemetry)
    open_app
    /usr/bin/log stream --info --style compact --predicate "subsystem == \"$BUNDLE_ID\""
    ;;
  --verify|verify)
    open_app
    sleep 2
    pgrep -x "$APP_NAME" >/dev/null
    ;;
  *)
    echo "usage: $0 [run|--debug|--logs|--telemetry|--verify]" >&2
    exit 2
    ;;
esac
