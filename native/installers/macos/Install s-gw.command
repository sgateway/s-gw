#!/bin/zsh
set -euo pipefail

installer_dir=${0:A:h}
package_path="$installer_dir/__PACKAGE_FILE__"

fail() {
  print -u2 -- "s-gw installation failed: $1"
  if [[ -t 0 ]]; then
    read -k 1 "?Press any key to close."
    print
  fi
  exit 1
}

[[ -f "$package_path" ]] || fail "The bundled package is missing."
command -v node >/dev/null 2>&1 || fail "Node.js 20 or newer is required. Install it from https://nodejs.org and run this installer again."
command -v npm >/dev/null 2>&1 || fail "npm is required. Reinstall Node.js 20 or newer and run this installer again."

node_major=$(node -p 'Number(process.versions.node.split(".")[0])')
[[ "$node_major" -ge 20 ]] || fail "Node.js 20 or newer is required."

print -- "Installing s-gw __VERSION__..."
npm install --global "$package_path" || fail "npm could not install the package. Check your npm global-directory permissions."

sgw_bin=$(command -v s-gw || true)
if [[ -z "$sgw_bin" ]]; then
  candidate="$(npm prefix --global)/bin/s-gw"
  [[ -x "$candidate" ]] && sgw_bin="$candidate"
fi
[[ -n "$sgw_bin" ]] || fail "s-gw was installed but its command is not on PATH."

"$sgw_bin" setup --port 8718 || fail "Initial setup did not complete."
print -- "s-gw __VERSION__ is installed."

if [[ -t 0 ]]; then
  read -k 1 "?Press any key to close."
  print
fi
