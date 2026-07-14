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

npm_prefix=$(npm prefix --global) || fail "npm did not report its global prefix."
npm_root=$(npm root --global --prefix "$npm_prefix") || fail "npm did not report its global package directory."
package_metadata=$(npm pack --dry-run --ignore-scripts --json -- "$package_path") || fail "The bundled package metadata could not be verified."
package_identity=$(print -r -- "$package_metadata" | node -e '
let data = "";
process.stdin.on("data", chunk => data += chunk);
process.stdin.on("end", () => {
  const item = JSON.parse(data)[0];
  process.stdout.write(`${item && item.name || ""}\t${item && item.version || ""}`);
});
') || fail "The bundled package metadata is invalid."
package_name=${package_identity%%$'\t'*}
package_version=${package_identity#*$'\t'}
[[ "$package_name" == "@s-gw/s-gw" && -n "$package_version" ]] || fail "The bundled archive is not the scoped @s-gw/s-gw package."

old_sgw=$(command -v s-gw || true)
if [[ -z "$old_sgw" && -x "$npm_prefix/bin/s-gw" ]]; then
  old_sgw="$npm_prefix/bin/s-gw"
fi
if [[ -n "$old_sgw" ]]; then
  "$old_sgw" stop >/dev/null || fail "The existing s-gw services could not be stopped. Close s-gw and try again."
  if [[ "${SGW_SKIP_APP_STOP:-0}" != "1" ]]; then
    /usr/bin/osascript -e 'tell application id "com.s-gw.sgw.app" to quit' >/dev/null 2>&1 || true
  fi
fi

node_arch=$(node -p 'process.arch')
keychain_target="darwin-$node_arch"
sgw_home=${SGW_HOME:-"$HOME/.s-gw"}
persistent_helper="$sgw_home/native/$keychain_target/s-gw-keychain-helper"

archive_keychain_helper() {
  local candidate=$1
  [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]] || return 0

  local helper_hash
  helper_hash=$(/usr/bin/shasum -a 256 "$candidate" | /usr/bin/awk '{print $1}') || fail "An existing Keychain helper could not be fingerprinted."
  print -r -- "$helper_hash" | /usr/bin/grep -Eq '^[0-9a-f]{64}$' || fail "An existing Keychain helper returned an invalid fingerprint."

  local archive_dir="$sgw_home/native/legacy/$helper_hash"
  local archive_path="$archive_dir/s-gw-keychain-helper"
  [[ ! -L "$archive_path" ]] || fail "A preserved Keychain helper has an unsafe path."
  if [[ -f "$archive_path" ]]; then
    local archived_hash
    archived_hash=$(/usr/bin/shasum -a 256 "$archive_path" | /usr/bin/awk '{print $1}') || fail "A preserved Keychain helper could not be verified."
    [[ "$archived_hash" == "$helper_hash" ]] || fail "A preserved Keychain helper failed verification."
    /bin/chmod 700 "$archive_dir" "$archive_path" || fail "A preserved Keychain helper could not be secured."
    return 0
  fi

  /bin/mkdir -p "$archive_dir" || fail "The Keychain helper archive could not be created."
  /bin/chmod 700 "$sgw_home/native/legacy" "$archive_dir" || fail "The Keychain helper archive could not be secured."
  local archive_staging="$archive_path.preserve-$$"
  /bin/cp "$candidate" "$archive_staging" || fail "An existing Keychain helper could not be archived."
  /bin/chmod 700 "$archive_staging" || fail "An archived Keychain helper could not be secured."
  /bin/mv -f "$archive_staging" "$archive_path" || fail "An archived Keychain helper could not be activated."
}

for package_root in "$npm_root/@s-gw/s-gw" "$npm_root/s-gw"; do
  for candidate in \
    "$package_root/dist/native/$keychain_target/s-gw-keychain-helper" \
    "$package_root/dist/native/s-gw-keychain-helper" \
    "$package_root/dist/native/sgw-keychain-helper"; do
    [[ -f "$candidate" && -x "$candidate" && ! -L "$candidate" ]] || continue
    archive_keychain_helper "$candidate"
    if [[ ! -f "$persistent_helper" ]]; then
      /bin/mkdir -p "${persistent_helper:h}" || fail "The existing Keychain helper directory could not be created."
      /bin/chmod 700 "${persistent_helper:h}" || fail "The existing Keychain helper directory could not be secured."
      /bin/cp "$candidate" "$persistent_helper" || fail "The existing Keychain helper could not be preserved before upgrade."
      /bin/chmod 700 "$persistent_helper" || fail "The preserved Keychain helper could not be secured."
    fi
  done
done

legacy_root="$npm_root/s-gw"
legacy_version=""
rollback_dir=""
rollback_path=""
if [[ -f "$legacy_root/package.json" ]]; then
  legacy_version=$(node -e '
const pkg = require(process.argv[1]);
if (pkg.name === "s-gw" && typeof pkg.version === "string") process.stdout.write(pkg.version);
' "$legacy_root/package.json") || fail "The existing legacy package metadata could not be read."
fi

if [[ -n "$legacy_version" ]]; then
  print -- "Migrating legacy s-gw $legacy_version to @s-gw/s-gw $package_version..."
  rollback_dir=$(mktemp -d "${TMPDIR:-/tmp}/s-gw-rollback.XXXXXX") || fail "A rollback directory could not be created."
  rollback_metadata=$(npm pack --ignore-scripts --json --pack-destination "$rollback_dir" -- "$legacy_root") || {
    rm -rf "$rollback_dir"
    fail "A rollback copy of legacy s-gw could not be created. The existing package was not removed."
  }
  rollback_file=$(print -r -- "$rollback_metadata" | node -e '
let data = "";
process.stdin.on("data", chunk => data += chunk);
process.stdin.on("end", () => {
  const item = JSON.parse(data)[0];
  if (item && item.name === "s-gw" && item.version === process.argv[1] && item.filename) process.stdout.write(item.filename);
});
' "$legacy_version") || true
  [[ -n "$rollback_file" && "$rollback_file" == "${rollback_file:t}" && -f "$rollback_dir/$rollback_file" ]] || {
    rm -rf "$rollback_dir"
    fail "The rollback copy of legacy s-gw could not be verified. The existing package was not removed."
  }
  rollback_path="$rollback_dir/$rollback_file"

  npm uninstall --global --prefix "$npm_prefix" --ignore-scripts -- s-gw || {
    rm -rf "$rollback_dir"
    fail "npm could not remove the legacy s-gw package. The scoped package was not installed."
  }
  print -- "Legacy package removed. Existing data under ~/.s-gw was left in place."
fi

print -- "Installing @s-gw/s-gw $package_version..."
if ! npm install --global --prefix "$npm_prefix" --ignore-scripts -- "$package_path"; then
  if [[ -n "$rollback_path" && -f "$rollback_path" ]]; then
    print -u2 -- "The scoped install failed. Restoring legacy s-gw $legacy_version from the local rollback copy..."
    npm uninstall --global --prefix "$npm_prefix" --ignore-scripts -- @s-gw/s-gw >/dev/null 2>&1 || true
    if npm install --global --prefix "$npm_prefix" --ignore-scripts -- "$rollback_path"; then
      rm -rf "$rollback_dir"
      fail "The new package could not be installed; legacy s-gw was restored. Your ~/.s-gw data was preserved."
    fi
    fail "The new package and automatic rollback both failed. Your ~/.s-gw data was preserved. Restore with: npm uninstall --global --prefix '$npm_prefix' @s-gw/s-gw && npm install --global --prefix '$npm_prefix' '$rollback_path'"
  fi
  fail "npm could not install the package. Check your npm global-directory permissions. Your ~/.s-gw data was preserved."
fi

installed_helper="$npm_root/@s-gw/s-gw/dist/native/$keychain_target/s-gw-keychain-helper"
if [[ -f "$persistent_helper" ]]; then
  archive_keychain_helper "$installed_helper"
  /bin/mkdir -p "${installed_helper:h}" || fail "The installed Keychain helper directory could not be created."
  helper_staging="$installed_helper.pin-$$"
  /bin/cp "$persistent_helper" "$helper_staging" || fail "The stable Keychain helper could not be restored after upgrade."
  /bin/chmod 755 "$helper_staging" || fail "The restored Keychain helper could not be made executable."
  /bin/mv -f "$helper_staging" "$installed_helper" || fail "The stable Keychain helper could not be activated after upgrade."
fi

[[ -z "$rollback_dir" ]] || rm -rf "$rollback_dir"

sgw_bin=$(command -v s-gw || true)
if [[ -z "$sgw_bin" ]]; then
  candidate="$npm_prefix/bin/s-gw"
  [[ -x "$candidate" ]] && sgw_bin="$candidate"
fi
[[ -n "$sgw_bin" ]] || fail "s-gw was installed but its command is not on PATH."

PATH="$npm_prefix/bin:$PATH" "$sgw_bin" setup --port 8718 || fail "Package installation completed, but setup did not. Run '$sgw_bin setup --port 8718' after closing this window."
print -- "s-gw $package_version is installed. Existing ~/.s-gw data was preserved."

if [[ -t 0 ]]; then
  read -k 1 "?Press any key to close."
  print
fi
