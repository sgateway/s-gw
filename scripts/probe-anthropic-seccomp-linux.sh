#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -eq 0 ]; then
  echo "Run this probe as a non-root Linux user." >&2
  exit 1
fi

node scripts/stage-anthropic-runtime.mjs
version=$(node -p "require('./node_modules/@anthropic-ai/sandbox-runtime/package.json').version")
if [ "$version" != 0.0.50 ]; then
  echo "Expected the pinned sandbox-runtime 0.0.50, found $version." >&2
  exit 1
fi

arch=$(node -p 'process.arch')
helper="$PWD/node_modules/@anthropic-ai/sandbox-runtime/vendor/seccomp/$arch/apply-seccomp"
if [ ! -x "$helper" ] || [ ! -x /usr/bin/bwrap ]; then
  echo "The bundled apply-seccomp helper or system bubblewrap is unavailable." >&2
  exit 1
fi

probe_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/sgw-seccomp-probe.XXXXXX")
trap 'rm -rf "$probe_dir"' EXIT

printf 'OS release:\n'
cat /etc/os-release
printf 'Kernel: %s\nRuntime: %s\n' "$(uname -r)" "$version"
/usr/bin/bwrap --version
printf 'Host AppArmor: '
cat /proc/self/attr/current
printf 'Host setgroups: '
cat /proc/self/setgroups
grep -E '^(CapBnd|CapEff|NoNewPrivs|Seccomp):' /proc/self/status
for key in apparmor_restrict_unprivileged_userns apparmor_restrict_unprivileged_unconfined unprivileged_userns_clone; do
  if [ -r "/proc/sys/kernel/$key" ]; then
    printf '%s: ' "$key"
    cat "/proc/sys/kernel/$key"
  fi
done

bwrap_args=(--ro-bind / / --bind "$probe_dir" "$probe_dir" --dev /dev --proc /proc --unshare-user --unshare-pid --unshare-net --new-session --die-with-parent --)

known_policy_denial() {
  local output=$1
  case "$output" in
    *'apply-seccomp: write /proc/self/setgroups'*|*'apply-seccomp: write /proc/self/uid_map'*|*'apply-seccomp: write /proc/self/gid_map'*|*'apply-seccomp: unshare('*|*'bwrap:'*)
      [[ "$output" == *'Permission denied'* || "$output" == *'Operation not permitted'* || "$output" == *'No permissions to create new namespace'* ]]
      return
      ;;
  esac
  return 1
}

outer_sentinel="$probe_dir/outer.started"
# shellcheck disable=SC2016
if outer_output=$(env -i PATH=/usr/bin:/bin HOME=/tmp /usr/bin/bwrap "${bwrap_args[@]}" /bin/sh -c 'printf started > "$1"; printf "Bwrap child AppArmor: "; cat /proc/self/attr/current; printf "Bwrap child setgroups: "; cat /proc/self/setgroups; grep -E "^(CapBnd|CapEff|NoNewPrivs|Seccomp):" /proc/self/status' sh "$outer_sentinel" 2>&1); then
  printf '%s\n' "$outer_output"
  if [ ! -f "$outer_sentinel" ]; then
    echo "Outer bubblewrap reported success without starting its payload." >&2
    exit 1
  fi
else
  outer_status=$?
  printf 'Outer bwrap exit: %s\n%s\n' "$outer_status" "$outer_output"
  if [ -e "$outer_sentinel" ] || ! known_policy_denial "$outer_output"; then
    echo "Outer bubblewrap failed for an unclassified reason or after starting its payload." >&2
    exit 1
  fi
  echo "Outer bubblewrap is blocked before payload by host policy; filtered launch is unavailable." >&2
  exit 1
fi

socket_probe=$'import sys\nwith open(sys.argv[1], "x") as marker:\n    marker.write("started")\nprint("SGW_PAYLOAD_STARTED", flush=True)\nimport errno, socket\ntry:\n    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nexcept OSError as error:\n    if error.errno != errno.EPERM:\n        raise\n    print("SGW_AF_UNIX_DENIED")\nelse:\n    sock.close()\n    raise SystemExit("SGW_AF_UNIX_ALLOWED")'

probe() {
  local label=$1 output status sentinel
  shift
  sentinel="$probe_dir/$label.started"
  if output=$(env -i PATH=/usr/bin:/bin HOME=/tmp "$@" /usr/bin/python3 -c "$socket_probe" "$sentinel" 2>&1); then
    status=0
  else
    status=$?
  fi
  printf '%s exit: %s\n%s\n' "$label" "$status" "$output"

  if [ "$status" -eq 0 ]; then
    if [ ! -f "$sentinel" ] || [[ "$output" != *SGW_PAYLOAD_STARTED* || "$output" != *SGW_AF_UNIX_DENIED* ]]; then
      echo "$label ran without proving Unix-socket filtering." >&2
      return 2
    fi
    echo "$label: filtered launch available"
    return 0
  fi

  if [ -e "$sentinel" ] || [[ "$output" == *SGW_PAYLOAD_STARTED* ]]; then
    echo "$label failed after starting the payload." >&2
    return 2
  fi
  if known_policy_denial "$output"; then
    echo "$label: blocked before payload by host policy; filtered launch is unavailable." >&2
    return 1
  fi
  echo "$label failed for an unclassified reason." >&2
  return 2
}

if probe standalone "$helper"; then
  standalone_result=0
else
  standalone_result=$?
fi
if probe inside-bwrap /usr/bin/bwrap "${bwrap_args[@]}" "$helper"; then
  inside_result=0
else
  inside_result=$?
fi

if [ "$standalone_result" -eq 1 ]; then
  echo "::warning title=Anthropic seccomp availability::Standalone helper is blocked before payload by host policy; the separate inside-bwrap probe was checked too."
elif [ "$standalone_result" -ne 0 ]; then
  echo "Standalone helper failed after payload start or for an unclassified reason." >&2
  exit 1
fi
if [ "$inside_result" -ne 0 ]; then
  echo "The separate inside-bwrap probe did not prove a filtered payload launch." >&2
  exit 1
fi
