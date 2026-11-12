#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Linux ]; then
  echo 'This test needs Linux.' >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo 'Run this test as an ordinary user.' >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo 'This test needs x86_64 or aarch64.' >&2; exit 1 ;;
esac

repo_root=$(cd "$(dirname "$0")/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/sgw-filter-only.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT

cc -std=c11 -O2 -Wall -Wextra -Werror \
  -o "$tmp_dir/filter-only-exec" \
  "$repo_root/vendor/anthropic-seccomp/filter-only-exec.c"
cc -std=c11 -O2 -Wall -Wextra -Werror \
  -o "$tmp_dir/payload" \
  "$repo_root/scripts/test-anthropic-filter-only-payload.c"

baseline=$("$tmp_dir/payload" baseline)
if [[ ! "$baseline" =~ ^[0-9]+$ ]]; then
  echo "Invalid baseline filter count: $baseline" >&2
  exit 1
fi
"$tmp_dir/payload" inherited-fd 9>"$tmp_dir/inherited-fd"

marker="$tmp_dir/payload.started"
status=0
"$tmp_dir/filter-only-exec" "$tmp_dir/payload" filtered "$marker" "$baseline" \
  9>"$tmp_dir/inherited-fd" || status=$?
if [ ! -f "$marker" ]; then
  echo "The filtered payload did not start (helper exit $status)." >&2
  exit 1
fi
if [ "$(cat "$marker")" != started ]; then
  echo 'The filtered payload marker is invalid.' >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo "The filtered payload failed (exit $status)." >&2
  exit 1
fi

status=0
"$tmp_dir/filter-only-exec" /bin/sh -c 'exit 37' || status=$?
if [ "$status" -ne 37 ]; then
  echo "The helper returned $status instead of the payload's exit status 37." >&2
  exit 1
fi

echo 'Filter-only payload started: AF_UNIX and io_uring denied; AF_INET allowed; inherited FD closed.'
