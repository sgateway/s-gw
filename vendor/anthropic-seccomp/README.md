# Anthropic Linux seccomp helper candidate

This is `apply-seccomp.c` from `@anthropic-ai/sandbox-runtime` 0.0.50
(SHA-256 `4fa515faf61274ab5058fe60dbb6da8a92a7bc243c72476fd2b6d798cfc9ab01`),
under its Apache-2.0 license. The only source change checks whether
`/proc/self/setgroups` already says `deny` before writing the same value.
An ancestor user namespace can make that write impossible even though the
required restriction is already active. All later UID/GID mapping, nested
PID and mount namespace, and seccomp steps still fail closed.

`unix-block-bpf.h` contains the exact filter bytes extracted from the
0.0.50 x64 and arm64 binaries (136 and 120 bytes respectively). The staged
binaries retain those bytes unchanged. They were built with Zig 0.16.0:

```sh
zig cc -target x86_64-linux-musl -static -O2 -s -Wall -Wextra -Werror \
  -I vendor/anthropic-seccomp -o vendor/anthropic-seccomp/x64/apply-seccomp \
  vendor/anthropic-seccomp/apply-seccomp.c
zig cc -target aarch64-linux-musl -static -O2 -s -Wall -Wextra -Werror \
  -I vendor/anthropic-seccomp -o vendor/anthropic-seccomp/arm64/apply-seccomp \
  vendor/anthropic-seccomp/apply-seccomp.c
```

`scripts/stage-anthropic-runtime.mjs` checks the original and replacement
hashes and updates both copies in the bundled runtime. The ad hoc Ubuntu 26.04
probe checks standalone and inside-bubblewrap helper launches. The separate
integrated test checks the actual `s-gw run` path. Both currently fail closed
before the payload at a denied `uid_map` write under host policy; this helper
still needs a different design for that host.

## Filter-only primitive for a future managed backend

`filter-only-exec.c` reuses the exact pinned `unix-block-bpf.h` bytes under
Apache-2.0. It sets `no_new_privs`, marks every descriptor above standard
input/output/error close-on-exec, installs the filter, then directly execs
the supplied executable path. It does not create namespaces, write UID/GID
maps, mount filesystems, or run a supervisor. A successful exec preserves the
payload's actual exit and signal status. Any setup failure stops before exec.

This is only a filter installer. It does not confine a process by itself.
The proposed root/systemd backend must independently provide the agent UID,
private namespaces, mounts, network policy, gate, and trusted executable path.
The helper is not wired into the existing Anthropic launcher or staged runtime.
The `close_range(CLOSE_RANGE_CLOEXEC)` call requires a supporting Linux kernel
and intentionally prevents payloads from inheriting descriptors numbered 3+.

On a non-root x86_64 or arm64 Linux host, run
`bash scripts/test-anthropic-filter-only-linux.sh`. This disposable test uses
`cc` and a synthetic payload. It checks payload start, filter installation,
AF_UNIX and io_uring denials, AF_INET creation, descriptor cleanup, and direct
exit status. It does not exercise a root-managed agent launch.
