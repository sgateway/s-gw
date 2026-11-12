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
hashes and updates both copies in the bundled runtime. The Ubuntu 26.04
probe must confirm that the payload starts and `socket(AF_UNIX)` is denied
both standalone and within bubblewrap before this candidate is accepted.
If that host also denies a later `uid_map`, `gid_map`, or namespace operation,
the helper still stops before the payload and needs a different design.
