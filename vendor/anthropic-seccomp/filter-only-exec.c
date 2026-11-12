/* SPDX-License-Identifier: Apache-2.0 */
/* Uses the pinned Anthropic sandbox-runtime 0.0.50 filter in unix-block-bpf.h. */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "filter-only-exec supports only x86_64 and aarch64"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "the pinned BPF bytes require a little-endian target"
#endif

#include "unix-block-bpf.h"

_Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
               "BPF bytes must contain complete sock_filter instructions");
_Static_assert(sizeof(unix_block_bpf) / sizeof(struct sock_filter) <= USHRT_MAX,
               "BPF program is too large");

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s EXECUTABLE [args...]\n", argv[0]);
        return 2;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("filter-only-exec: PR_SET_NO_NEW_PRIVS");
        return 1;
    }
    if (syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC) != 0) {
        perror("filter-only-exec: close_range(CLOEXEC)");
        return 1;
    }

    struct sock_fprog filter = {
        .len = (unsigned short)(sizeof(unix_block_bpf) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter *)(void *)unix_block_bpf,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) != 0) {
        perror("filter-only-exec: PR_SET_SECCOMP");
        return 1;
    }

    execv(argv[1], &argv[1]);
    int exec_errno = errno;
    perror("filter-only-exec: execv");
    return exec_errno == ENOENT ? 127 : 126;
}
