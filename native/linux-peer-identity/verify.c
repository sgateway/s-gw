#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#if defined(__x86_64__) || defined(__aarch64__)
#define SO_PEERPIDFD 77
#else
#error SO_PEERPIDFD is unavailable for this Linux architecture.
#endif
#endif

static int live_pidfd(int pidfd) {
    struct pollfd item = { .fd = pidfd, .events = POLLIN };
    int result = poll(&item, 1, 0);
    return result == 0 && item.revents == 0;
}

static int valid_cgroup(const char *path) {
    if (!path || path[0] != '/' || path[1] == '\0') return 0;
    size_t length = strlen(path);
    if (length > 4096 || path[length - 1] == '/') return 0;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (size == 0 || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

static int in_cgroup(pid_t pid, const char *expected) {
    char filename[64];
    if (snprintf(filename, sizeof(filename), "/proc/%ld/cgroup", (long)pid) >= (int)sizeof(filename)) return 0;
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;

    char content[16384];
    ssize_t amount = read(fd, content, sizeof(content) - 1);
    int complete = amount > 0 && amount < (ssize_t)sizeof(content) - 1;
    close(fd);
    if (!complete) return 0;
    content[amount] = '\0';

    size_t expected_len = strlen(expected);
    char *line = content;
    while (line && *line) {
        char *next = strchr(line, '\n');
        if (next) *next = '\0';
        if (strncmp(line, "0::", 3) == 0) {
            const char *actual = line + 3;
            return strncmp(actual, expected, expected_len) == 0 &&
                (actual[expected_len] == '\0' || actual[expected_len] == '/');
        }
        line = next ? next + 1 : NULL;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct sockaddr_storage address;
    socklen_t address_len = sizeof(address);
    int socket_type = 0;
    socklen_t type_len = sizeof(socket_type);
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    int pidfd = -1;
    socklen_t pidfd_len = sizeof(pidfd);

    if (argc != 2 || !valid_cgroup(argv[1]) ||
        getsockname(3, (struct sockaddr *)&address, &address_len) != 0 ||
        address.ss_family != AF_UNIX ||
        getpeername(3, (struct sockaddr *)&address, &address_len) != 0 ||
        getsockopt(3, SOL_SOCKET, SO_TYPE, &socket_type, &type_len) != 0 ||
        socket_type != SOCK_STREAM ||
        getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
        peer_len != sizeof(peer) || peer.pid <= 0) {
        fputs("Could not verify Linux peer process.\n", stderr);
        return 1;
    }
    if (getsockopt(3, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &pidfd_len) != 0) {
        if (errno == ENOPROTOOPT || errno == EOPNOTSUPP || errno == EINVAL) {
            fputs("The Linux kernel has no peer pidfd support.\n", stderr);
            return 2;
        }
        fputs("Could not verify Linux peer process.\n", stderr);
        return 1;
    }
    if (pidfd_len != sizeof(pidfd) || pidfd < 0) {
        fputs("Could not verify Linux peer process.\n", stderr);
        return 1;
    }

    int verified = live_pidfd(pidfd) && in_cgroup(peer.pid, argv[1]) && live_pidfd(pidfd);
    close(pidfd);
    if (!verified) {
        fputs("Linux peer process is not live in the registered cgroup.\n", stderr);
        return 1;
    }
    printf("%lu %lu %ld\n", (unsigned long)peer.uid, (unsigned long)peer.gid, (long)peer.pid);
    return fflush(stdout) == 0 ? 0 : 1;
}
