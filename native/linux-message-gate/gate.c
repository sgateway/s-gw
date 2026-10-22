#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

#define SOCKET_FD 3
#define CHUNK_SIZE 16384

struct pending {
    char bytes[CHUNK_SIZE];
    size_t used;
    size_t sent;
};

static int socket_flag(int fd, int option) {
    int value = 0;
    socklen_t size = sizeof(value);
    return getsockopt(fd, SOL_SOCKET, option, &value, &size) == 0 &&
        size == sizeof(value) && value == 1;
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

static int read_id(const char *input, unsigned int *value) {
    if (!input || !*input) return 0;
    errno = 0;
    char *end = NULL;
    unsigned long parsed = strtoul(input, &end, 10);
    if (errno || !end || *end || parsed > UINT32_MAX) return 0;
    *value = (unsigned int)parsed;
    return 1;
}

static int live_pidfd(int fd) {
    struct pollfd item = { .fd = fd, .events = POLLIN };
    return poll(&item, 1, 0) == 0 && item.revents == 0;
}

static int in_cgroup(pid_t pid, const char *expected) {
    char filename[64];
    if (pid <= 0 || snprintf(filename, sizeof(filename), "/proc/%ld/cgroup", (long)pid) >=
            (int)sizeof(filename)) return 0;
    int fd = open(filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;

    char content[16384];
    ssize_t amount = read(fd, content, sizeof(content) - 1);
    close(fd);
    if (amount <= 0 || amount >= (ssize_t)sizeof(content) - 1) return 0;
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

static int nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static void close_rights(const struct cmsghdr *item) {
    if (item->cmsg_len < CMSG_LEN(0)) return;
    size_t count = (item->cmsg_len - CMSG_LEN(0)) / sizeof(int);
    const int *fds = (const int *)CMSG_DATA(item);
    for (size_t i = 0; i < count; i++) close(fds[i]);
}

static int verified_read(struct pending *buffer, uid_t uid, gid_t gid, const char *cgroup) {
    union {
        struct cmsghdr aligned;
        char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int)) +
            CMSG_SPACE(253 * sizeof(int))];
    } control;
    struct iovec data = { .iov_base = buffer->bytes, .iov_len = sizeof(buffer->bytes) };
    struct msghdr message = { .msg_iov = &data, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    ssize_t amount = recvmsg(SOCKET_FD, &message, MSG_CMSG_CLOEXEC);
    if (amount <= 0) return amount == 0 ? 0 : (errno == EAGAIN || errno == EWOULDBLOCK ? 2 : -1);

    struct ucred sender = { 0 };
    int pidfd = -1;
    int creds_seen = 0;
    int pidfd_seen = 0;
    int invalid = (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0;
    char *cursor = control.bytes;
    size_t left = message.msg_controllen;
    while (left >= sizeof(struct cmsghdr)) {
        struct cmsghdr *item = (struct cmsghdr *)cursor;
        if (item->cmsg_len < CMSG_LEN(0) || item->cmsg_len > left) {
            invalid = 1;
            break;
        }
        if (item->cmsg_level != SOL_SOCKET) {
            invalid = 1;
        } else if (item->cmsg_type == SCM_RIGHTS) {
            close_rights(item);
            invalid = 1;
        } else if (item->cmsg_type == SCM_CREDENTIALS &&
                item->cmsg_len == CMSG_LEN(sizeof(sender)) && !creds_seen) {
            memcpy(&sender, CMSG_DATA(item), sizeof(sender));
            creds_seen = 1;
        } else if (item->cmsg_type == SCM_PIDFD &&
                item->cmsg_len == CMSG_LEN(sizeof(int))) {
            int received = -1;
            memcpy(&received, CMSG_DATA(item), sizeof(received));
            if (pidfd_seen) {
                if (received >= 0) close(received);
                invalid = 1;
            } else {
                pidfd = received;
                pidfd_seen = 1;
            }
        } else {
            invalid = 1;
        }
        size_t step = CMSG_ALIGN(item->cmsg_len);
        if (step > left) {
            if (item->cmsg_len != left) invalid = 1;
            left = 0;
        } else {
            cursor += step;
            left -= step;
        }
    }
    if (left != 0) invalid = 1;

    int allowed = !invalid && creds_seen && pidfd_seen && sender.uid == uid &&
        sender.gid == gid && sender.pid > 0 && pidfd >= 0 &&
        live_pidfd(pidfd) && in_cgroup(sender.pid, cgroup) && live_pidfd(pidfd);
    if (pidfd >= 0) close(pidfd);
    if (!allowed) return -1;
    buffer->used = (size_t)amount;
    buffer->sent = 0;
    return 1;
}

static int prepare_listener(void) {
    int kind = 0;
    int accepting = 0;
    socklen_t size = sizeof(int);
    if (getsockopt(SOCKET_FD, SOL_SOCKET, SO_TYPE, &kind, &size) != 0 ||
        size != sizeof(int) || kind != SOCK_STREAM ||
        getsockopt(SOCKET_FD, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &size) != 0 ||
        size != sizeof(int) || !accepting || !socket_flag(SOCKET_FD, SO_PASSCRED)) return 1;
    int enabled = 1;
    if (setsockopt(SOCKET_FD, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled)) != 0 ||
        !socket_flag(SOCKET_FD, SO_PASSPIDFD)) return 1;
    return 0;
}

static int run_gate(uid_t uid, gid_t gid, const char *cgroup, int http_half_close) {
    struct sockaddr_storage address = { 0 };
    socklen_t address_size = sizeof(address);
    struct ucred peer = { 0 };
    socklen_t peer_size = sizeof(peer);
    int kind = 0;
    socklen_t kind_size = sizeof(kind);
    if (!valid_cgroup(cgroup) ||
        getsockname(SOCKET_FD, (struct sockaddr *)&address, &address_size) != 0 ||
        address.ss_family != AF_UNIX ||
        getpeername(SOCKET_FD, (struct sockaddr *)&address, &address_size) != 0 ||
        getsockopt(SOCKET_FD, SOL_SOCKET, SO_TYPE, &kind, &kind_size) != 0 ||
        kind_size != sizeof(kind) || kind != SOCK_STREAM ||
        getsockopt(SOCKET_FD, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer_size != sizeof(peer) || peer.pid <= 0 || peer.uid != uid || peer.gid != gid ||
        !socket_flag(SOCKET_FD, SO_PASSCRED) || !socket_flag(SOCKET_FD, SO_PASSPIDFD) ||
        !nonblocking(SOCKET_FD) || !nonblocking(STDIN_FILENO) || !nonblocking(STDOUT_FILENO)) return 1;

    struct pending inbound = { 0 };
    struct pending outbound = { 0 };
    int input_open = 1;
    int socket_input_open = 1;
    while (1) {
        struct pollfd items[3] = {
            { .fd = SOCKET_FD,
                .events = (socket_input_open && !inbound.used ? POLLIN : 0) |
                    (outbound.used ? POLLOUT : 0) },
            { .fd = STDOUT_FILENO, .events = inbound.used ? POLLOUT : 0 },
            { .fd = input_open ? STDIN_FILENO : -1,
                .events = input_open && !outbound.used ? POLLIN : 0 }
        };
        int ready = poll(items, 3, 35 * 60 * 1000);
        if (ready <= 0) break;

        if (inbound.used && (items[1].revents & POLLOUT)) {
            ssize_t amount = write(STDOUT_FILENO, inbound.bytes + inbound.sent,
                inbound.used - inbound.sent);
            if (amount > 0) inbound.sent += (size_t)amount;
            else if (amount < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
            if (inbound.sent == inbound.used) inbound = (struct pending){ 0 };
        }
        if (outbound.used && (items[0].revents & POLLOUT)) {
            ssize_t amount = send(SOCKET_FD, outbound.bytes + outbound.sent,
                outbound.used - outbound.sent, MSG_NOSIGNAL);
            if (amount > 0) outbound.sent += (size_t)amount;
            else if (amount < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
            if (outbound.sent == outbound.used) outbound = (struct pending){ 0 };
        }
        if (socket_input_open && !inbound.used && (items[0].revents & (POLLIN | POLLHUP))) {
            int result = verified_read(&inbound, uid, gid, cgroup);
            if (result < 0 || (result == 0 && !http_half_close)) break;
            if (result == 0) socket_input_open = 0;
        }
        if (input_open && !outbound.used && (items[2].revents & POLLIN)) {
            ssize_t amount = read(STDIN_FILENO, outbound.bytes, sizeof(outbound.bytes));
            if (amount > 0) { outbound.used = (size_t)amount; outbound.sent = 0; }
            else if (amount == 0) input_open = 0;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) break;
        }
        if (items[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (items[1].revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (items[2].revents & (POLLERR | POLLNVAL)) break;
        if (items[2].revents & POLLHUP) input_open = 0;
        if (!input_open && !outbound.used) break;
    }
    shutdown(SOCKET_FD, SHUT_RDWR);
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "prepare") == 0) return prepare_listener();
    unsigned int uid = 0;
    unsigned int gid = 0;
    if ((argc == 5 || (argc == 6 && strcmp(argv[5], "http") == 0)) &&
        strcmp(argv[1], "run") == 0 && read_id(argv[2], &uid) &&
        read_id(argv[3], &gid) && uid > 0 && gid > 0) {
        return run_gate((uid_t)uid, (gid_t)gid, argv[4], argc == 6);
    }
    return 1;
}
