#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t retry = 0;
static volatile sig_atomic_t transfer_probe = 0;
static int save(const char *filename, const char *value);

static void on_retry(int signal_number) {
    (void)signal_number;
    retry = 1;
}

static void on_transfer(int signal_number) {
    (void)signal_number;
    transfer_probe = 1;
}

static int unix_connect(const char *name) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(name) >= sizeof(address.sun_path)) return -1;
    strcpy(address.sun_path, name);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) return fd;
    close(fd);
    return -1;
}

static int unix_listen(const char *name) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(name) >= sizeof(address.sun_path)) return -1;
    strcpy(address.sun_path, name);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 && listen(fd, 2) == 0) return fd;
    close(fd);
    return -1;
}

static int abstract_socket(const char *name, int serving) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    size_t length = strlen(name);
    if (length + 1 > sizeof(address.sun_path)) return -1;
    memcpy(address.sun_path + 1, name, length);
    socklen_t size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + length);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int result = serving ? bind(fd, (struct sockaddr *)&address, size) :
        connect(fd, (struct sockaddr *)&address, size);
    if (result == 0 && (!serving || listen(fd, 2) == 0)) return fd;
    close(fd);
    return -1;
}

static int self_connect(int listener, int connector) {
    if (connector < 0) return 0;
    int accepted = accept(listener, NULL, NULL);
    close(connector);
    if (accepted < 0) return 0;
    close(accepted);
    return 1;
}

static int rights_selftest(void) {
    int pair[2];
    int pipefd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 0;
    if (pipe(pipefd) != 0) { close(pair[0]); close(pair[1]); return 0; }
    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &pipefd[0], sizeof(int));
    int sent = sendmsg(pair[0], &message, 0) == 1;
    memset(control, 0, sizeof(control));
    message.msg_controllen = sizeof(control);
    int got = sent && recvmsg(pair[1], &message, 0) == 1 && !(message.msg_flags & MSG_CTRUNC);
    header = got ? CMSG_FIRSTHDR(&message) : NULL;
    int received = -1;
    if (header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len >= CMSG_LEN(sizeof(int))) memcpy(&received, CMSG_DATA(header), sizeof(int));
    int okay = received >= 0 && fcntl(received, F_GETFD) >= 0;
    if (received >= 0) close(received);
    close(pipefd[0]);
    close(pipefd[1]);
    close(pair[0]);
    close(pair[1]);
    return okay;
}

static int rights_address(const char *name, int abstract, struct sockaddr_un *address,
                          socklen_t *size) {
    size_t length = strlen(name);
    if (length + 1 > sizeof(address->sun_path)) return 0;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    if (abstract) memcpy(address->sun_path + 1, name, length);
    else memcpy(address->sun_path, name, length + 1);
    *size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
    return 1;
}

static int rights_listener(const char *name, int abstract) {
    struct sockaddr_un address;
    socklen_t size;
    if (!rights_address(name, abstract, &address, &size)) return -1;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&address, size) == 0) return fd;
    close(fd);
    return -1;
}

static int send_rights_to(const char *name, int abstract, int passed_fd) {
    struct sockaddr_un address;
    socklen_t size;
    if (!rights_address(name, abstract, &address, &size)) return -EIO;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return -EIO;
    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_name = &address, .msg_namelen = size,
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &passed_fd, sizeof(int));
    ssize_t sent = sendmsg(fd, &message, MSG_NOSIGNAL);
    int error = errno;
    close(fd);
    if (sent == 1) return 1;
    return sent < 0 ? -error : -EIO;
}

static int denied_rights_transfer(int status) {
    if (status == 1) return 0;
    if (status == -ENOENT || status == -ECONNREFUSED ||
        status == -EACCES || status == -EPERM) return 1;
    return status < 0 ? status : -EIO;
}

static int received_rights_match(int listener, int original) {
    char payload = 0;
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    ssize_t count = recvmsg(listener, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    int received = -1;
    if (header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len == CMSG_LEN(sizeof(int))) memcpy(&received, CMSG_DATA(header), sizeof(int));
    if (received < 0) return 0;
    struct stat expected, actual;
    int same = count == 1 && !(message.msg_flags & MSG_CTRUNC) &&
        fstat(original, &expected) == 0 && fstat(received, &actual) == 0 &&
        expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino &&
        S_ISSOCK(actual.st_mode);
    close(received);
    return same;
}

static int broker_transfer_fd(void) {
    int fd = unix_connect("/run/s-gw/broker.sock");
    if (fd < 0) return -1;
    struct timeval deadline = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0 ||
        write(fd, "TRANSFER\n", 9) != 9) {
        close(fd);
        return -1;
    }
    char answer[8] = { 0 };
    size_t used = 0;
    while (used < sizeof(answer) - 1 && (used == 0 || answer[used - 1] != '\n')) {
        ssize_t count = read(fd, answer + used, sizeof(answer) - 1 - used);
        if (count <= 0) break;
        used += (size_t)count;
    }
    if (strcmp(answer, "READY\n") == 0) return fd;
    close(fd);
    return -1;
}

static int socket_path(char *buffer, size_t size, const char *prefix, const char *session) {
    int length = snprintf(buffer, size, "%s%s.sock", prefix, session);
    return length > 0 && (size_t)length < size;
}

static int shared_memory_name(char *buffer, size_t size, const char *session) {
    int length = snprintf(buffer, size, "/sgw-ci-%s", session);
    return length > 0 && (size_t)length < size;
}

static int create_shared_memory(const char *name) {
    int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) return -1;
    const char marker = 's';
    if (fchmod(fd, 0666) != 0 || ftruncate(fd, 1) != 0 ||
        pwrite(fd, &marker, 1, 0) != 1) {
        close(fd);
        shm_unlink(name);
        return -1;
    }
    return fd;
}

static int shared_memory_result(const char *own, const char *other,
                                int *own_good, int *other_denied) {
    char own_name[96], other_name[96];
    if (!shared_memory_name(own_name, sizeof(own_name), own) ||
        !shared_memory_name(other_name, sizeof(other_name), other)) return -1;
    int fd = shm_open(own_name, O_RDONLY, 0);
    char marker = 0;
    *own_good = fd >= 0 && pread(fd, &marker, 1, 0) == 1 && marker == 's';
    if (fd >= 0) close(fd);
    fd = shm_open(other_name, O_RDONLY, 0);
    int error = errno;
    if (fd >= 0) close(fd);
    *other_denied = fd < 0 && error == ENOENT;
    return 0;
}

static int transfer_result(const char *own, const char *other, int path_listener, int abstract_listener,
                           int rights_path_listener, int rights_abstract_listener) {
    char workspace[128], host_path[128], abstract_name[96];
    char own_path[128], own_abstract[96];
    char rights_path[128], rights_host_path[160], rights_abstract[96];
    char own_rights_path[128], own_rights_abstract[96];
    if (!socket_path(workspace, sizeof(workspace), "/workspace/transfer-", other) ||
        !socket_path(abstract_name, sizeof(abstract_name), "sgw-ci-transfer-", other) ||
        !socket_path(own_path, sizeof(own_path), "/workspace/transfer-", own) ||
        !socket_path(own_abstract, sizeof(own_abstract), "sgw-ci-transfer-", own) ||
        !socket_path(rights_path, sizeof(rights_path), "/workspace/rights-", other) ||
        !socket_path(rights_abstract, sizeof(rights_abstract), "sgw-ci-rights-", other) ||
        !socket_path(own_rights_path, sizeof(own_rights_path), "/workspace/rights-", own) ||
        !socket_path(own_rights_abstract, sizeof(own_rights_abstract), "sgw-ci-rights-", own)) return -1;
    int length = snprintf(host_path, sizeof(host_path),
        "/var/lib/s-gw/agent-roots/%s%s", other, workspace);
    if (length < 0 || (size_t)length >= sizeof(host_path)) return -1;
    length = snprintf(rights_host_path, sizeof(rights_host_path),
        "/var/lib/s-gw/agent-roots/%s%s", other, rights_path);
    if (length < 0 || (size_t)length >= sizeof(rights_host_path)) return -1;
    int file_fd = unix_connect(workspace);
    int host_fd = unix_connect(host_path);
    int abstract_fd = abstract_socket(abstract_name, 0);
    int file_denied = file_fd < 0, host_denied = host_fd < 0, abstract_denied = abstract_fd < 0;
    if (file_fd >= 0) close(file_fd);
    if (host_fd >= 0) close(host_fd);
    if (abstract_fd >= 0) close(abstract_fd);
    int own_file = self_connect(path_listener, unix_connect(own_path));
    int own_abstract_socket = self_connect(abstract_listener, abstract_socket(own_abstract, 0));
    int own_shared = 0, other_shared_denied = 0;
    if (shared_memory_result(own, other, &own_shared, &other_shared_denied) != 0) return -1;
    int broker_fd = broker_transfer_fd();
    if (broker_fd < 0) return -1;
    int own_rights = send_rights_to(own_rights_path, 0, broker_fd) == 1 &&
        received_rights_match(rights_path_listener, broker_fd);
    int own_abstract_rights = send_rights_to(own_rights_abstract, 1, broker_fd) == 1 &&
        received_rights_match(rights_abstract_listener, broker_fd);
    int rights_fs_denied = denied_rights_transfer(send_rights_to(rights_path, 0, broker_fd));
    int rights_host_denied = denied_rights_transfer(send_rights_to(rights_host_path, 0, broker_fd));
    int rights_abstract_denied = denied_rights_transfer(send_rights_to(rights_abstract, 1, broker_fd));
    close(broker_fd);
    char result[256];
    snprintf(result, sizeof(result),
        "rights=%d ownfs=%d ownabstract=%d fs=%d hostfs=%d abstract=%d ownshm=%d crossshm=%d ownrights=%d ownrightsa=%d rightsfs=%d rightshostfs=%d rightsa=%d\n",
        rights_selftest(), own_file, own_abstract_socket, file_denied, host_denied,
        abstract_denied, own_shared, other_shared_denied, own_rights, own_abstract_rights,
        rights_fs_denied, rights_host_denied, rights_abstract_denied);
    return save("/workspace/transfer", result);
}

static int tcp_connect(int family, const char *host, int port) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) { close(fd); return -1; }
    struct sockaddr_storage address = { 0 };
    socklen_t size;
    if (family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((unsigned short)port);
        if (inet_pton(AF_INET, host, &ipv4->sin_addr) != 1) { close(fd); return -1; }
        size = sizeof(*ipv4);
    } else {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((unsigned short)port);
        if (inet_pton(AF_INET6, host, &ipv6->sin6_addr) != 1) { close(fd); return -1; }
        size = sizeof(*ipv6);
    }
    int result = connect(fd, (struct sockaddr *)&address, size);
    if (result == 0) return fd;
    if (errno == EINPROGRESS) {
        struct pollfd item = { .fd = fd, .events = POLLOUT };
        if (poll(&item, 1, 1000) == 1) {
            int error = 0;
            socklen_t error_size = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_size) == 0 && error == 0) return fd;
        }
    }
    close(fd);
    return -1;
}

static int udp_send(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((unsigned short)port) };
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) { close(fd); return 0; }
    int sent = sendto(fd, "probe", 5, 0, (struct sockaddr *)&address, sizeof(address)) == 5;
    close(fd);
    return sent;
}

static int approved(const char *claimed, const char *actual) {
    int fd = unix_connect("/run/s-gw/broker.sock");
    if (fd < 0) return 0;
    char request[96];
    int length = snprintf(request, sizeof(request), "CLAIM %s\n", claimed);
    if (length < 0 || (size_t)length >= sizeof(request)) {
        close(fd);
        return 0;
    }
    struct timeval deadline = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0) {
        close(fd);
        return 0;
    }
    int written = 0;
    while (written < length) {
        ssize_t count = write(fd, request + written, (size_t)(length - written));
        if (count <= 0) { close(fd); return 0; }
        written += (int)count;
    }
    char response[96] = { 0 };
    size_t used = 0;
    int finished = 0;
    while (used < sizeof(response) - 1) {
        ssize_t count = read(fd, response + used, sizeof(response) - 1 - used);
        if (count == 0) { finished = 1; break; }
        if (count < 0) break;
        used += (size_t)count;
    }
    close(fd);
    char expected[96];
    snprintf(expected, sizeof(expected), "ALLOW %s\n", actual);
    return finished && strcmp(response, expected) == 0;
}

static int save(const char *filename, const char *value) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(value);
    int okay = write(fd, value, length) == (ssize_t)length;
    if (close(fd) != 0) okay = 0;
    return okay ? 0 : -1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--rights-positive") == 0) {
        return rights_selftest() ? 0 : 1;
    }
    if (argc == 5 && strcmp(argv[1], "--tcp-positive") == 0) {
        int family = strcmp(argv[2], "ipv6") == 0 ? AF_INET6 : AF_INET;
        int fd = tcp_connect(family, argv[3], atoi(argv[4]));
        if (fd < 0) return 1;
        close(fd);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--udp-positive") == 0) {
        return udp_send(argv[2], atoi(argv[3])) ? 0 : 1;
    }
    if (argc != 9) return 64;
    int port4 = atoi(argv[3]);
    int port6 = atoi(argv[4]);
    int port_host = atoi(argv[6]);
    int port_udp4 = atoi(argv[7]);
    int port_udp_host = atoi(argv[8]);
    if (port4 < 1 || port4 > 65535 || port6 < 1 || port6 > 65535 ||
        port_host < 1 || port_host > 65535 || port_udp4 < 1 || port_udp4 > 65535 ||
        port_udp_host < 1 || port_udp_host > 65535) return 64;

    int own = approved(argv[2], argv[1]);
    char other_socket[128];
    int length = snprintf(other_socket, sizeof(other_socket), "/run/s-gw/agents/%s/broker.sock", argv[2]);
    if (length < 0 || (size_t)length >= sizeof(other_socket)) return 64;
    int cross = unix_connect(other_socket);
    int ipv4 = tcp_connect(AF_INET, "127.0.0.1", port4);
    int ipv6 = tcp_connect(AF_INET6, "::1", port6);
    int host = tcp_connect(AF_INET, argv[5], port_host);
    int udp4 = udp_send("127.0.0.1", port_udp4);
    int udp_host = udp_send(argv[5], port_udp_host);
    if (cross >= 0) close(cross);
    if (ipv4 >= 0) close(ipv4);
    if (ipv6 >= 0) close(ipv6);
    if (host >= 0) close(host);

    char result[160];
    snprintf(result, sizeof(result), "own=%d cross=%d ipv4=%d ipv6=%d host=%d udp4=%d udphost=%d\n",
        own, cross < 0, ipv4 < 0, ipv6 < 0, host < 0, udp4, udp_host);
    struct sigaction action = { .sa_handler = on_retry };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL) != 0) return 70;
    action.sa_handler = on_transfer;
    if (sigaction(SIGUSR2, &action, NULL) != 0) return 70;
    if (save("/workspace/result", result) != 0) return 70;
    char own_path[128], own_abstract[96], rights_path[128], rights_abstract[96];
    if (!socket_path(own_path, sizeof(own_path), "/workspace/transfer-", argv[1]) ||
        !socket_path(own_abstract, sizeof(own_abstract), "sgw-ci-transfer-", argv[1]) ||
        !socket_path(rights_path, sizeof(rights_path), "/workspace/rights-", argv[1]) ||
        !socket_path(rights_abstract, sizeof(rights_abstract), "sgw-ci-rights-", argv[1])) return 70;
    int path_listener = unix_listen(own_path);
    int abstract_listener = abstract_socket(own_abstract, 1);
    int rights_path_listener = rights_listener(rights_path, 0);
    int rights_abstract_listener = rights_listener(rights_abstract, 1);
    char shared_name[96];
    if (!shared_memory_name(shared_name, sizeof(shared_name), argv[1])) return 70;
    int shared_fd = create_shared_memory(shared_name);
    if (path_listener < 0 || abstract_listener < 0 || rights_path_listener < 0 ||
        rights_abstract_listener < 0 || !rights_selftest() ||
        shared_fd < 0 ||
        !self_connect(path_listener, unix_connect(own_path)) ||
        !self_connect(abstract_listener, abstract_socket(own_abstract, 0)) ||
        save("/workspace/transfer-ready", "ready\n") != 0) {
        if (shared_fd >= 0) { close(shared_fd); shm_unlink(shared_name); }
        if (path_listener >= 0) close(path_listener);
        if (abstract_listener >= 0) close(abstract_listener);
        if (rights_path_listener >= 0) close(rights_path_listener);
        if (rights_abstract_listener >= 0) close(rights_abstract_listener);
        return 70;
    }
    while (!retry) {
        if (transfer_probe) {
            transfer_probe = 0;
            if (transfer_result(argv[1], argv[2], path_listener, abstract_listener,
                                rights_path_listener, rights_abstract_listener) != 0) return 70;
        } else poll(NULL, 0, 100);
    }
    close(path_listener);
    close(abstract_listener);
    close(rights_path_listener);
    close(rights_abstract_listener);
    close(shared_fd);
    shm_unlink(shared_name);
    const char *rebound = approved(argv[2], argv[1]) ? "rebind=accepted\n" : "rebind=denied\n";
    return save("/workspace/rebind", rebound) == 0 ? 0 : 70;
}
