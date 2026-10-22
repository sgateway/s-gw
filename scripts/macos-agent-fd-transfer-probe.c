#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE 1

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int address_for(const char *path, struct sockaddr_un *address, socklen_t *length) {
    size_t size = strlen(path);
    if (size == 0 || size >= sizeof(address->sun_path)) return 0;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, size + 1);
    *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + size + 1);
#ifdef __APPLE__
    address->sun_len = (unsigned char)*length;
#endif
    return 1;
}

static int deadline_for(int fd) {
    struct timeval limit = { .tv_sec = 12 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof(limit)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof(limit)) == 0;
}

static int write_text(int fd, const char *text) {
    size_t remaining = strlen(text);
    while (remaining > 0) {
        ssize_t count = write(fd, text, remaining);
        if (count < 0) return 0;
        if (count == 0) { errno = EIO; return 0; }
        text += count;
        remaining -= (size_t)count;
    }
    return 1;
}

static int read_text(int fd, const char *expected) {
    size_t length = strlen(expected);
    for (size_t i = 0; i < length; i++) {
        char byte = 0;
        ssize_t count = read(fd, &byte, 1);
        if (count < 0) return 0;
        if (count != 1 || byte != expected[i]) { errno = EPROTO; return 0; }
    }
    return 1;
}

static int send_fd(int socket_fd, int passed_fd) {
    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &passed_fd, sizeof(passed_fd));
    ssize_t sent = sendmsg(socket_fd, &message, 0);
    if (sent == 1) return 1;
    if (sent >= 0) errno = EIO;
    return 0;
}

static int recv_fd(int socket_fd) {
    char payload = 0;
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    ssize_t count = recvmsg(socket_fd, &message, 0);
    if (count < 0) return -1;
    if (count == 0) { errno = ECONNRESET; return -1; }
    if (count != 1 || payload != 'x' || (message.msg_flags & MSG_CTRUNC)) {
        errno = EPROTO;
        return -1;
    }
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) {
        errno = EPROTO;
        return -1;
    }
    int received = -1;
    memcpy(&received, CMSG_DATA(header), sizeof(received));
    if (received < 0) errno = EPROTO;
    return received;
}

static int status(const char *value) {
    puts(value);
    return 0;
}

static int denied(int error) {
    return error == EACCES || error == EPERM;
}

static int sender(const char *rendezvous, const char *broker_socket) {
    struct sockaddr_un address;
    socklen_t length;
    if (!address_for(rendezvous, &address, &length) ||
        !address_for(broker_socket, &address, &length)) return 1;

    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return denied(errno) ? status("denied") : 1;
    address_for(rendezvous, &address, &length);
    mode_t old_umask = umask(0111);
    int bound = bind(listener, (struct sockaddr *)&address, length);
    int bind_error = errno;
    umask(old_umask);
    if (bound != 0) {
        close(listener);
        return denied(bind_error) ? status("denied") : 1;
    }
    int result = 1;
    int broker = -1;
    int peer = -1;
    struct stat node;
    if (lstat(rendezvous, &node) != 0 || !S_ISSOCK(node.st_mode) ||
        (node.st_mode & 0777) != 0666 || listen(listener, 1) != 0) goto done;

    address_for(broker_socket, &address, &length);
    broker = socket(AF_UNIX, SOCK_STREAM, 0);
    if (broker < 0 || !deadline_for(broker) ||
        connect(broker, (struct sockaddr *)&address, length) != 0 ||
        !write_text(broker, "XFER-START-V1\n") ||
        !read_text(broker, "XFER-READY-V1\n")) goto done;

    struct pollfd pending = { .fd = listener, .events = POLLIN };
    int ready = poll(&pending, 1, 12000);
    if (ready == 0) { result = status("unreachable"); goto done; }
    if (ready < 0 || !(pending.revents & POLLIN)) goto done;
    peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        if (denied(errno)) result = status("denied");
        goto done;
    }
    if (!deadline_for(peer)) goto done;
    // Keep the donor's socket open until the recipient reads the broker's reply.
    if (send_fd(peer, broker) && read_text(peer, "XFER-DONE-V1\n")) result = status("sent");
    else if (denied(errno)) result = status("denied");
done:
    if (peer >= 0) close(peer);
    if (broker >= 0) close(broker);
    close(listener);
    unlink(rendezvous);
    return result;
}

static int receiver(const char *rendezvous) {
    struct sockaddr_un address;
    socklen_t length;
    if (!address_for(rendezvous, &address, &length)) return 1;
    int peer = -1;
    for (int i = 0; i < 120; i++) {
        peer = socket(AF_UNIX, SOCK_STREAM, 0);
        if (peer < 0) return denied(errno) ? status("denied") : 1;
        if (connect(peer, (struct sockaddr *)&address, length) == 0) break;
        int error = errno;
        close(peer);
        peer = -1;
        if (denied(error)) return status("denied");
        if (error != ENOENT && error != ECONNREFUSED) return 1;
        struct timespec pause = { .tv_nsec = 100000000 };
        nanosleep(&pause, NULL);
    }
    if (peer < 0) return status("unreachable");
    int result = 1;
    if (!deadline_for(peer)) goto done;
    int broker = recv_fd(peer);
    if (broker < 0) {
        if (denied(errno)) result = status("denied");
        else if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNRESET)
            result = status("unreachable");
        if (result == 0) write_text(peer, "XFER-DONE-V1\n");
        goto done;
    }
    if (!deadline_for(broker)) { close(broker); goto done; }
    if (write_text(broker, "XFER-USE-V1\n") && read_text(broker, "XFER-ACK-V1\n")) {
        result = status("used");
    } else if (denied(errno)) {
        result = status("denied");
    } else {
        perror("receive: broker exchange");
    }
    if (!write_text(peer, "XFER-DONE-V1\n")) result = 1;
    close(broker);
done:
    close(peer);
    return result;
}

static int self_test(void) {
    int sockets[2];
    int pipe_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0 || pipe(pipe_fds) != 0) return 1;
    if (!send_fd(sockets[0], pipe_fds[0])) return 1;
    int passed = recv_fd(sockets[1]);
    if (passed < 0 || write(pipe_fds[1], "x", 1) != 1) return 1;
    char byte = 0;
    int good = read(passed, &byte, 1) == 1 && byte == 'x';
    close(passed);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(sockets[0]);
    close(sockets[1]);
    return good ? 0 : 1;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "self-test") == 0) return self_test();
    if (argc == 4 && strcmp(argv[1], "send") == 0) return sender(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "recv") == 0) return receiver(argv[2]);
    return 1;
}
