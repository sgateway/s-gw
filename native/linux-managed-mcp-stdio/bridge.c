/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* The root manager must bind this port only in the matching private network namespace. */
#define MCP_PORT 43871
#define BUFFER_SIZE (64u * 1024u)
#define MAX_STREAM (64u * 1024u * 1024u)
#define IDLE_MS (35 * 60 * 1000)

struct lane {
    int input;
    int output;
    unsigned char buffer[BUFFER_SIZE];
    size_t used;
    size_t sent;
    size_t total;
    bool eof;
};

static struct lane to_broker;
static struct lane to_client;

static long long now_ms(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return -1;
    return (long long)time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

static int nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int connect_forwarder(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (nonblocking(fd) != 0) goto fail;

    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(MCP_PORT);
    address.sin_addr.s_addr = htonl(0x7f000001u);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0) return fd;
    if (errno != EINPROGRESS) goto fail;

    struct pollfd wait_for = { .fd = fd, .events = POLLOUT };
    if (poll(&wait_for, 1, 5000) <= 0) goto fail;
    int error = 0;
    socklen_t error_len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 || error != 0) goto fail;
    return fd;

fail:
    close(fd);
    return -1;
}

static bool can_read(const struct lane *lane) {
    return !lane->eof && lane->sent == lane->used;
}

static bool can_write(const struct lane *lane) {
    return lane->sent < lane->used;
}

static int read_chunk(struct lane *lane) {
    unsigned char excess;
    size_t room = MAX_STREAM - lane->total;
    void *target = room ? (void *)lane->buffer : (void *)&excess;
    if (room > sizeof(lane->buffer)) room = sizeof(lane->buffer);
    ssize_t count = read(lane->input, target, room ? room : 1);
    if (count > 0) {
        if (room == 0) return -1;
        lane->used = (size_t)count;
        lane->sent = 0;
        lane->total += (size_t)count;
        return 1;
    }
    if (count == 0) {
        lane->eof = true;
        return 1;
    }
    if (errno == EAGAIN || errno == EINTR) return 0;
    return -1;
}

static int write_chunk(struct lane *lane) {
    ssize_t count = write(lane->output, lane->buffer + lane->sent, lane->used - lane->sent);
    if (count > 0) {
        lane->sent += (size_t)count;
        if (lane->sent == lane->used) lane->sent = lane->used = 0;
        return 1;
    }
    if (count < 0 && (errno == EAGAIN || errno == EINTR)) return 0;
    return -1;
}

static int relay(int socket_fd) {
    to_broker = (struct lane){ .input = STDIN_FILENO, .output = socket_fd };
    to_client = (struct lane){ .input = socket_fd, .output = STDOUT_FILENO };
    if (nonblocking(STDIN_FILENO) != 0 || nonblocking(STDOUT_FILENO) != 0) return -1;

    bool sent_fin = false;
    long long last_activity = now_ms();
    if (last_activity < 0) return -1;
    for (;;) {
        if (to_client.eof && !can_write(&to_client)) return 0;
        if (to_broker.eof && !can_write(&to_broker) && !sent_fin) {
            if (shutdown(socket_fd, SHUT_WR) != 0) return -1;
            sent_fin = true;
        }

        short socket_events = (short)((can_read(&to_client) ? POLLIN : 0) |
                                      (can_write(&to_broker) ? POLLOUT : 0));
        struct pollfd fds[3] = {
            { .fd = can_read(&to_broker) ? STDIN_FILENO : -1, .events = POLLIN },
            { .fd = can_write(&to_client) ? STDOUT_FILENO : -1, .events = POLLOUT },
            { .fd = socket_events ? socket_fd : -1, .events = socket_events }
        };
        long long left = IDLE_MS - (now_ms() - last_activity);
        if (left <= 0 || left > IDLE_MS) return -1;
        int result = poll(fds, 3, (int)left);
        if (result == 0) return -1;
        if (result < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if ((fds[0].revents | fds[1].revents | fds[2].revents) & POLLNVAL) return -1;

        int progress = 0;
        if (can_read(&to_client) && (fds[2].revents & (POLLIN | POLLHUP | POLLERR))) {
            progress = read_chunk(&to_client);
            if (progress < 0) return -1;
        }
        if (can_write(&to_client) && (fds[1].revents & (POLLOUT | POLLHUP | POLLERR))) {
            int wrote = write_chunk(&to_client);
            if (wrote < 0) return -1;
            progress |= wrote;
        }
        if (!to_client.eof && can_write(&to_broker) && (fds[2].revents & POLLOUT)) {
            int wrote = write_chunk(&to_broker);
            if (wrote < 0) return -1;
            progress |= wrote;
        }
        if (can_read(&to_broker) && (fds[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            int read_more = read_chunk(&to_broker);
            if (read_more < 0) return -1;
            progress |= read_more;
        }
        if (!progress && (fds[2].revents & (POLLERR | POLLHUP))) return -1;
        if (progress) last_activity = now_ms();
        if (last_activity < 0) return -1;
    }
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) {
        fputs("managed MCP bridge takes no arguments\n", stderr);
        return 2;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fputs("managed MCP bridge could not set signal policy\n", stderr);
        return 1;
    }
    int socket_fd = connect_forwarder();
    if (socket_fd < 0) {
        fputs("managed MCP bridge could not reach its forwarder\n", stderr);
        return 1;
    }
    int result = relay(socket_fd);
    close(socket_fd);
    if (result != 0) {
        fputs("managed MCP bridge closed a failed or over-limit stream\n", stderr);
        return 1;
    }
    return 0;
}
