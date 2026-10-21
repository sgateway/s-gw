#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t retry = 0;

static void on_retry(int signal_number) {
    (void)signal_number;
    retry = 1;
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
    if (save("/workspace/result", result) != 0) return 70;
    while (!retry) pause();
    const char *rebound = approved(argv[2], argv[1]) ? "rebind=accepted\n" : "rebind=denied\n";
    return save("/workspace/rebind", rebound) == 0 ? 0 : 70;
}
