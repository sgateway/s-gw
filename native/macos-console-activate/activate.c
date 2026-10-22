#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <launch.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int expected_port(const char *text) {
    char *end = NULL;
    errno = 0;
    long port = strtol(text, &end, 10);
    if (errno || !end || *end || port < 1 || port > 65535) return -1;
    return (int)port;
}

static int valid_listener(int fd, int port) {
    int type = 0;
    int accepting = 0;
    socklen_t size = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) != 0 || type != SOCK_STREAM) return 0;
    size = sizeof(accepting);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &size) != 0 || !accepting) return 0;

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    size = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &size) != 0) return 0;
    return size == sizeof(address) && address.sin_family == AF_INET
        && address.sin_addr.s_addr == htonl(INADDR_LOOPBACK)
        && ntohs(address.sin_port) == port;
}

int main(int argc, char **argv) {
    if (argc != 12 || argv[1][0] != '/' || argv[2][0] != '/'
        || strcmp(argv[3], "console") || strcmp(argv[4], "--host")
        || strcmp(argv[5], "127.0.0.1") || strcmp(argv[6], "--port")
        || strcmp(argv[8], "--no-open") || strcmp(argv[9], "--operator-auth")
        || strcmp(argv[10], "--background") || strcmp(argv[11], "--launchd-socket")) {
        fputs("Expected the protected launchd console arguments.\n", stderr);
        return 2;
    }

    int port = expected_port(argv[7]);
    if (port < 0) {
        fputs("Invalid protected console port.\n", stderr);
        return 2;
    }

    int *fds = NULL;
    size_t count = 0;
    int result = launch_activate_socket("ProtectedConsole", &fds, &count);
    if (result != 0 || count != 1 || !valid_listener(fds[0], port)) {
        fputs("Expected one launchd-owned IPv4 loopback listener on the configured port.\n", stderr);
        free(fds);
        return 1;
    }

    int fd = fds[0];
    free(fds);
    if (fd != 3 && dup2(fd, 3) < 0) {
        perror("dup2");
        return 1;
    }
    if (fd != 3) close(fd);
    int flags = fcntl(3, F_GETFD);
    if (flags < 0 || fcntl(3, F_SETFD, flags & ~FD_CLOEXEC) < 0
        || setenv("SGW_CONSOLE_ACTIVATED_FD", "3", 1) != 0) {
        fputs("Could not pass the protected console listener to Node.\n", stderr);
        return 1;
    }

    char *node_args[] = {argv[1], argv[2], argv[3], argv[4], argv[5], argv[6],
        argv[7], argv[8], argv[9], argv[10], argv[11], NULL};
    execv(argv[1], node_args);
    perror("execv");
    return 1;
}
