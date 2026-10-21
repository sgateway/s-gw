#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int send_line(int fd, const char *line) {
    size_t left = strlen(line);
    while (left) {
        ssize_t sent = write(fd, line, left);
        if (sent <= 0) return -1;
        line += sent;
        left -= (size_t)sent;
    }
    return 0;
}

static int receive_line(int fd, char *out, size_t capacity) {
    size_t used = 0;
    while (used + 1 < capacity) {
        ssize_t count = read(fd, out + used, 1);
        if (count == 0) return -2;
        if (count < 0) {
            if (errno == EINTR) continue;
            return errno == ECONNRESET ? -2 : -1;
        }
        if (out[used++] == '\n') {
            out[used] = 0;
            return 0;
        }
    }
    return -1;
}

static int read_field(const char *filename, char *out, size_t capacity) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;
    char *line = fgets(out, (int)capacity, file);
    if (fclose(file) != 0 || !line) return -1;
    size_t length = strlen(out);
    if (length < 2 || out[length - 1] != '\n') return -1;
    out[length - 1] = 0;
    if (strspn(out, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.:/") != length - 1) return -1;
    return 0;
}

static int canary_denied(const char *filename) {
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 0; }
    fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 0; }
    return 1;
}

static int own_canary_readable(void) {
    int fd = open("/workspace/private-canary", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char marker = 0;
    int readable = read(fd, &marker, 1) == 1 && marker == 'p';
    close(fd);
    return readable;
}

static int port_number(const char *value) {
    char *end = NULL;
    errno = 0;
    long port = strtol(value, &end, 10);
    return errno == 0 && end && *end == 0 && port > 0 && port <= 65535 ? (int)port : -1;
}

static int network_probe(int family, int kind, const char *host, int port) {
    int fd = socket(family, kind | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct timeval deadline = { .tv_sec = 2, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0) {
        close(fd);
        return 0;
    }
    int result;
    if (family == AF_INET) {
        struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
        if (inet_pton(AF_INET, host, &address.sin_addr) != 1) { close(fd); return 0; }
        result = kind == SOCK_STREAM
            ? connect(fd, (struct sockaddr *)&address, sizeof(address))
            : sendto(fd, "probe", 5, 0, (struct sockaddr *)&address, sizeof(address));
    } else {
        struct sockaddr_in6 address = { .sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port) };
        if (inet_pton(AF_INET6, host, &address.sin6_addr) != 1) { close(fd); return 0; }
        result = kind == SOCK_STREAM
            ? connect(fd, (struct sockaddr *)&address, sizeof(address))
            : sendto(fd, "probe", 5, 0, (struct sockaddr *)&address, sizeof(address));
    }
    close(fd);
    return kind == SOCK_STREAM ? result != 0 : 1;
}

int main(int argc, char **argv) {
    int claimant = argc == 2 && strcmp(argv[1], "--out-of-cgroup") == 0;
    if (argc != 11 && !claimant) return 1;
    signal(SIGPIPE, SIG_IGN);
    const char *socket_path = getenv("SGW_BROKER_SOCKET");
    if (!socket_path || strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) return 3;
    struct timeval deadline = { .tv_sec = claimant ? 8 : 12, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0) return 4;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 5;
    char reply[16384];
    if (claimant) {
        return receive_line(fd, reply, sizeof(reply)) == -2 ? 0 : 10;
    }
    const int port_args[6] = { 4, 5, 7, 8, 9, 10 };
    int ports[6];
    for (int index = 0; index < 6; index++) {
        ports[index] = port_number(argv[port_args[index]]);
        if (ports[index] < 0) return 20;
    }
    int files = own_canary_readable() && canary_denied(argv[1]) &&
        canary_denied(argv[2]) && canary_denied(argv[3]);
    int tcp4 = network_probe(AF_INET, SOCK_STREAM, "127.0.0.1", ports[0]);
    int tcp6 = network_probe(AF_INET6, SOCK_STREAM, "::1", ports[1]);
    int tcp_host = network_probe(AF_INET, SOCK_STREAM, argv[6], ports[2]);
    int udp4 = network_probe(AF_INET, SOCK_DGRAM, "127.0.0.1", ports[3]);
    int udp6 = network_probe(AF_INET6, SOCK_DGRAM, "::1", ports[4]);
    int udp_host = network_probe(AF_INET, SOCK_DGRAM, argv[6], ports[5]);
    char boundary[128];
    int boundary_size = snprintf(boundary, sizeof(boundary),
        "files=%d tcp4=%d tcp6=%d tcphost=%d udp4=%d udp6=%d udphost=%d\n",
        files, tcp4, tcp6, tcp_host, udp4, udp6, udp_host);
    if (boundary_size < 0 || (size_t)boundary_size >= sizeof(boundary)) return 21;
    int boundary_fd = open("/workspace/boundary", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ssize_t boundary_written = boundary_fd < 0 ? -1 : write(boundary_fd, boundary, (size_t)boundary_size);
    int boundary_closed = boundary_fd < 0 ? -1 : close(boundary_fd);
    if (boundary_written != boundary_size || boundary_closed != 0) return 21;
    if (!files || !tcp4 || !tcp6 || !tcp_host || !udp4 || !udp6 || !udp_host) return 22;
    char handle[256], url[256], request_id[256], foreign_id[256], call[1024];
    if (read_field("/workspace/handle", handle, sizeof(handle)) != 0 ||
        read_field("/workspace/url", url, sizeof(url)) != 0) return 11;
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"forged-agent\",\"version\":\"1\"}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":1") ||
        !strstr(reply, "\"result\"")) return 6;
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n") != 0 ||
        send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "sgw_list_handles") ||
        strstr(reply, "sgw_scan_file")) return 7;
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_list_handles\",\"arguments\":{}}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":3") ||
        !strstr(reply, "\"result\"") || !strstr(reply, handle)) return 8;
    int size = snprintf(call, sizeof(call), "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_request_http\",\"arguments\":{\"handle\":\"%s\",\"url\":\"%s\",\"method\":\"GET\",\"auth\":{\"kind\":\"bearer\"},\"reason\":\"Native managed MCP fixture\"}}}\n", handle, url);
    if (size < 0 || (size_t)size >= sizeof(call) || send_line(fd, call) != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":4") ||
        !strstr(reply, "\"result\"") || !strstr(reply, "approvalRequired")) return 12;
    int marker = open("/workspace/requested", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (marker < 0 || write(marker, "pending\n", 8) != 8 || close(marker) != 0) return 13;
    int approved = 0;
    for (int attempt = 0; attempt < 300; attempt++) {
        if (read_field("/workspace/approved-id", request_id, sizeof(request_id)) == 0) {
            approved = 1;
            break;
        }
        usleep(100000);
    }
    if (!approved) return 14;
    if (read_field("/workspace/foreign-id", foreign_id, sizeof(foreign_id)) != 0) return 16;
    size = snprintf(call, sizeof(call), "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_execute_request\",\"arguments\":{\"requestId\":\"%s\"}}}\n", foreign_id);
    if (size < 0 || (size_t)size >= sizeof(call) || send_line(fd, call) != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":5") ||
        !strstr(reply, "isError\":true") || !strstr(reply, "different verified agent")) return 17;
    int denied = open("/workspace/foreign-denied", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (denied < 0 || write(denied, "denied\n", 7) != 7 || close(denied) != 0) return 18;
    int go = 0;
    char gate[256];
    for (int attempt = 0; attempt < 300; attempt++) {
        if (read_field("/workspace/execute-go", gate, sizeof(gate)) == 0 &&
            strcmp(gate, "go") == 0) {
            go = 1;
            break;
        }
        usleep(100000);
    }
    if (!go) return 19;
    size = snprintf(call, sizeof(call), "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_execute_request\",\"arguments\":{\"requestId\":\"%s\"}}}\n", request_id);
    if (size < 0 || (size_t)size >= sizeof(call) || send_line(fd, call) != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":6") ||
        !strstr(reply, "\"result\"") || !strstr(reply, "approved fixture") ||
        !strstr(reply, "\\\"exitCode\\\": 0")) return 15;
    int result = open("/workspace/result", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (result < 0 || write(result, "owned-https=1\n", 14) != 14 || close(result) != 0) return 9;
    for (;;) pause();
}
