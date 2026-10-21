#define _GNU_SOURCE
#include <fcntl.h>
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
        if (count != 1) return -1;
        if (out[used++] == '\n') {
            out[used] = 0;
            return 0;
        }
    }
    return -1;
}

int main(void) {
    const char *socket_path = getenv("SGW_BROKER_SOCKET");
    if (!socket_path || strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 3;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) return 3;
    struct timeval deadline = { .tv_sec = 12, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0) return 4;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 5;
    char reply[16384];
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"forged-agent\",\"version\":\"1\"}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":1") ||
        !strstr(reply, "\"result\"")) return 6;
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n") != 0 ||
        send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "sgw_list_handles") ||
        strstr(reply, "sgw_scan_file")) return 7;
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_list_handles\",\"arguments\":{}}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":3") ||
        !strstr(reply, "\"result\"")) return 8;
    int result = open("/workspace/result", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (result < 0 || write(result, "verified-mcp=1\n", 15) != 15 || close(result) != 0) return 9;
    for (;;) pause();
}
