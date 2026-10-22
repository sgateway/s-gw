#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <grp.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
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

static int netlink_route_socket(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd >= 0) { close(fd); return 1; }
    return 0;
}

static int netlink_route_denied(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd >= 0) { close(fd); return 0; }
    return errno == EAFNOSUPPORT || errno == EPERM;
}

static int initialized_broker_socket(const char *socket_path) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, socket_path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval deadline = { .tv_sec = 12, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    char reply[16384];
    if (send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":81,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"handoff-probe\",\"version\":\"1\"}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":81") ||
        !strstr(reply, "\"result\"") ||
        send_line(fd, "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n") != 0 ||
        send_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":82,\"method\":\"tools/list\",\"params\":{}}\n") != 0 ||
        receive_line(fd, reply, sizeof(reply)) != 0 || !strstr(reply, "\"id\":82") ||
        !strstr(reply, "sgw_list_handles")) {
        close(fd);
        return -1;
    }
    return fd;
}

static int positive_number(const char *text) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    return errno == 0 && end && *end == 0 && value > 0 && value <= 1000000000 ? (int)value : -1;
}

static int enter_agent_netns_and_drop(const char *pid_text, const char *uid_text,
                                      const char *gid_text) {
    int pid = positive_number(pid_text);
    int uid = positive_number(uid_text);
    int gid = positive_number(gid_text);
    if (getuid() != 0 || geteuid() != 0 || pid < 1 || uid < 1 || gid < 1) return -1;
    char name[64];
    int length = snprintf(name, sizeof(name), "/proc/%d/ns/net", pid);
    if (length < 0 || (size_t)length >= sizeof(name)) return -1;
    int ns = open(name, O_RDONLY | O_CLOEXEC);
    if (ns < 0) return -1;
    int joined = setns(ns, CLONE_NEWNET);
    close(ns);
    if (joined != 0 || setgroups(0, NULL) != 0 ||
        setresgid((gid_t)gid, (gid_t)gid, (gid_t)gid) != 0 ||
        setresuid((uid_t)uid, (uid_t)uid, (uid_t)uid) != 0) return -1;
    return 0;
}

static int handoff_socket(int broker_fd, const char *name) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, name);
    int channel = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (channel < 0) return -1;
    if (connect(channel, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int error = errno;
        close(channel);
        return error == EACCES || error == EPERM || error == ENOENT || error == ECONNREFUSED ? 0 : -1;
    }
    char payload = 'x';
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &broker_fd, sizeof(int));
    ssize_t sent = sendmsg(channel, &message, MSG_NOSIGNAL);
    int error = errno;
    close(channel);
    if (sent == 1) return 1;
    return sent < 0 && (error == EACCES || error == EPERM) ? 0 : -1;
}

static int write_handoff_result(const char *filename, const char *result) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int written = send_line(fd, result);
    int closed = close(fd);
    return written == 0 && closed == 0 ? 0 : -1;
}

static int receive_handoff(const char *socket_name, const char *result_name,
                           const char *pid_name, const char *expected_handle, int agent_pid,
                           int model, int cross_session) {
    if (agent_pid < 1 || agent_pid == getpid() ||
        strlen(socket_name) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 30;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, socket_name);
    int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 || (cross_session && chmod(socket_name, 0666) != 0)) return 31;
    char pid_text[32];
    int pid_size = snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)getpid());
    if (pid_size < 0 || (size_t)pid_size >= sizeof(pid_text) ||
        write_handoff_result(pid_name, pid_text) != 0) return 38;
    int channel = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (channel < 0) return 32;
    struct timeval deadline = { .tv_sec = 6, .tv_usec = 0 };
    if (setsockopt(channel, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0) return 33;
    char payload = 0;
    struct iovec iov = { .iov_base = &payload, .iov_len = 1 };
    char control[CMSG_SPACE(sizeof(int))] = { 0 };
    struct msghdr message = { .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control) };
    ssize_t count = recvmsg(channel, &message, MSG_CMSG_CLOEXEC);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    int broker_fd = -1;
    if (header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
        header->cmsg_len == CMSG_LEN(sizeof(int))) memcpy(&broker_fd, CMSG_DATA(header), sizeof(int));
    close(channel);
    close(listener);
    if (count != 1 || payload != 'x' || (message.msg_flags & MSG_CTRUNC) || broker_fd < 0) return 34;
    struct stat info;
    int socket_type = 0;
    socklen_t type_size = sizeof(socket_type);
    if (fstat(broker_fd, &info) != 0 || !S_ISSOCK(info.st_mode) ||
        getsockopt(broker_fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_size) != 0 ||
        socket_type != SOCK_STREAM) return 35;
    if (setsockopt(broker_fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(broker_fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0) return 36;
    char forged_byte = 'x';
    struct iovec forged_data = { .iov_base = &forged_byte, .iov_len = 1 };
    char forged_control[CMSG_SPACE(sizeof(struct ucred))] = { 0 };
    struct msghdr forged = { .msg_iov = &forged_data, .msg_iovlen = 1,
        .msg_control = forged_control, .msg_controllen = sizeof(forged_control) };
    struct cmsghdr *claimed = CMSG_FIRSTHDR(&forged);
    struct ucred identity = { .pid = agent_pid, .uid = getuid(), .gid = getgid() };
    claimed->cmsg_level = SOL_SOCKET;
    claimed->cmsg_type = SCM_CREDENTIALS;
    claimed->cmsg_len = CMSG_LEN(sizeof(identity));
    memcpy(CMSG_DATA(claimed), &identity, sizeof(identity));
    if (sendmsg(broker_fd, &forged, MSG_NOSIGNAL) != -1 || errno != EPERM) return 40;
    const char *result = "inconclusive\n";
    if (model) {
        const char *remaining = "\"max_tokens\":16,\"mcp_servers\":[]}";
        if (send_line(broker_fd, remaining) != 0) result = "denied\n";
        else {
            char reply[4096] = { 0 };
            size_t used = 0;
            while (used + 1 < sizeof(reply)) {
                ssize_t received = read(broker_fd, reply + used, sizeof(reply) - used - 1);
                if (received == 0 || (received < 0 && errno == ECONNRESET)) {
                    if (used == 0) result = "denied\n";
                    break;
                }
                if (received < 0) break;
                used += (size_t)received;
                reply[used] = 0;
            }
            if (strstr(reply, "HTTP/1.1 403") &&
                strstr(reply, "Remote model MCP servers are outside this grant.")) result = "accepted\n";
        }
    } else if (send_line(broker_fd, "{\"jsonrpc\":\"2.0\",\"id\":91,\"method\":\"tools/call\",\"params\":{\"name\":\"sgw_list_handles\",\"arguments\":{}}}\n") != 0) {
        result = "denied\n";
    } else {
        char reply[16384];
        int read_result = receive_line(broker_fd, reply, sizeof(reply));
        if (read_result == -2) result = "denied\n";
        else if (read_result == 0 && strstr(reply, "\"id\":91") &&
                 strstr(reply, "\"result\"") && strstr(reply, expected_handle) &&
                 !strstr(reply, "\"isError\":true")) result = "accepted\n";
    }
    close(broker_fd);
    return write_handoff_result(result_name, result) == 0 ? 0 : 37;
}

static int connect_model(const char *name) {
    if (!name || strlen(name) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return -1;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, name);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval deadline = { .tv_sec = 12, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof(deadline)) != 0 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int model_headers(int fd, size_t length) {
    char headers[300];
    int size = snprintf(headers, sizeof(headers),
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
        "Content-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", length);
    return size > 0 && (size_t)size < sizeof(headers) && send_line(fd, headers) == 0 ? 0 : -1;
}

static int strict_model_denied(const char *socket_path) {
    const char *body = "{\"model\":\"fixture-model\",\"max_tokens\":16,\"mcp_servers\":[]}";
    int fd = connect_model(socket_path);
    if (fd < 0) return -1;
    if (model_headers(fd, strlen(body)) != 0 || send_line(fd, body) != 0) {
        close(fd);
        return -1;
    }
    char reply[8192] = { 0 };
    size_t used = 0;
    while (used + 1 < sizeof(reply)) {
        ssize_t count = read(fd, reply + used, sizeof(reply) - used - 1);
        if (count == 0) break;
        if (count < 0) { close(fd); return -1; }
        used += (size_t)count;
        reply[used] = 0;
    }
    close(fd);
    return strstr(reply, "HTTP/1.1 403") &&
           strstr(reply, "Remote model MCP servers are outside this grant.") ? 0 : -1;
}

static int model_stream_request(const char *socket_path, int cancel) {
    const char *phase = cancel ? "fixture-cancel" : "fixture-stream-complete";
    const char *first = cancel ? "fixture-cancel-first" : "fixture-first";
    char body[256], headers[512], reply[32768] = { 0 };
    int body_size = snprintf(body, sizeof(body),
        "{\"model\":\"fixture-model\",\"max_tokens\":16,\"stream\":true,"
        "\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}]}", phase);
    if (body_size < 0 || (size_t)body_size >= sizeof(body)) return -1;
    int fd = connect_model(socket_path);
    if (fd < 0) return -1;
    struct timeval deadline = { .tv_sec = 30, .tv_usec = 0 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0) {
        close(fd);
        return -1;
    }
    int header_size = snprintf(headers, sizeof(headers),
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\n"
        "Authorization: Bearer agent-supplied-fixture\r\n"
        "x-api-key: agent-supplied-fixture\r\nConnection: close\r\n\r\n", body_size);
    if (header_size < 0 || (size_t)header_size >= sizeof(headers) ||
        send_line(fd, headers) != 0 || send_line(fd, body) != 0) {
        close(fd);
        return -1;
    }
    size_t used = 0;
    while (!strstr(reply, first) && used + 1 < sizeof(reply)) {
        ssize_t count = read(fd, reply + used, sizeof(reply) - used - 1);
        if (count <= 0) { close(fd); return -1; }
        used += (size_t)count;
        reply[used] = 0;
    }
    if (!strstr(reply, "HTTP/1.1 200") || strstr(reply, "fixture-second") ||
        strstr(reply, "synthetic-managed-model-")) {
        close(fd);
        return -1;
    }
    const char *first_result = cancel ? "/workspace/model-cancel-ready" : "/workspace/model-stream-first";
    if (write_handoff_result(first_result, "first\n") != 0) { close(fd); return -1; }
    if (cancel) {
        for (;;) pause();
    }
    char gate[32];
    int released = 0;
    for (int attempt = 0; attempt < 300; attempt++) {
        if (read_field("/workspace/model-stream-go", gate, sizeof(gate)) == 0 &&
            strcmp(gate, "go") == 0) { released = 1; break; }
        usleep(100000);
    }
    if (!released) { close(fd); return -1; }
    while (used + 1 < sizeof(reply)) {
        ssize_t count = read(fd, reply + used, sizeof(reply) - used - 1);
        if (count == 0) break;
        if (count < 0) { close(fd); return -1; }
        used += (size_t)count;
        reply[used] = 0;
    }
    close(fd);
    if (!strstr(reply, "fixture-second") ||
        !strstr(reply, "[s-gw withheld credential]") ||
        strstr(reply, "synthetic-managed-model-")) return -1;
    return write_handoff_result("/workspace/model-stream-result", "streamed\n");
}

static int model_handoff_probe(const char *socket_path, const char *handoff_path,
                               const char *ready_path, const char *result_path) {
    const char *prefix = "{\"model\":\"fixture-model\",";
    const char *remaining = "\"max_tokens\":16,\"mcp_servers\":[]}";
    int fd = connect_model(socket_path);
    if (fd < 0) return -1;
    if (model_headers(fd, strlen(prefix) + strlen(remaining)) != 0 ||
        send_line(fd, prefix) != 0 ||
        write_handoff_result(ready_path, "ready\n") != 0) {
        close(fd);
        return -1;
    }
    int handoff = handoff_socket(fd, handoff_path);
    close(fd);
    if (handoff != 1) return -1;
    for (int attempt = 0; attempt < 100; attempt++) {
        if (access(result_path, F_OK) == 0) return 0;
        usleep(100000);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--netlink-positive") == 0)
        return netlink_route_socket() ? 0 : 47;
    if (argc == 3 && strcmp(argv[1], "--ptrace-out-of-cgroup") == 0) {
        int pid = positive_number(argv[2]);
        if (pid < 1) return 48;
        if (ptrace(PTRACE_SEIZE, (pid_t)pid, NULL, NULL) == 0) {
            ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
            return 49;
        }
        return errno == EPERM || errno == EACCES ? 0 : 50;
    }
    int claimant = argc == 2 && strcmp(argv[1], "--out-of-cgroup") == 0;
    int model_claimant = argc == 2 && strcmp(argv[1], "--model-out-of-cgroup") == 0;
    int model_cross_uid = argc == 2 && strcmp(argv[1], "--model-cross-uid") == 0;
    int cross_handoff = argc == 10 && strcmp(argv[1], "--receive-cross-model-handoff") == 0;
    if ((argc == 9 && (strcmp(argv[1], "--receive-handoff") == 0 ||
                       strcmp(argv[1], "--receive-model-handoff") == 0)) || cross_handoff) {
        signal(SIGPIPE, SIG_IGN);
        if (enter_agent_netns_and_drop(cross_handoff ? argv[9] : argv[6], argv[7], argv[8]) != 0) return 39;
        return receive_handoff(argv[2], argv[3], argv[4], argv[5], positive_number(argv[6]),
                               strcmp(argv[1], "--receive-handoff") != 0, cross_handoff);
    }
    if (model_claimant || model_cross_uid) {
        signal(SIGPIPE, SIG_IGN);
        const char *model_socket = getenv("SGW_MODEL_RELAY_SOCKET");
        int model_fd = connect_model(model_socket);
        if (model_cross_uid) return model_fd < 0 && (errno == EACCES || errno == EPERM) ? 0 : 44;
        if (model_fd < 0) return 45;
        const char *body = "{\"model\":\"fixture-model\",\"max_tokens\":16,\"mcp_servers\":[]}";
        int sent = model_headers(model_fd, strlen(body)) == 0 && send_line(model_fd, body) == 0;
        if (!sent) { close(model_fd); return 0; }
        char byte;
        ssize_t received = read(model_fd, &byte, 1);
        int error = errno;
        close(model_fd);
        return received == 0 || (received < 0 && error == ECONNRESET) ? 0 : 46;
    }
    const char *model_socket = getenv("SGW_MODEL_RELAY_SOCKET");
    if ((model_socket ? argc != 12 : argc != 11) && !claimant) return 1;
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
    int model_direct = !model_socket || network_probe(AF_INET, SOCK_STREAM, argv[11], 443);
    int netlink_denied = netlink_route_denied();
    const char *model_result = "";
    if (model_socket) model_result = model_direct ? " model=1" : " model=0";
    char boundary[128];
    int boundary_size = snprintf(boundary, sizeof(boundary),
        "files=%d tcp4=%d tcp6=%d tcphost=%d udp4=%d udp6=%d udphost=%d netlink=%d%s\n",
        files, tcp4, tcp6, tcp_host, udp4, udp6, udp_host, netlink_denied, model_result);
    if (boundary_size < 0 || (size_t)boundary_size >= sizeof(boundary)) return 21;
    int boundary_fd = open("/workspace/boundary", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    ssize_t boundary_written = boundary_fd < 0 ? -1 : write(boundary_fd, boundary, (size_t)boundary_size);
    int boundary_closed = boundary_fd < 0 ? -1 : close(boundary_fd);
    if (boundary_written != boundary_size || boundary_closed != 0) return 21;
    if (!files || !tcp4 || !tcp6 || !tcp_host || !udp4 || !udp6 || !udp_host ||
        !netlink_denied || !model_direct) return 22;
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
    int handoff_fd = initialized_broker_socket(socket_path);
    if (handoff_fd < 0) return 28;
    int ready = open("/workspace/handoff-ready", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ready < 0 || write(ready, "ready\n", 6) != 6 || close(ready) != 0) return 26;
    int release = 0;
    char handoff_gate[32];
    for (int attempt = 0; attempt < 900; attempt++) {
        if (read_field("/workspace/handoff-go", handoff_gate, sizeof(handoff_gate)) == 0 &&
            strcmp(handoff_gate, "go") == 0) { release = 1; break; }
        usleep(100000);
    }
    if (!release) return 27;
    int handoff = handoff_socket(handoff_fd, "/workspace/handoff.sock");
    close(handoff_fd);
    if (handoff != 1) return 23;
    int finished = 0;
    for (int attempt = 0; attempt < 100; attempt++) {
        int result = open("/workspace/handoff-result", O_RDONLY | O_CLOEXEC);
        if (result >= 0) { close(result); finished = 1; break; }
        usleep(100000);
    }
    if (!finished) return 25;
    if (model_socket) {
        if (strict_model_denied(model_socket) != 0) return 41;
        if (model_handoff_probe(model_socket, "/workspace/model-handoff.sock",
            "/workspace/model-handoff-ready", "/workspace/model-handoff-result") != 0) return 42;
        if (model_handoff_probe(model_socket, "/run/s-gw/handoff-cross/model.sock",
            "/workspace/cross-model-handoff-ready", "/run/s-gw/handoff-cross/result") != 0) return 47;
        if (model_stream_request(model_socket, 0) != 0) return 48;
        if (write_handoff_result("/workspace/model-result", "strict-rejected-and-streamed\n") != 0) return 43;
    }
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
    if (model_socket && model_stream_request(model_socket, 1) != 0) return 49;
    for (;;) pause();
}
