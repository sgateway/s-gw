#define main sgw_message_gate_main
#include "../native/linux-message-gate/gate.c"
#undef main

#include <stddef.h>

static int check(int good, const char *name) {
    if (good) return 1;
    fprintf(stderr, "Linux message gate failed: %s\n", name);
    return 0;
}

static int use_gate_fd(int *receiver, int *sender) {
    if (*sender == SOCKET_FD) {
        int moved = fcntl(*sender, F_DUPFD_CLOEXEC, SOCKET_FD + 1);
        if (moved < 0) return 0;
        close(*sender);
        *sender = moved;
    }
    if (*receiver == SOCKET_FD) return 1;
    if (dup2(*receiver, SOCKET_FD) != SOCKET_FD) return 0;
    close(*receiver);
    *receiver = SOCKET_FD;
    return 1;
}

static int stream_pair(int *sender) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) return 0;
    *sender = pair[1];
    if (use_gate_fd(&pair[0], sender)) return 1;
    close(pair[0]);
    close(*sender);
    return 0;
}

static int enable_creds(void) {
    int yes = 1;
    return setsockopt(SOCKET_FD, SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)) == 0 &&
        setsockopt(SOCKET_FD, SOL_SOCKET, SO_PASSPIDFD, &yes, sizeof(yes)) == 0;
}

static int own_cgroup(char *path, size_t capacity) {
    FILE *file = fopen("/proc/self/cgroup", "r");
    if (!file) return 0;
    char line[4096];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "0::", 3) != 0) continue;
        char *end = strchr(line + 3, '\n');
        if (end) *end = '\0';
        if (strlen(line + 3) + 1 > capacity) break;
        strcpy(path, line + 3);
        found = 1;
        break;
    }
    fclose(file);
    return found;
}

static int test_listener(void) {
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!check(listener >= 0, "create listener")) return 0;
    int dummy = -1;
    if (!check(use_gate_fd(&listener, &dummy), "move listener to fd 3")) return 0;

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    const char *name = "sgw-message-gate-native-test";
    memcpy(address.sun_path + 1, name, strlen(name));
    socklen_t size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name));
    if (!check(bind(SOCKET_FD, (struct sockaddr *)&address, size) == 0 &&
            listen(SOCKET_FD, 1) == 0, "listen")) return 0;
    if (!check(prepare_listener() != 0, "listener without PassCredentials rejected")) return 0;
    int yes = 1;
    if (!check(setsockopt(SOCKET_FD, SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)) == 0 &&
            prepare_listener() == 0 && socket_flag(SOCKET_FD, SO_PASSPIDFD),
            "listener preparation")) return 0;
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!check(client >= 0 && connect(client, (struct sockaddr *)&address, size) == 0,
            "connect prepared listener")) return 0;
    int accepted = accept4(SOCKET_FD, NULL, NULL, SOCK_CLOEXEC);
    if (!check(accepted >= 0 && socket_flag(accepted, SO_PASSCRED) &&
            socket_flag(accepted, SO_PASSPIDFD), "accepted socket inherits message options")) return 0;
    close(accepted);
    close(client);
    close(SOCKET_FD);
    return 1;
}

static int test_read(const char *cgroup, uid_t uid, gid_t gid, int options_before_send,
    int expected, const char *name) {
    int sender = -1;
    if (!check(stream_pair(&sender), name)) return 0;
    if (options_before_send && !check(enable_creds(), "enable per-message credentials")) return 0;
    if (!check(send(sender, "ok", 2, MSG_NOSIGNAL) == 2, "send probe")) return 0;
    if (!options_before_send && !check(enable_creds(), "enable after queued probe")) return 0;
    struct pending bytes = { 0 };
    int result = verified_read(&bytes, uid, gid, cgroup);
    int good = result == expected && (expected != 1 ||
        (bytes.used == 2 && memcmp(bytes.bytes, "ok", 2) == 0));
    close(sender);
    close(SOCKET_FD);
    return check(good, name);
}

static int test_rights(const char *cgroup) {
    int sender = -1;
    if (!check(stream_pair(&sender) && enable_creds(), "rights socket")) return 0;
    int source = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (!check(source >= 0, "rights source")) return 0;
    union { struct cmsghdr aligned; char bytes[CMSG_SPACE(sizeof(int))]; } control = { 0 };
    char byte = 'x';
    struct iovec data = { .iov_base = &byte, .iov_len = 1 };
    struct msghdr message = { .msg_iov = &data, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes) };
    struct cmsghdr *item = CMSG_FIRSTHDR(&message);
    item->cmsg_level = SOL_SOCKET;
    item->cmsg_type = SCM_RIGHTS;
    item->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(item), &source, sizeof(source));
    if (!check(sendmsg(sender, &message, MSG_NOSIGNAL) == 1, "send rights")) return 0;
    struct pending bytes = { 0 };
    int rejected = verified_read(&bytes, getuid(), getgid(), cgroup) == -1;
    close(source);
    close(sender);
    close(SOCKET_FD);
    return check(rejected, "SCM_RIGHTS rejected");
}

int main(void) {
    char cgroup[4096];
    if (!check(own_cgroup(cgroup, sizeof(cgroup)), "read own cgroup")) return 1;
    if (!test_listener()) return 1;
    if (!test_read(cgroup, getuid(), getgid(), 1, 1, "own bytes accepted")) return 1;
    if (!test_read(cgroup, (uid_t)(getuid() + 1), getgid(), 1, -1, "wrong UID rejected")) return 1;
    if (!test_read("/not-the-sender-cgroup", getuid(), getgid(), 1, -1,
            "wrong cgroup rejected")) return 1;
    if (!test_read(cgroup, getuid(), getgid(), 0, -1, "prequeued bytes rejected")) return 1;
    if (!test_rights(cgroup)) return 1;
    puts("Linux message gate native checks passed.");
    return 0;
}
