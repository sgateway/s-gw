#if !defined(__APPLE__)
#error This runner is for macOS only.
#endif

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stddef.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/acl.h>
#include <time.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>

#define CONTROL_SOCKET "/private/var/db/s-gw/agent-launch-control.sock"
#define POLICY_SOCKET "/private/var/db/s-gw/agent-network-policy.sock"
#define UID_LEASE_DIR "/private/var/db/s-gw/agent-uid-leases"
#define UID_SCAN_LIMIT 8192
#define POLICY_CHECK_INTERVAL_MS 1000
#define POLICY_REPLY_DEADLINE_MS 1500

static volatile sig_atomic_t stopping = 0;

static void on_signal(int signal_number) {
    (void)signal_number;
    stopping = 1;
}

static int fail(const char *reason) {
    fprintf(stderr, "s-gw agent UID runner: %s\n", reason);
    return 1;
}

static int parse_id(const char *text, unsigned long *result) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !text[0] || *end || value == 0 || value > UINT_MAX) return -1;
    *result = value;
    return 0;
}

static int valid_session(const char *value) {
    size_t len = strlen(value);
    if (!len || len > 64) return 0;
    for (size_t i = 0; i < len; i++) {
        char ch = value[i];
        if ((ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') &&
            (ch < '0' || ch > '9') && ch != '-' && ch != '_') return 0;
    }
    return 1;
}

static int socket_peer(int fd, const char *expected_path, int local, uid_t *peer_uid) {
    int socket_type = 0;
    socklen_t type_len = sizeof(socket_type);
    struct sockaddr_un address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &type_len) || socket_type != SOCK_STREAM) return -1;
    if (local) {
        if (getsockname(fd, (struct sockaddr *)&address, &address_len)) return -1;
    } else if (getpeername(fd, (struct sockaddr *)&address, &address_len)) return -1;
    if (address.sun_family != AF_UNIX ||
        address_len <= offsetof(struct sockaddr_un, sun_path) ||
        strnlen(address.sun_path, sizeof(address.sun_path)) >= sizeof(address.sun_path) ||
        strcmp(address.sun_path, expected_path)) return -1;
    gid_t peer_gid;
    return getpeereid(fd, peer_uid, &peer_gid);
}

static int canonical_path(const char *location) {
    char resolved[PATH_MAX];
    if (location[0] != '/' || !realpath(location, resolved)) return -1;
    return strcmp(location, resolved) == 0 ? 0 : -1;
}

static int no_acl_allow(const char *location) {
    errno = 0;
    acl_t acl = acl_get_file(location, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT ? 0 : -1;
    acl_entry_t entry;
    int next = ACL_FIRST_ENTRY;
    int safe = 0;
    for (;;) {
        errno = 0;
        if (acl_get_entry(acl, next, &entry)) {
            if (errno != EINVAL) safe = -1;
            break;
        }
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) || tag != ACL_EXTENDED_DENY) {
            safe = -1;
            break;
        }
        next = ACL_NEXT_ENTRY;
    }
    acl_free(acl);
    return safe;
}

static int trusted_parents(const char *location, uid_t allowed_owner) {
    char current[PATH_MAX];
    if (strlen(location) >= sizeof(current)) return -1;
    strcpy(current, location);
    for (;;) {
        char *slash = strrchr(current, '/');
        if (!slash) return -1;
        if (slash == current) current[1] = '\0';
        else *slash = '\0';
        struct stat info;
        if (lstat(current, &info) || !S_ISDIR(info.st_mode) || no_acl_allow(current) ||
            (info.st_uid != 0 && info.st_uid != allowed_owner) || (info.st_mode & 022)) return -1;
        if (!strcmp(current, "/")) return 0;
    }
}

static int trusted_socket_node(const char *location, uid_t owner, uid_t parent_owner) {
    struct stat info;
    if (canonical_path(location) || lstat(location, &info) || !S_ISSOCK(info.st_mode) ||
        info.st_uid != owner || (info.st_mode & 0777) != 0600 ||
        no_acl_allow(location) || trusted_parents(location, parent_owner)) return -1;
    return 0;
}

static int reserve_uid(uid_t uid, const char *session) {
    struct stat info;
    if (canonical_path(UID_LEASE_DIR) || lstat(UID_LEASE_DIR, &info) ||
        !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0777) != 0700 ||
        no_acl_allow(UID_LEASE_DIR) ||
        trusted_parents(UID_LEASE_DIR, 0)) return -1;
    char location[PATH_MAX], record[128];
    int path_len = snprintf(location, sizeof(location), "%s/%u", UID_LEASE_DIR, uid);
    int record_len = snprintf(record, sizeof(record), "%u %s\n", uid, session);
    if (path_len < 1 || path_len >= (int)sizeof(location) ||
        record_len < 1 || record_len >= (int)sizeof(record)) return -1;
    int fd = open(location, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int written = write(fd, record, (size_t)record_len) == record_len && fsync(fd) == 0;
    close(fd);
    if (!written) return -1;
    int dir = open(UID_LEASE_DIR, O_RDONLY | O_DIRECTORY);
    if (dir < 0) return -1;
    int synced = fsync(dir) == 0;
    close(dir);
    return synced ? 0 : -1;
}

static int check_uid_lease(uid_t uid, const char *session) {
    struct stat info;
    if (canonical_path(UID_LEASE_DIR) || lstat(UID_LEASE_DIR, &info) ||
        !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0777) != 0700 ||
        no_acl_allow(UID_LEASE_DIR) ||
        trusted_parents(UID_LEASE_DIR, 0)) return -1;
    int dir = open(UID_LEASE_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (dir < 0) return -1;
    char name[32], expected[128], contents[128];
    int name_len = snprintf(name, sizeof(name), "%u", uid);
    int expected_len = snprintf(expected, sizeof(expected), "%u %s\n", uid, session);
    if (name_len < 1 || name_len >= (int)sizeof(name) ||
        expected_len < 1 || expected_len >= (int)sizeof(expected)) { close(dir); return -1; }
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW);
    close(dir);
    if (fd < 0) return -1;
    ssize_t amount = read(fd, contents, sizeof(contents));
    int safe = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == 0 &&
        (info.st_mode & 0777) == 0600 && amount == expected_len &&
        memcmp(contents, expected, (size_t)expected_len) == 0;
    close(fd);
    return safe ? 0 : -1;
}

struct uid_process {
    pid_t pid;
    uint64_t start_sec;
    uint64_t start_usec;
};

static int process_under_uid(const struct proc_bsdinfo *info, uid_t uid) {
    return info->pbi_uid == uid || info->pbi_ruid == uid || info->pbi_svuid == uid;
}

static int read_process(pid_t pid, uid_t uid, struct uid_process *found) {
    struct proc_bsdinfo info;
    errno = 0;
    int amount = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (amount != sizeof(info)) {
        if (kill(pid, 0) < 0 && errno == ESRCH) return 0;
        return -1;
    }
    if (info.pbi_pid != (uint32_t)pid) return -1;
    if (!process_under_uid(&info, uid)) return 0;
    found->pid = pid;
    found->start_sec = info.pbi_start_tvsec;
    found->start_usec = info.pbi_start_tvusec;
    return 1;
}

static int list_uid_processes(uid_t uid, pid_t ignored, struct uid_process *found, size_t *count) {
    pid_t pids[UID_SCAN_LIMIT];
    *count = 0;
    // The UID filters omit processes that retain only the agent's saved UID.
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    if (bytes <= 0 || bytes >= (int)sizeof(pids) || bytes % sizeof(pid_t)) return -1;
    for (int i = 0; i < bytes / (int)sizeof(pid_t); i++) {
        pid_t pid = pids[i];
        if (pid <= 0 || pid == ignored) continue;
        struct uid_process current;
        int match = read_process(pid, uid, &current);
        if (match < 0) return -1;
        if (match == 1) {
            if (*count == UID_SCAN_LIMIT) return -1;
            found[(*count)++] = current;
        }
    }
    return 0;
}

static int signal_uid_process(const struct uid_process *target, uid_t uid, int signal_number) {
    struct uid_process current;
    int match = read_process(target->pid, uid, &current);
    if (match < 0) return -1;
    if (match == 0 || current.start_sec != target->start_sec ||
        current.start_usec != target->start_usec) return 0;
    if (kill(target->pid, signal_number) < 0 && errno != ESRCH) return -1;
    return 0;
}

static int teardown_uid(uid_t uid, pid_t ignored) {
    struct uid_process *found = calloc(UID_SCAN_LIMIT, sizeof(*found));
    if (!found) return -1;
    int clean = 0;
    for (int attempt = 0; attempt < 40; attempt++) {
        size_t count = 0;
        if (list_uid_processes(uid, ignored, found, &count)) break;
        if (!count) {
            if (++clean == 2) { free(found); return 0; }
        } else {
            clean = 0;
            for (size_t i = 0; i < count; i++) {
                if (signal_uid_process(&found[i], uid, attempt < 5 ? SIGTERM : SIGKILL)) {
                    free(found);
                    return -1;
                }
            }
        }
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 100000000 };
        nanosleep(&pause, NULL);
    }
    free(found);
    return -1;
}

static int uid_is_empty(uid_t uid) {
    struct uid_process *found = calloc(UID_SCAN_LIMIT, sizeof(*found));
    if (!found) return -1;
    size_t count = 0;
    int result = list_uid_processes(uid, 0, found, &count);
    free(found);
    return result == 0 && count == 0 ? 0 : -1;
}

static int close_inherited_fds(void) {
    int needed = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, NULL, 0);
    if (needed <= 0 || needed > 8 * 1024 * 1024) return -1;
    size_t capacity = (size_t)needed + 1024 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *fds = malloc(capacity);
    if (!fds) return -1;
    int amount = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, (int)capacity);
    if (amount <= 0 || (size_t)amount >= capacity || amount % sizeof(struct proc_fdinfo)) {
        free(fds);
        return -1;
    }
    for (int i = 0; i < amount / (int)sizeof(struct proc_fdinfo); i++) {
        if (fds[i].proc_fd >= 3 && close(fds[i].proc_fd)) {
            free(fds);
            return -1;
        }
    }
    free(fds);
    return 0;
}

static int checked_workspace(const char *location, uid_t agent_uid) {
    struct stat info;
    if (canonical_path(location) || lstat(location, &info) || !S_ISDIR(info.st_mode) ||
        info.st_uid != agent_uid || (info.st_mode & 0777) != 0700 || no_acl_allow(location) ||
        trusted_parents(location, 0)) return -1;
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s/tmp", location) >= (int)sizeof(tmp)) return -1;
    if (lstat(tmp, &info) || !S_ISDIR(info.st_mode) || info.st_uid != agent_uid ||
        (info.st_mode & 0777) != 0700 || no_acl_allow(tmp)) return -1;
    return 0;
}

static int checked_executable(const char *location, uid_t broker_uid) {
    struct stat info;
    if (canonical_path(location) || lstat(location, &info) || !S_ISREG(info.st_mode) ||
        (info.st_uid != 0 && info.st_uid != broker_uid) || (info.st_mode & 022) ||
        (info.st_mode & (S_ISUID | S_ISGID)) || !(info.st_mode & 0111) ||
        no_acl_allow(location) ||
        trusted_parents(location, broker_uid)) return -1;
    return 0;
}

static int checked_broker_socket(const char *location, uid_t broker_uid, gid_t agent_gid) {
    struct stat info;
    if (canonical_path(location) || lstat(location, &info) || !S_ISSOCK(info.st_mode) ||
        info.st_uid != broker_uid || info.st_gid != agent_gid ||
        (info.st_mode & 0777) != 0660 || no_acl_allow(location) ||
        trusted_parents(location, broker_uid)) return -1;
    return 0;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int policy_exchange(int fd, uid_t uid, const char *session) {
    char request[128];
    int length = snprintf(request, sizeof(request), "CHECK-V1 %u %s\n", uid, session);
    char expected[128];
    int expected_len = snprintf(expected, sizeof(expected), "READY-V1 %u %s\n", uid, session);
    if (length < 1 || length >= (int)sizeof(request) ||
        expected_len < 1 || expected_len >= (int)sizeof(expected)) return -1;
    int enabled = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) ||
        send(fd, request, (size_t)length, MSG_DONTWAIT) != length) return -1;
    int64_t deadline = monotonic_ms();
    if (deadline < 0) return -1;
    deadline += POLICY_REPLY_DEADLINE_MS;
    size_t used = 0;
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0 || now >= deadline) return -1;
        struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
        int ready = poll(&poll_fd, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready != 1 || (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            !(poll_fd.revents & POLLIN)) return -1;
        char response[128];
        ssize_t received = recv(fd, response, sizeof(response), MSG_DONTWAIT);
        if (received <= 0 || used + (size_t)received > (size_t)expected_len ||
            memcmp(response, expected + used, (size_t)received)) return -1;
        used += (size_t)received;
        if (used == (size_t)expected_len) return 0;
    }
}

static int policy_ready(uid_t uid, const char *session) {
    uid_t policy_uid;
    if (socket_peer(4, POLICY_SOCKET, 0, &policy_uid) || policy_uid != 0 ||
        trusted_socket_node(POLICY_SOCKET, 0, 0)) return -1;
    return policy_exchange(4, uid, session);
}

static int policy_heartbeat(int fd, uid_t uid, const char *session, int64_t *next_check) {
    struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
    int ready = poll(&poll_fd, 1, 0);
    if (ready < 0 || (ready == 1 && poll_fd.revents)) return -1;
    int64_t now = monotonic_ms();
    if (now < 0) return -1;
    if (now < *next_check) return 0;
    if (policy_exchange(fd, uid, session)) return -1;
    now = monotonic_ms();
    if (now < 0) return -1;
    *next_check = now + POLICY_CHECK_INTERVAL_MS;
    return 0;
}

static void child_exec(uid_t uid, gid_t gid, const char *session, const char *workspace, const char *broker_socket,
                       const char *exe, char **args) {
    if (setpgid(0, 0) || setgroups(0, NULL) || setgid(gid) || setuid(uid) ||
        getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid ||
        chdir(workspace)) _exit(126);
    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un broker;
    memset(&broker, 0, sizeof(broker));
    broker.sun_family = AF_UNIX;
    if (probe < 0 || strlen(broker_socket) >= sizeof(broker.sun_path)) _exit(126);
    strcpy(broker.sun_path, broker_socket);
    if (connect(probe, (struct sockaddr *)&broker, sizeof(broker))) _exit(126);
    char request[128], expected[128], response[128];
    int length = snprintf(request, sizeof(request), "HELLO-V1 %u %s\n", uid, session);
    if (length < 1 || length >= (int)sizeof(request) || write(probe, request, (size_t)length) != length ||
        shutdown(probe, SHUT_WR)) _exit(126);
    struct pollfd poll_fd = { .fd = probe, .events = POLLIN };
    if (poll(&poll_fd, 1, 1500) != 1 || !(poll_fd.revents & POLLIN)) _exit(126);
    ssize_t received = read(probe, response, sizeof(response) - 1);
    if (received < 1) _exit(126);
    response[received] = '\0';
    snprintf(expected, sizeof(expected), "READY-V1 %u %s\n", uid, session);
    if (strcmp(response, expected)) _exit(126);
    close(probe);
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0 || dup2(null_fd, 0) < 0 || dup2(null_fd, 1) < 0 || dup2(null_fd, 2) < 0) _exit(126);
    if (close_inherited_fds()) _exit(126);
    umask(077);
    char home[PATH_MAX + 6], tmp[PATH_MAX + 10], socket_env[PATH_MAX + 18];
    if (snprintf(home, sizeof(home), "HOME=%s", workspace) >= (int)sizeof(home) ||
        snprintf(tmp, sizeof(tmp), "TMPDIR=%s/tmp", workspace) >= (int)sizeof(tmp) ||
        snprintf(socket_env, sizeof(socket_env), "SGW_AGENT_SOCKET=%s", broker_socket) >= (int)sizeof(socket_env)) _exit(126);
    char *environment[] = { home, tmp, socket_env, "PATH=/usr/bin:/bin", NULL };
    execve(exe, args, environment);
    _exit(126);
}

int main(int argc, char **argv) {
    if (getuid() != 0 || geteuid() != 0) return fail("requires a root-owned service, never a setuid executable");
    if (argc == 4 && !strcmp(argv[1], "--teardown")) {
        unsigned long raw_uid;
        uid_t broker_uid;
        if (parse_id(argv[2], &raw_uid) || !valid_session(argv[3]) ||
            socket_peer(3, CONTROL_SOCKET, 1, &broker_uid) || broker_uid == 0 ||
            trusted_socket_node(CONTROL_SOCKET, broker_uid, 0))
            return fail("untrusted teardown request");
        uid_t uid = (uid_t)raw_uid;
        struct passwd *account = getpwuid(uid);
        if (!account || strncmp(account->pw_name, "_sgwagent_", 10) || uid == broker_uid ||
            check_uid_lease(uid, argv[3])) return fail("UID is not leased to this agent session");
        if (teardown_uid(uid, 0)) return fail("agent UID teardown is incomplete; tombstone remains");
        return 0;
    }
    if (argc < 8 || strcmp(argv[7], "--")) return fail("invalid launch plan");
    unsigned long raw_uid, raw_gid;
    if (parse_id(argv[1], &raw_uid) || parse_id(argv[2], &raw_gid) || !valid_session(argv[3]))
        return fail("invalid agent identity or session");
    uid_t agent_uid = (uid_t)raw_uid;
    gid_t agent_gid = (gid_t)raw_gid;
    uid_t broker_uid;
    if (socket_peer(3, CONTROL_SOCKET, 1, &broker_uid) || broker_uid == 0 ||
        trusted_socket_node(CONTROL_SOCKET, broker_uid, 0) || agent_uid == broker_uid)
        return fail("untrusted broker control connection");
    struct passwd *account = getpwuid(agent_uid);
    if (!account || strncmp(account->pw_name, "_sgwagent_", 10) || account->pw_gid != agent_gid)
        return fail("agent account was not provisioned for s-gw");
    if (uid_is_empty(agent_uid))
        return fail("agent UID already has a process");
    if (checked_workspace(argv[4], agent_uid) || checked_broker_socket(argv[5], broker_uid, agent_gid) ||
        checked_executable(argv[6], broker_uid)) return fail("unsafe workspace, broker socket, or executable");
    if (policy_ready(agent_uid, argv[3])) return fail("network policy service did not attest this session");
    int64_t next_policy_check = monotonic_ms();
    if (next_policy_check < 0) return fail("could not schedule network policy checks");
    next_policy_check += POLICY_CHECK_INTERVAL_MS;
    if (reserve_uid(agent_uid, argv[3])) return fail("agent UID is already leased or lease storage is unavailable");
    if (uid_is_empty(agent_uid)) return fail("agent UID became active before launch; tombstone remains");

    char **agent_args = calloc((size_t)argc - 6, sizeof(char *));
    if (!agent_args) return fail("could not allocate agent arguments");
    agent_args[0] = argv[6];
    for (int i = 8; i < argc; i++) agent_args[i - 7] = argv[i];
    sigset_t launch_signals, previous_mask;
    sigemptyset(&launch_signals);
    sigaddset(&launch_signals, SIGTERM);
    sigaddset(&launch_signals, SIGINT);
    sigaddset(&launch_signals, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &launch_signals, &previous_mask) ||
        signal(SIGTERM, on_signal) == SIG_ERR ||
        signal(SIGINT, on_signal) == SIG_ERR ||
        signal(SIGHUP, on_signal) == SIG_ERR) {
        free(agent_args);
        return fail("could not guard agent launch signals");
    }
    pid_t child = fork();
    if (child < 0) {
        sigprocmask(SIG_SETMASK, &previous_mask, NULL);
        free(agent_args);
        return fail("could not fork agent");
    }
    if (child == 0) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        if (sigprocmask(SIG_SETMASK, &previous_mask, NULL)) _exit(126);
        child_exec(agent_uid, agent_gid, argv[3], argv[4], argv[5], argv[6], agent_args);
    }
    if (sigprocmask(SIG_SETMASK, &previous_mask, NULL)) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        free(agent_args);
        if (teardown_uid(agent_uid, 0)) return fail("agent UID teardown is incomplete; tombstone remains");
        return fail("could not resume agent supervision");
    }
    int sent_term = 0;
    int wait_error = 0;
    int policy_error = 0;
    time_t term_at = 0;
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    for (;;) {
        errno = 0;
        int wait_result = waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT | WNOHANG);
        if (wait_result == 0 && info.si_pid == child) break;
        if (wait_result < 0 && errno != EINTR) { wait_error = 1; break; }
        if (!stopping && policy_heartbeat(4, agent_uid, argv[3], &next_policy_check)) {
            policy_error = 1;
            stopping = 1;
            kill(-child, SIGKILL);
            kill(child, SIGKILL);
        }
        if (stopping && !sent_term) { kill(-child, SIGTERM); kill(child, SIGTERM); sent_term = 1; term_at = time(NULL); }
        if (sent_term && time(NULL) - term_at >= 2) { kill(-child, SIGKILL); kill(child, SIGKILL); }
        struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
        nanosleep(&pause, NULL);
    }
    // Keep the direct child unreaped until the group is gone, so its PGID cannot be reused.
    kill(-child, SIGTERM);
    struct timespec grace = { .tv_sec = 0, .tv_nsec = 100000000 };
    nanosleep(&grace, NULL);
    kill(-child, SIGKILL);
    int teardown_error = teardown_uid(agent_uid, child);
    int status = 0;
    pid_t reaped;
    do { reaped = waitpid(child, &status, 0); }
    while (reaped < 0 && errno == EINTR);
    free(agent_args);
    if (teardown_error || teardown_uid(agent_uid, 0))
        return fail("agent UID teardown is incomplete; tombstone remains");
    if (reaped != child || wait_error) return fail("could not supervise agent exit");
    if (policy_error) return fail("network policy service stopped attesting the agent session");
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : SIGTERM);
}
