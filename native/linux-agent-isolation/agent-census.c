#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/magic.h>
#include <poll.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#endif

#ifndef SGW_CENSUS_MAX_ENTRIES
#define SGW_CENSUS_MAX_ENTRIES 4096
#endif
#ifndef SGW_CENSUS_MAX_PROC_PIDS
#define SGW_CENSUS_MAX_PROC_PIDS 65536
#endif
#ifndef SGW_CENSUS_MAX_PROC_TIDS
#define SGW_CENSUS_MAX_PROC_TIDS 65536
#endif

#define MAX_MOUNTS 64
#define MAX_LINE 8192
#define MAX_STATUS 32768
#define MAX_DEPTH 32
#define MAX_ROOT_PATH 2048

static int decimal(const char *value, unsigned long long *number) {
    if (!value || !*value) return 0;
    for (const char *p = value; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long result = strtoull(value, &end, 10);
    if (errno || !end || *end) return 0;
    *number = result;
    return 1;
}

static int clean_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    size_t length = strnlen(path, MAX_ROOT_PATH + 1);
    if (length == 0 || length > MAX_ROOT_PATH) return 0;
    if (length > 1 && path[length - 1] == '/') return 0;
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t size = end ? (size_t)(end - part) : strlen(part);
        if (size == 0 || (size == 1 && part[0] == '.') ||
            (size == 2 && part[0] == '.' && part[1] == '.')) return 0;
        if (!end) break;
        part = end + 1;
    }
    return 1;
}

static int decode_mount_path(const char *input, char *output, size_t capacity) {
    size_t used = 0;
    for (size_t i = 0; input[i]; i++) {
        unsigned char value = (unsigned char)input[i];
        if (value == '\\') {
            if (!input[i + 1] || !input[i + 2] || !input[i + 3]) return 0;
            value = 0;
            for (size_t digit = 1; digit <= 3; digit++) {
                char c = input[i + digit];
                if (c < '0' || c > '7') return 0;
                value = (unsigned char)((value << 3) | (c - '0'));
            }
            if (!value) return 0;
            i += 3;
        }
        if (used + 1 >= capacity) return 0;
        output[used++] = (char)value;
    }
    output[used] = '\0';
    return clean_path(output);
}

static int mount_line_ok(const char *line, const char **allowed, size_t count,
                         unsigned char *seen) {
    if (!line || strnlen(line, MAX_LINE + 1) > MAX_LINE) return 0;
    char copy[MAX_LINE + 1];
    strcpy(copy, line);
    char *tokens[128];
    size_t n = 0;
    char *save = NULL;
    for (char *part = strtok_r(copy, " \t\r\n", &save); part;
         part = strtok_r(NULL, " \t\r\n", &save)) {
        if (n == sizeof(tokens) / sizeof(tokens[0])) return 0;
        tokens[n++] = part;
    }
    if (n < 10) return 0;
    unsigned long long number;
    if (!decimal(tokens[0], &number) || !decimal(tokens[1], &number) ||
        tokens[3][0] != '/' || !strchr(tokens[2], ':')) return 0;

    size_t separator = 6;
    while (separator < n && strcmp(tokens[separator], "-") != 0) separator++;
    if (separator >= n || separator + 4 != n) return 0;
    for (size_t i = 6; i < separator; i++) {
        if (strcmp(tokens[i], "unbindable") != 0) return 0;
    }
    if (!*tokens[5] || !*tokens[separator + 1] ||
        !*tokens[separator + 2] || !*tokens[separator + 3]) return 0;

    char mountpoint[MAX_ROOT_PATH + 1];
    if (!decode_mount_path(tokens[4], mountpoint, sizeof(mountpoint))) return 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(mountpoint, allowed[i]) != 0) continue;
        if (seen[i]) return 0;
        seen[i] = 1;
        return 1;
    }
    return 0;
}

static int proc_stat_starttime(const char *text, unsigned long long *starttime) {
    if (!text || strnlen(text, MAX_LINE + 1) > MAX_LINE) return 0;
    const char *open_paren = strchr(text, '(');
    const char *close_paren = strrchr(text, ')');
    if (!open_paren || !close_paren || close_paren <= open_paren ||
        open_paren < text + 2 || open_paren[-1] != ' ' || close_paren[1] != ' ') return 0;
    char pid_text[32];
    size_t pid_len = (size_t)(open_paren - text - 1);
    if (pid_len >= sizeof(pid_text)) return 0;
    memcpy(pid_text, text, pid_len);
    pid_text[pid_len] = '\0';
    unsigned long long pid_number;
    if (!decimal(pid_text, &pid_number) || pid_number == 0) return 0;

    char fields[MAX_LINE + 1];
    strcpy(fields, close_paren + 2);
    char *save = NULL;
    size_t field = 3;
    for (char *part = strtok_r(fields, " \t\r\n", &save); part;
         part = strtok_r(NULL, " \t\r\n", &save), field++) {
        if (field == 3 && (strlen(part) != 1 || strchr("ZXx", part[0]))) return 0;
        if (field == 22) return decimal(part, starttime) && *starttime != 0;
    }
    return 0;
}

static int parse_status_uids(const char *text, unsigned long long uids[4]) {
    if (!text || strnlen(text, MAX_STATUS + 1) > MAX_STATUS) return 0;
    int found = 0;
    const char *line = text;
    while (*line) {
        const char *end = strchr(line, '\n');
        if (!end) return 0;
        if ((size_t)(end - line) >= 4 && memcmp(line, "Uid:", 4) == 0) {
            if (found || (size_t)(end - line) >= 128) return 0;
            char copy[128];
            size_t length = (size_t)(end - line);
            memcpy(copy, line, length);
            copy[length] = '\0';
            char *save = NULL;
            char *part = strtok_r(copy, " \t", &save);
            if (!part || strcmp(part, "Uid:") != 0) return 0;
            for (size_t i = 0; i < 4; i++) {
                part = strtok_r(NULL, " \t", &save);
                if (!decimal(part, &uids[i]) || uids[i] > UINT_MAX) return 0;
            }
            if (strtok_r(NULL, " \t", &save)) return 0;
            found = 1;
        }
        line = end + 1;
    }
    return found;
}

static int uids_all(const unsigned long long uids[4], unsigned long long expected) {
    for (size_t i = 0; i < 4; i++) if (uids[i] != expected) return 0;
    return 1;
}

static int uids_any(const unsigned long long uids[4], unsigned long long expected) {
    for (size_t i = 0; i < 4; i++) if (uids[i] == expected) return 1;
    return 0;
}

static int scan_dir(int dirfd, const char *relative, unsigned depth,
                    dev_t null_rdev, size_t *entries, int trusted_owner) {
    if (depth > MAX_DEPTH) return 0;
    struct stat current;
    if (fstat(dirfd, &current) != 0 || !S_ISDIR(current.st_mode)) return 0;
    if (trusted_owner && (current.st_uid != 0 || (current.st_mode & 022) != 0)) return 0;

    int duplicate = dup(dirfd);
    if (duplicate < 0) return 0;
    DIR *stream = fdopendir(duplicate);
    if (!stream) {
        close(duplicate);
        return 0;
    }
    int okay = 1;
    for (;;) {
        errno = 0;
        struct dirent *item = readdir(stream);
        if (!item) {
            if (errno) okay = 0;
            break;
        }
        if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0) continue;
        if (++*entries > SGW_CENSUS_MAX_ENTRIES) { okay = 0; break; }

        char name[MAX_ROOT_PATH + 1];
        int length = snprintf(name, sizeof(name), "%s%s%s", relative,
                              *relative ? "/" : "", item->d_name);
        if (length < 0 || (size_t)length >= sizeof(name)) { okay = 0; break; }
        struct stat info;
        if (fstatat(dirfd, item->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
            okay = 0;
            break;
        }
        if (trusted_owner && S_ISDIR(info.st_mode) &&
            (info.st_uid != 0 || (info.st_mode & 022) != 0)) {
            okay = 0;
            break;
        }
        if (S_ISREG(info.st_mode)) continue;
        if (S_ISCHR(info.st_mode) && strcmp(name, "dev/null") == 0 &&
            info.st_rdev == null_rdev) continue;
        if (!S_ISDIR(info.st_mode)) { okay = 0; break; }

        int child = openat(dirfd, item->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child < 0) { okay = 0; break; }
        struct stat opened;
        if (fstat(child, &opened) != 0 || opened.st_dev != info.st_dev ||
            opened.st_ino != info.st_ino || !scan_dir(child, name, depth + 1,
                                                     null_rdev, entries, trusted_owner)) okay = 0;
        close(child);
        if (!okay) break;
    }
    if (closedir(stream) != 0) okay = 0;
    return okay;
}

static int scan_tree(int root_fd, dev_t null_rdev, size_t *entries, int trusted_owner) {
    return scan_dir(root_fd, "", 0, null_rdev, entries, trusted_owner);
}

static int read_small_at(int dirfd, const char *name, char *result, size_t capacity,
                         int root_owned) {
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    if (root_owned) {
        struct stat info;
        if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
            info.st_uid != 0 || (info.st_mode & 022) != 0) {
            close(fd);
            return 0;
        }
    }
    size_t used = 0;
    int okay = 1;
    int saved_errno = 0;
    for (;;) {
        if (used + 1 >= capacity) { okay = 0; saved_errno = EOVERFLOW; break; }
        ssize_t amount = read(fd, result + used, capacity - used - 1);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { okay = 0; saved_errno = errno; break; }
        if (amount == 0) break;
        used += (size_t)amount;
    }
    if (close(fd) != 0) { okay = 0; saved_errno = errno; }
    if (!okay || used == 0) {
        errno = saved_errno ? saved_errno : EIO;
        return 0;
    }
    result[used] = '\0';
    return 1;
}

static int scan_task_uids_at(int pid_dir, unsigned long long expected, size_t *scanned) {
    int task_fd = openat(pid_dir, "task", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (task_fd < 0) return 0;
    DIR *tasks = fdopendir(task_fd);
    if (!tasks) { close(task_fd); return 0; }
    int okay = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(tasks);
        if (!entry) { if (errno) okay = 0; break; }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        unsigned long long tid;
        if (!decimal(entry->d_name, &tid) || tid == 0 || tid > INT_MAX ||
            ++*scanned > SGW_CENSUS_MAX_PROC_TIDS) { okay = 0; break; }
        int thread_dir = openat(dirfd(tasks), entry->d_name,
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (thread_dir < 0) {
            if (errno == ENOENT || errno == ESRCH) continue;
            okay = 0;
            break;
        }
        char status[MAX_STATUS + 1];
        int read_ok = read_small_at(thread_dir, "status", status, sizeof(status), 0);
        int read_errno = errno;
        if (close(thread_dir) != 0) { okay = 0; break; }
        if (!read_ok && (read_errno == ENOENT || read_errno == ESRCH)) continue;
        unsigned long long uids[4];
        if (!read_ok || !parse_status_uids(status, uids) || uids_any(uids, expected)) {
            okay = 0;
            break;
        }
    }
    if (closedir(tasks) != 0) okay = 0;
    return okay;
}

static int scan_other_uids_at(int procfd, pid_t target, unsigned long long expected) {
    int copy = dup(procfd);
    if (copy < 0) return 0;
    DIR *stream = fdopendir(copy);
    if (!stream) { close(copy); return 0; }
    size_t scanned = 0, scanned_tids = 0;
    int okay = 1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (!entry) { if (errno) okay = 0; break; }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        unsigned long long number;
        if (!decimal(entry->d_name, &number) || number == 0 || number > INT_MAX ||
            ++scanned > SGW_CENSUS_MAX_PROC_PIDS) { okay = 0; break; }
        if (number == (unsigned long long)target) continue;

        int pid_dir = openat(procfd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (pid_dir < 0) {
            if (errno == ENOENT || errno == ESRCH) continue;
            okay = 0;
            break;
        }
        char status[MAX_STATUS + 1];
        int read_ok = read_small_at(pid_dir, "status", status, sizeof(status), 0);
        int read_errno = errno;
        if (!read_ok && (read_errno == ENOENT || read_errno == ESRCH)) {
            if (close(pid_dir) != 0) okay = 0;
            if (!okay) break;
            continue;
        }
        unsigned long long uids[4];
        int clean = read_ok && parse_status_uids(status, uids) &&
            !uids_any(uids, expected) && scan_task_uids_at(pid_dir, expected, &scanned_tids);
        if (close(pid_dir) != 0 || !clean) {
            okay = 0;
            break;
        }
    }
    if (closedir(stream) != 0) okay = 0;
    return okay;
}

#ifdef __linux__
static int exact_number_file(int dirfd, const char *name, unsigned long long expected) {
    char content[128];
    if (!read_small_at(dirfd, name, content, sizeof(content), 1)) return 0;
    size_t length = strlen(content);
    if (length < 2 || content[length - 1] != '\n') return 0;
    content[length - 1] = '\0';
    unsigned long long actual;
    return decimal(content, &actual) && actual == expected;
}

static int keyed_number(int dirfd, const char *name, const char *key,
                        unsigned long long expected) {
    char content[2048];
    if (!read_small_at(dirfd, name, content, sizeof(content), 1)) return 0;
    int found = 0;
    char *save = NULL;
    for (char *line = strtok_r(content, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *space = strchr(line, ' ');
        if (!space) return 0;
        *space++ = '\0';
        if (strcmp(line, key) != 0) continue;
        unsigned long long actual;
        if (found || !decimal(space, &actual) || actual != expected) return 0;
        found = 1;
    }
    return found;
}

static int cgroup_ok(int group_fd, pid_t pid) {
    char type[64];
    return read_small_at(group_fd, "cgroup.type", type, sizeof(type), 1) &&
        strcmp(type, "domain\n") == 0 &&
        exact_number_file(group_fd, "cgroup.freeze", 1) &&
        keyed_number(group_fd, "cgroup.events", "frozen", 1) &&
        keyed_number(group_fd, "cgroup.events", "populated", 1) &&
        keyed_number(group_fd, "cgroup.stat", "nr_descendants", 0) &&
        keyed_number(group_fd, "cgroup.stat", "nr_dying_descendants", 0) &&
        exact_number_file(group_fd, "cgroup.procs", (unsigned long long)pid) &&
        exact_number_file(group_fd, "cgroup.threads", (unsigned long long)pid);
}

static int pidfd_live(int pidfd) {
    struct pollfd event = { .fd = pidfd, .events = POLLIN };
    int result = poll(&event, 1, 0);
    return result == 0 && event.revents == 0;
}

static int proc_identity(pid_t pid, unsigned long long *starttime) {
    char path[64], content[MAX_LINE + 1];
    int length = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    if (length < 0 || (size_t)length >= sizeof(path)) return 0;
    if (!read_small_at(AT_FDCWD, path, content, sizeof(content), 0)) return 0;
    return proc_stat_starttime(content, starttime);
}

static int proc_cgroup_ok(pid_t pid, const char *cgroup_path) {
    char filename[64], content[2048], expected[2048];
    int n = snprintf(filename, sizeof(filename), "/proc/%ld/cgroup", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(filename) ||
        !read_small_at(AT_FDCWD, filename, content, sizeof(content), 0)) return 0;
    n = snprintf(expected, sizeof(expected), "0::%s\n", cgroup_path + strlen("/sys/fs/cgroup"));
    return n > 0 && (size_t)n < sizeof(expected) && strcmp(content, expected) == 0;
}

static int target_uids_ok(pid_t pid, unsigned long long expected) {
    char filename[64], status[MAX_STATUS + 1];
    int n = snprintf(filename, sizeof(filename), "/proc/%ld/status", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(filename) ||
        !read_small_at(AT_FDCWD, filename, status, sizeof(status), 0)) return 0;
    unsigned long long uids[4];
    return parse_status_uids(status, uids) && uids_all(uids, expected);
}

static int other_uids_ok(pid_t pid, unsigned long long dedicated_uid) {
    int procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (procfd < 0) return 0;
    struct statfs fs;
    int okay = fstatfs(procfd, &fs) == 0 && fs.f_type == PROC_SUPER_MAGIC &&
        scan_other_uids_at(procfd, pid, dedicated_uid);
    if (close(procfd) != 0) okay = 0;
    return okay;
}

static int same_object(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static int trusted_dir_chain(const char *path) {
    char copy[MAX_ROOT_PATH + 1];
    strcpy(copy, path);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return 0;
    char *save = NULL;
    int okay = 1;
    for (char *part = strtok_r(copy + 1, "/", &save); part;
         part = strtok_r(NULL, "/", &save)) {
        int child = openat(fd, part, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        struct stat info;
        if (child < 0 || fstat(child, &info) != 0 || info.st_uid != 0 ||
            ((info.st_mode & 022) != 0 && (info.st_mode & S_ISVTX) == 0)) {
            if (child >= 0) close(child);
            okay = 0;
            break;
        }
        if (close(fd) != 0) {
            close(child);
            okay = 0;
            break;
        }
        fd = child;
    }
    if (close(fd) != 0) okay = 0;
    return okay;
}

static int namespace_and_root_ok(pid_t pid, const char *root_path) {
    char path[80];
    struct stat host_ns, agent_ns, host_user_ns, agent_user_ns;
    struct stat host_root, agent_root, agent_cwd, expected_root;
    if (stat("/proc/self/ns/mnt", &host_ns) != 0 ||
        stat("/proc/self/ns/user", &host_user_ns) != 0 ||
        stat("/", &host_root) != 0 || stat(root_path, &expected_root) != 0 ||
        !S_ISDIR(expected_root.st_mode) || same_object(&host_root, &expected_root)) return 0;
    int n = snprintf(path, sizeof(path), "/proc/%ld/ns/mnt", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path) || stat(path, &agent_ns) != 0 ||
        same_object(&host_ns, &agent_ns)) return 0;
    n = snprintf(path, sizeof(path), "/proc/%ld/ns/user", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path) || stat(path, &agent_user_ns) != 0 ||
        !same_object(&host_user_ns, &agent_user_ns)) return 0;
    n = snprintf(path, sizeof(path), "/proc/%ld/root", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path) || stat(path, &agent_root) != 0 ||
        !same_object(&agent_root, &expected_root)) return 0;
    n = snprintf(path, sizeof(path), "/proc/%ld/cwd", (long)pid);
    return n > 0 && (size_t)n < sizeof(path) && stat(path, &agent_cwd) == 0 &&
        same_object(&agent_cwd, &expected_root);
}

static int mountinfo_ok(pid_t pid, const char **mounts, size_t mount_count) {
    char path[80], line[MAX_LINE + 1];
    int n = snprintf(path, sizeof(path), "/proc/%ld/mountinfo", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    FILE *stream = fdopen(fd, "r");
    if (!stream) { close(fd); return 0; }
    unsigned char seen[MAX_MOUNTS] = { 0 };
    size_t lines = 0;
    int okay = 1;
    while (fgets(line, sizeof(line), stream)) {
        size_t length = strlen(line);
        if (++lines > MAX_MOUNTS || length == 0 || line[length - 1] != '\n' ||
            !mount_line_ok(line, mounts, mount_count, seen)) { okay = 0; break; }
    }
    if (ferror(stream)) okay = 0;
    if (fclose(stream) != 0) okay = 0;
    if (!okay || lines != mount_count) return 0;
    for (size_t i = 0; i < mount_count; i++) if (!seen[i]) return 0;
    return 1;
}

static int task_and_fd_ok(pid_t pid, dev_t null_rdev) {
    char path[128];
    int n = snprintf(path, sizeof(path), "/proc/%ld/task", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    DIR *tasks = opendir(path);
    if (!tasks) return 0;
    int task_count = 0, okay = 1;
    for (;;) {
        errno = 0;
        struct dirent *item = readdir(tasks);
        if (!item) { if (errno) okay = 0; break; }
        if (item->d_name[0] == '.') continue;
        unsigned long long tid;
        if (!decimal(item->d_name, &tid) || tid != (unsigned long long)pid || ++task_count != 1) {
            okay = 0;
            break;
        }
    }
    if (closedir(tasks) != 0 || !okay || task_count != 1) return 0;

    n = snprintf(path, sizeof(path), "/proc/%ld/task/%ld/fd", (long)pid, (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path)) return 0;
    DIR *fds = opendir(path);
    if (!fds) return 0;
    unsigned seen = 0;
    okay = 1;
    for (;;) {
        errno = 0;
        struct dirent *item = readdir(fds);
        if (!item) { if (errno) okay = 0; break; }
        if (item->d_name[0] == '.') continue;
        unsigned long long number;
        struct stat info;
        if (!decimal(item->d_name, &number) || number > 2 ||
            (seen & (1u << number)) ||
            fstatat(dirfd(fds), item->d_name, &info, 0) != 0 ||
            !S_ISCHR(info.st_mode) || info.st_rdev != null_rdev) {
            okay = 0;
            break;
        }
        seen |= 1u << number;
    }
    if (closedir(fds) != 0) okay = 0;
    return okay && seen == 7;
}

static int verify(pid_t pid, unsigned long long dedicated_uid,
                  const char *group_path, const char *root_path,
                  const char **mounts, size_t mount_count) {
#ifndef SYS_pidfd_open
    (void)pid; (void)dedicated_uid; (void)group_path; (void)root_path;
    (void)mounts; (void)mount_count;
    return 0;
#else
    if (!trusted_dir_chain(group_path) || !trusted_dir_chain(root_path)) return 0;
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) return 0;
    int group_fd = open(group_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (group_fd < 0) { close(pidfd); return 0; }
    struct statfs fs;
    struct stat group_info;
    struct stat null_info;
    unsigned long long start_a = 0, start_b = 0;
    int okay = fstat(group_fd, &group_info) == 0 && group_info.st_uid == 0 &&
        (group_info.st_mode & 022) == 0 &&
        fstatfs(group_fd, &fs) == 0 && fs.f_type == CGROUP2_SUPER_MAGIC &&
        stat("/dev/null", &null_info) == 0 && S_ISCHR(null_info.st_mode) &&
        pidfd_live(pidfd) && proc_identity(pid, &start_a) &&
        target_uids_ok(pid, dedicated_uid) && other_uids_ok(pid, dedicated_uid) &&
        proc_cgroup_ok(pid, group_path) && cgroup_ok(group_fd, pid) &&
        namespace_and_root_ok(pid, root_path) &&
        task_and_fd_ok(pid, null_info.st_rdev) &&
        mountinfo_ok(pid, mounts, mount_count);
    if (okay) {
        char live_path[80];
        int n = snprintf(live_path, sizeof(live_path), "/proc/%ld/root", (long)pid);
        int expected_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int live_fd = n > 0 && (size_t)n < sizeof(live_path) ?
            open(live_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC) : -1;
        struct stat expected_info, live_info;
        if (expected_fd < 0 || live_fd < 0 ||
            fstat(expected_fd, &expected_info) != 0 || fstat(live_fd, &live_info) != 0 ||
            !same_object(&expected_info, &live_info) || expected_info.st_uid != 0 ||
            (expected_info.st_mode & 022) != 0) okay = 0;
        if (okay) {
            size_t entries = 0;
            okay = scan_tree(live_fd, null_info.st_rdev, &entries, 1) &&
                fstat(expected_fd, &expected_info) == 0 &&
                fstat(live_fd, &live_info) == 0 &&
                same_object(&expected_info, &live_info);
        }
        if (expected_fd >= 0 && close(expected_fd) != 0) okay = 0;
        if (live_fd >= 0 && close(live_fd) != 0) okay = 0;
    }
    if (okay) okay = proc_identity(pid, &start_b) && start_a == start_b &&
        pidfd_live(pidfd) && target_uids_ok(pid, dedicated_uid) &&
        other_uids_ok(pid, dedicated_uid) && proc_cgroup_ok(pid, group_path) &&
        fstat(group_fd, &group_info) == 0 && group_info.st_uid == 0 &&
        (group_info.st_mode & 022) == 0 &&
        cgroup_ok(group_fd, pid) && namespace_and_root_ok(pid, root_path) &&
        task_and_fd_ok(pid, null_info.st_rdev) &&
        mountinfo_ok(pid, mounts, mount_count) && pidfd_live(pidfd);
    if (close(group_fd) != 0 || close(pidfd) != 0) okay = 0;
    return okay;
#endif
}
#endif

#ifndef SGW_CENSUS_TEST
int main(int argc, char **argv) {
#ifndef __linux__
    (void)argc; (void)argv;
    fputs("Linux required.\n", stderr);
    return 2;
#else
    pid_t pid = 0;
    unsigned long long dedicated_uid = 0;
    const char *group = NULL, *root = NULL;
    const char *mounts[MAX_MOUNTS];
    size_t mount_count = 0;
    for (int i = 1; i < argc; i++) {
        if (++i >= argc) return 2;
        const char *flag = argv[i - 1], *value = argv[i];
        if (strcmp(flag, "--pid") == 0 && !pid) {
            unsigned long long number;
            if (!decimal(value, &number) || number == 0 || number > INT_MAX) return 2;
            pid = (pid_t)number;
        } else if (strcmp(flag, "--uid") == 0 && !dedicated_uid) {
            if (!decimal(value, &dedicated_uid) || dedicated_uid == 0 ||
                dedicated_uid > UINT_MAX) return 2;
        } else if (strcmp(flag, "--cgroup") == 0 && !group) {
            if (!clean_path(value) || strncmp(value, "/sys/fs/cgroup/", 15) != 0) return 2;
            group = value;
        } else if (strcmp(flag, "--root") == 0 && !root) {
            if (!clean_path(value) || strcmp(value, "/") == 0) return 2;
            root = value;
        } else if (strcmp(flag, "--mount") == 0 && mount_count < MAX_MOUNTS) {
            if (!clean_path(value)) return 2;
            for (size_t j = 0; j < mount_count; j++) {
                if (strcmp(mounts[j], value) == 0) return 2;
            }
            mounts[mount_count++] = value;
        } else {
            return 2;
        }
    }
    if (!pid || !dedicated_uid || !group || !root || !mount_count) return 2;
    if (getuid() != 0 || geteuid() != 0) {
        fputs("Root required for agent census.\n", stderr);
        return 1;
    }
    if (!verify(pid, dedicated_uid, group, root, mounts, mount_count)) {
        fputs("Agent isolation census failed.\n", stderr);
        return 1;
    }
    return 0;
#endif
}
#endif
