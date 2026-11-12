#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int status_value(const char *name) {
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) {
        perror("fopen /proc/self/status");
        return -1;
    }

    char line[256];
    size_t name_len = strlen(name);
    int value = -1;
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, name, name_len) == 0 && line[name_len] == ':') {
            if (sscanf(line + name_len + 1, "%d", &value) != 1) value = -1;
            break;
        }
    }
    if (fclose(file) != 0) {
        perror("fclose /proc/self/status");
        return -1;
    }
    if (value < 0) fprintf(stderr, "Missing status field: %s\n", name);
    return value;
}

static int expect_socket(int family, int blocked) {
    errno = 0;
    int fd = socket(family, SOCK_STREAM, 0);
    if (blocked) {
        if (fd == -1 && errno == EPERM) return 0;
        int socket_errno = errno;
        if (fd >= 0) close(fd);
        fprintf(stderr, "socket(%d) was not denied with EPERM (errno %d).\n", family, socket_errno);
        return 1;
    }
    if (fd < 0) {
        perror("socket positive control");
        return 1;
    }
    if (close(fd) != 0) {
        perror("close socket");
        return 1;
    }
    return 0;
}

static int expect_io_uring_denial(void) {
    struct {
        const char *name;
        long number;
    } calls[] = {
        { "io_uring_setup", SYS_io_uring_setup },
        { "io_uring_enter", SYS_io_uring_enter },
        { "io_uring_register", SYS_io_uring_register },
    };

    for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
        errno = 0;
        long result = syscall(calls[i].number, -1, 0, 0, 0, NULL, 0);
        if (result == -1 && errno == EPERM) continue;
        fprintf(stderr, "%s was not denied with EPERM (result %ld, errno %d).\n",
                calls[i].name, result, errno);
        return 1;
    }
    return 0;
}

static int write_marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("create payload marker");
        return 1;
    }
    const char marker[] = "started\n";
    ssize_t written = write(fd, marker, sizeof(marker) - 1);
    int saved_errno = errno;
    if (close(fd) != 0) {
        perror("close payload marker");
        return 1;
    }
    if (written != (ssize_t)(sizeof(marker) - 1)) {
        errno = written < 0 ? saved_errno : EIO;
        perror("write payload marker");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "baseline") == 0) {
        if (expect_socket(AF_UNIX, 0) || expect_socket(AF_INET, 0)) return 1;
        int filters = status_value("Seccomp_filters");
        if (filters < 0) return 1;
        printf("%d\n", filters);
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "inherited-fd") == 0) {
        if (fcntl(9, F_GETFD) < 0) {
            perror("baseline inherited FD 9");
            return 1;
        }
        return 0;
    }

    if (argc != 4 || strcmp(argv[1], "filtered") != 0) {
        fprintf(stderr, "Usage: %s baseline|inherited-fd|filtered MARKER BASELINE_FILTERS\n", argv[0]);
        return 2;
    }
    if (write_marker(argv[2])) return 1;

    errno = 0;
    if (fcntl(9, F_GETFD) != -1 || errno != EBADF) {
        fprintf(stderr, "Inherited FD 9 reached the payload.\n");
        return 1;
    }

    char *end = NULL;
    long baseline = strtol(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0' || baseline < 0) return 2;
    if (status_value("NoNewPrivs") != 1 || status_value("Seccomp") != 2 ||
        status_value("Seccomp_filters") != baseline + 1) {
        fprintf(stderr, "The payload did not inherit exactly one new seccomp filter.\n");
        return 1;
    }
    if (expect_socket(AF_UNIX, 1) || expect_socket(AF_INET, 0) ||
        expect_io_uring_denial()) return 1;

    return 0;
}
