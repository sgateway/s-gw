#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int safe_path(const char *value) {
    const char *prefix = "/run/s-gw/netns/";
    size_t len = strlen(value), prefix_len = strlen(prefix);
    if (strncmp(value, prefix, prefix_len) != 0 || len <= prefix_len || len > prefix_len + 48) return 0;
    const char *name = value + prefix_len;
    for (size_t i = 0; name[i]; i++) {
        char c = name[i];
        int alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!alnum && !(c == '-' && i > 0 && name[i + 1])) return 0;
        if ((i == 0 || name[i + 1] == '\0') && !alnum) return 0;
    }
    return 1;
}

static int root_directory(const char *name) {
    struct stat item;
    return lstat(name, &item) == 0 && S_ISDIR(item.st_mode) && item.st_uid == 0 &&
        (item.st_mode & 022) == 0;
}

static int private_loopback(void) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return 0;
    int found = 0, okay = 1;
    for (struct ifaddrs *item = list; item; item = item->ifa_next) {
        if (!item->ifa_name || strcmp(item->ifa_name, "lo") != 0 ||
            !(item->ifa_flags & IFF_LOOPBACK) || !(item->ifa_flags & IFF_UP)) {
            okay = 0;
            break;
        }
        found = 1;
    }
    freeifaddrs(list);
    return found && okay;
}

static int only_loopback_routes(void) {
    char line[512], interface[17], destination[33], prefix[3];
    char gateway[33], mask[9], source[33], source_prefix[3];
    char metric[9], refcount[9], used[9], flags[9];
    FILE *ipv4 = fopen("/proc/net/route", "r");
    if (!ipv4) {
        perror("Managed namespace IPv4 route inventory open");
        return 0;
    }
    if (!fgets(line, sizeof(line), ipv4)) {
        fputs("Managed namespace IPv4 route inventory has no header.\n", stderr);
        fclose(ipv4);
        return 0;
    }
    while (fgets(line, sizeof(line), ipv4)) {
        int fields = sscanf(line, "%16s %8s %8s %8s %8s %8s %8s %8s",
            interface, destination, gateway, flags, refcount, used, metric, mask);
        if (fields != 8 ||
            strcmp(interface, "lo") != 0 || strcmp(gateway, "00000000") != 0 ||
            !((strcmp(destination, "0000007F") == 0 && strcmp(mask, "000000FF") == 0) ||
              (strcmp(destination, "0100007F") == 0 && strcmp(mask, "FFFFFFFF") == 0))) {
            fprintf(stderr, "Managed namespace rejected IPv4 route (%d fields): %s",
                fields, line);
            if (!strchr(line, '\n')) fputc('\n', stderr);
            fclose(ipv4);
            return 0;
        }
    }
    if (ferror(ipv4)) {
        perror("Managed namespace IPv4 route inventory read");
        fclose(ipv4);
        return 0;
    }
    fclose(ipv4);

    FILE *ipv6 = fopen("/proc/net/ipv6_route", "r");
    if (!ipv6) {
        if (errno == ENOENT) return 1;
        perror("Managed namespace IPv6 route inventory open");
        return 0;
    }
    while (fgets(line, sizeof(line), ipv6)) {
        int fields = sscanf(line, "%32s %2s %32s %2s %32s %8s %8s %8s %8s %16s",
            destination, prefix, source, source_prefix, gateway, metric, refcount, used,
            flags, interface);
        // Linux net/ipv6/route.c defines fib6_null_entry_template as an unreachable
        // RTF_REJECT|RTF_NONEXTHOP route with metric ~0u.
        int kernel_null = fields == 10 &&
            strcmp(destination, "00000000000000000000000000000000") == 0 &&
            strcmp(prefix, "00") == 0 && strcmp(metric, "ffffffff") == 0 &&
            strcmp(flags, "00200200") == 0;
        if (fields != 10 || strcmp(interface, "lo") != 0 ||
            strcmp(source, "00000000000000000000000000000000") != 0 ||
            strcmp(source_prefix, "00") != 0 ||
            strcmp(gateway, "00000000000000000000000000000000") != 0 ||
            !((strcmp(destination, "00000000000000000000000000000001") == 0 &&
                strcmp(prefix, "80") == 0) ||
              (strcmp(destination, "ff000000000000000000000000000000") == 0 &&
                strcmp(prefix, "08") == 0) || kernel_null)) {
            fprintf(stderr, "Managed namespace rejected IPv6 route (%d fields): %s",
                fields, line);
            if (!strchr(line, '\n')) fputc('\n', stderr);
            fclose(ipv6);
            return 0;
        }
    }
    int okay = !ferror(ipv6);
    if (!okay) perror("Managed namespace IPv6 route inventory read");
    fclose(ipv6);
    return okay;
}

static int namespace_file(int fd, const struct stat *host) {
    struct stat item;
    if (fstat(fd, &item) != 0) {
        perror("Managed namespace check: mountpoint stat");
        return 0;
    }
    if (!S_ISREG(item.st_mode) || item.st_uid != 0 ||
        (item.st_mode & 022) != 0 || item.st_nlink != 1 ||
        (item.st_dev == host->st_dev && item.st_ino == host->st_ino)) {
        fputs("Managed namespace check: untrusted mountpoint.\n", stderr);
        return 0;
    }
    if (setns(fd, CLONE_NEWNET) != 0) {
        perror("Managed namespace check: setns");
        return 0;
    }
    struct stat current;
    if (stat("/proc/self/ns/net", &current) != 0) {
        perror("Managed namespace check: live namespace stat");
        return 0;
    }
    if (current.st_dev != item.st_dev || current.st_ino != item.st_ino) {
        fputs("Managed namespace check: pinned inode differs from live namespace.\n", stderr);
        return 0;
    }
    if (!private_loopback()) {
        fputs("Managed namespace check: loopback interface invariant failed.\n", stderr);
        return 0;
    }
    if (!only_loopback_routes()) {
        fputs("Managed namespace check: route invariant failed.\n", stderr);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3 || geteuid() != 0 || getuid() != 0 || !safe_path(argv[2]) ||
        !root_directory("/run") || !root_directory("/run/s-gw") ||
        !root_directory("/run/s-gw/netns")) {
        fputs("Invalid managed network namespace request.\n", stderr);
        return 2;
    }
    int host_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
    struct stat host;
    if (host_fd < 0 || fstat(host_fd, &host) != 0) {
        perror("Managed namespace host readback");
        return 3;
    }

    if (strcmp(argv[1], "check") == 0) {
        int fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) perror("Managed namespace check: mountpoint open");
        int okay = fd >= 0 && namespace_file(fd, &host);
        if (fd >= 0) close(fd);
        close(host_fd);
        return okay ? 0 : 4;
    }
    if (strcmp(argv[1], "create") != 0) return 2;
    int target = open(argv[2], O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (target < 0) {
        perror("Managed namespace mountpoint create");
        return 5;
    }
    int mounted = 0, okay = 0, failure_errno = 0;
    const char *step = "mountpoint chmod";
    if (fchmod(target, 0600) != 0) goto done;
    step = "unshare(CLONE_NEWNET)";
    if (unshare(CLONE_NEWNET) != 0) goto done;
    step = "loopback socket";
    int socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) goto done;
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    memcpy(request.ifr_name, "lo", 3);
    step = "loopback SIOCGIFFLAGS";
    if (ioctl(socket_fd, SIOCGIFFLAGS, &request) != 0) {
        close(socket_fd);
        goto done;
    }
    request.ifr_flags |= IFF_UP;
    step = "loopback SIOCSIFFLAGS";
    if (ioctl(socket_fd, SIOCSIFFLAGS, &request) != 0) {
        close(socket_fd);
        goto done;
    }
    close(socket_fd);
    errno = 0;
    step = "loopback interface inventory";
    if (!private_loopback()) goto done;
    errno = 0;
    step = "loopback route inventory";
    if (!only_loopback_routes()) goto done;
    step = "namespace bind mount";
    if (mount("/proc/self/ns/net", argv[2], NULL, MS_BIND, NULL) != 0) goto done;
    mounted = 1;
    struct stat pinned, current;
    errno = 0;
    step = "pinned namespace readback";
    okay = stat(argv[2], &pinned) == 0 && stat("/proc/self/ns/net", &current) == 0 &&
        pinned.st_dev == current.st_dev && pinned.st_ino == current.st_ino &&
        (pinned.st_dev != host.st_dev || pinned.st_ino != host.st_ino);
done:
    failure_errno = errno;
    close(target);
    close(host_fd);
    if (!okay) {
        if (mounted) umount(argv[2]);
        unlink(argv[2]);
        fprintf(stderr, "Could not pin a private loopback-only network namespace (%s: %s).\n",
            step, failure_errno ? strerror(failure_errno) : "invariant failed");
    }
    return okay ? 0 : 6;
}
