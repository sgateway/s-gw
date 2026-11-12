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
    if (!ipv4 || !fgets(line, sizeof(line), ipv4)) {
        if (ipv4) fclose(ipv4);
        return 0;
    }
    while (fgets(line, sizeof(line), ipv4)) {
        if (sscanf(line, "%16s %8s %8s %8s %8s %8s %8s %8s",
            interface, destination, gateway, flags, refcount, used, metric, mask) != 8 ||
            strcmp(interface, "lo") != 0 || strcmp(gateway, "00000000") != 0 ||
            !((strcmp(destination, "0000007F") == 0 && strcmp(mask, "000000FF") == 0) ||
              (strcmp(destination, "0100007F") == 0 && strcmp(mask, "FFFFFFFF") == 0))) {
            fclose(ipv4);
            return 0;
        }
    }
    if (ferror(ipv4)) { fclose(ipv4); return 0; }
    fclose(ipv4);

    FILE *ipv6 = fopen("/proc/net/ipv6_route", "r");
    if (!ipv6) return errno == ENOENT;
    while (fgets(line, sizeof(line), ipv6)) {
        if (sscanf(line, "%32s %2s %32s %2s %32s %8s %8s %8s %8s %16s",
            destination, prefix, source, source_prefix, gateway, metric, refcount, used,
            flags, interface) != 10 || strcmp(interface, "lo") != 0 ||
            strcmp(source, "00000000000000000000000000000000") != 0 ||
            strcmp(source_prefix, "00") != 0 ||
            strcmp(gateway, "00000000000000000000000000000000") != 0 ||
            !((strcmp(destination, "00000000000000000000000000000001") == 0 &&
                strcmp(prefix, "80") == 0) ||
              (strcmp(destination, "ff000000000000000000000000000000") == 0 &&
                strcmp(prefix, "08") == 0))) {
            fclose(ipv6);
            return 0;
        }
    }
    int okay = !ferror(ipv6);
    fclose(ipv6);
    return okay;
}

static int namespace_file(int fd, const struct stat *host) {
    struct stat item;
    if (fstat(fd, &item) != 0 || !S_ISREG(item.st_mode) || item.st_uid != 0 ||
        (item.st_mode & 022) != 0 || item.st_nlink != 1) return 0;
    if (item.st_dev == host->st_dev && item.st_ino == host->st_ino) return 0;
    if (setns(fd, CLONE_NEWNET) != 0) return 0;
    struct stat current;
    return stat("/proc/self/ns/net", &current) == 0 &&
        current.st_dev == item.st_dev && current.st_ino == item.st_ino &&
        private_loopback() && only_loopback_routes();
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
    if (host_fd < 0 || fstat(host_fd, &host) != 0) return 3;

    if (strcmp(argv[1], "check") == 0) {
        int fd = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        int okay = fd >= 0 && namespace_file(fd, &host);
        if (fd >= 0) close(fd);
        close(host_fd);
        return okay ? 0 : 4;
    }
    if (strcmp(argv[1], "create") != 0) return 2;
    int target = open(argv[2], O_RDONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (target < 0) return 5;
    int mounted = 0, okay = 0;
    if (fchmod(target, 0600) != 0 || unshare(CLONE_NEWNET) != 0) goto done;
    int socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) goto done;
    struct ifreq request;
    memset(&request, 0, sizeof(request));
    memcpy(request.ifr_name, "lo", 3);
    if (ioctl(socket_fd, SIOCGIFFLAGS, &request) != 0) {
        close(socket_fd);
        goto done;
    }
    request.ifr_flags |= IFF_UP;
    if (ioctl(socket_fd, SIOCSIFFLAGS, &request) != 0) {
        close(socket_fd);
        goto done;
    }
    close(socket_fd);
    if (!private_loopback() || !only_loopback_routes() ||
        mount("/proc/self/ns/net", argv[2], NULL, MS_BIND, NULL) != 0) goto done;
    mounted = 1;
    struct stat pinned, current;
    okay = stat(argv[2], &pinned) == 0 && stat("/proc/self/ns/net", &current) == 0 &&
        pinned.st_dev == current.st_dev && pinned.st_ino == current.st_ino &&
        (pinned.st_dev != host.st_dev || pinned.st_ino != host.st_ino);
done:
    close(target);
    close(host_fd);
    if (!okay) {
        if (mounted) umount(argv[2]);
        unlink(argv[2]);
        fputs("Could not pin a private loopback-only network namespace.\n", stderr);
    }
    return okay ? 0 : 6;
}
