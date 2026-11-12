#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1], "extra") == 0) {
        if (open("/ready", O_RDONLY | O_CLOEXEC) < 3) return 3;
    } else if (strcmp(argv[1], "socket") == 0) {
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0 ||
            fds[0] < 3 || fds[1] < 3) return 4;
    } else if (strcmp(argv[1], "clean") != 0) {
        return 2;
    }

    int ready = open("/ready", O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (ready < 3 || write(ready, "READY\n", 6) != 6 || fsync(ready) != 0 || close(ready) != 0)
        return 5;
    for (;;) pause();
}
