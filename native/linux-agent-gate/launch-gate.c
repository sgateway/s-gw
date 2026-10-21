#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#endif

#ifndef SGW_GATE_RELEASE_FILE
#define SGW_GATE_RELEASE_FILE "/run/s-gw/launch-gate/release"
#endif

#ifndef SGW_GATE_OWNER_UID
#define SGW_GATE_OWNER_UID 0
#endif

#ifndef GATE_WAIT_SECONDS
#define GATE_WAIT_SECONDS 60
#endif

#ifdef __linux__
static int close_inherited_fds(void) {
#ifdef SYS_close_range
  if (syscall(SYS_close_range, 3u, ~0u, 0) == 0) return 0;
#endif
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0 ||
      limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > INT_MAX) return -1;
  for (int fd = 3; (rlim_t)fd < limit.rlim_cur; fd++) {
    if (close(fd) != 0 && errno != EBADF) return -1;
  }
  return 0;
}
#endif

static int valid_invocation(const char *value) {
  if (!value || strlen(value) != 32) return 0;
  for (size_t i = 0; i < 32; i++) {
    if (!((value[i] >= '0' && value[i] <= '9') ||
          (value[i] >= 'a' && value[i] <= 'f'))) return 0;
  }
  return 1;
}

static int read_release(char *buf, size_t size) {
  int fd = open(SGW_GATE_RELEASE_FILE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  struct stat info;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != SGW_GATE_OWNER_UID ||
      (info.st_mode & 022) != 0 || info.st_nlink != 1) {
    close(fd);
    return -1;
  }
  ssize_t count = read(fd, buf, size);
  if (count <= 0 || (size_t)count >= size) {
    close(fd);
    return -1;
  }
  char extra;
  ssize_t tail = read(fd, &extra, 1);
  close(fd);
  if (tail != 0) return -1;
  buf[count] = '\0';
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3 || strcmp(argv[1], "--") != 0 || argv[2][0] != '/') return 64;
#ifdef __linux__
  if (prctl(PR_SET_DUMPABLE, 0) != 0) return 70;
#endif
  const char *invocation = getenv("INVOCATION_ID");
  if (!valid_invocation(invocation)) return 65;

  char expected[96];
  int size = snprintf(expected, sizeof(expected), "GO %s %ld\n", invocation, (long)getpid());
  if (size < 0 || (size_t)size >= sizeof(expected)) return 65;

  struct timespec deadline;
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) return 70;
  deadline.tv_sec += GATE_WAIT_SECONDS;

  for (;;) {
    char marker[96];
    if (read_release(marker, sizeof(marker)) != 0) return 70;
    if (strcmp(marker, expected) == 0) {
#ifdef __linux__
      if (close_inherited_fds() != 0) return 70;
#endif
      execv(argv[2], argv + 2);
      return 71;
    }
    if (strcmp(marker, "WAIT\n") != 0) return 72;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 70;
    if (now.tv_sec > deadline.tv_sec ||
        (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) return 73;
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 20000000 };
    while (nanosleep(&pause, &pause) != 0) {
      if (errno != EINTR) return 70;
    }
  }
}
