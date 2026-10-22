#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAX_ENTRIES 200000
#define MAX_DEPTH 128

extern char **environ;

struct visited_dir {
  dev_t device;
  ino_t inode;
  int active;
};

static struct visited_dir *visited;
static size_t visited_count;
static size_t entry_count;
static const char *trusted_root;
static int trusted_root_fd = -1;

static int inside_root(const char *path) {
  size_t len = strlen(trusted_root);
  return strncmp(path, trusted_root, len) == 0 && path[len] == '/';
}

static int safe_owner(const struct stat *info) {
  return info->st_uid == 0 && (info->st_mode & 022) == 0;
}

static int canonical(const char *path) {
  char resolved[PATH_MAX];
  if (!path || path[0] != '/' || strlen(path) >= sizeof(resolved)) return 0;
  return realpath(path, resolved) && strcmp(path, resolved) == 0;
}

static int check_path(const char *path, int required_type) {
  if (!canonical(path)) return 0;

  char current[PATH_MAX];
  size_t used = 1;
  current[0] = '/';
  current[1] = '\0';
  struct stat info;
  if (lstat(current, &info) != 0 || !S_ISDIR(info.st_mode) || !safe_owner(&info)) return 0;

  const char *part = path + 1;
  while (*part) {
    const char *end = strchr(part, '/');
    size_t amount = end ? (size_t)(end - part) : strlen(part);
    if (amount == 0 || used + amount + 1 >= sizeof(current)) return 0;
    if (used > 1) current[used++] = '/';
    memcpy(current + used, part, amount);
    used += amount;
    current[used] = '\0';
    if (lstat(current, &info) != 0 || !safe_owner(&info)) return 0;
    if (end && !S_ISDIR(info.st_mode)) return 0;
    if (!end) break;
    part = end + 1;
  }

  if (required_type == 1) return S_ISDIR(info.st_mode);
  if (required_type == 2) return S_ISREG(info.st_mode) && info.st_nlink == 1;
  return (S_ISDIR(info.st_mode) || S_ISREG(info.st_mode)) &&
    (S_ISDIR(info.st_mode) || info.st_nlink == 1);
}

static int check_tree(const char *path, unsigned int depth);

static int check_link(const char *path, const struct stat *info, unsigned int depth) {
  if (info->st_uid != 0 || info->st_nlink != 1 || !inside_root(path)) return 0;
  struct open_how how = {
    .flags = O_PATH | O_CLOEXEC,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
  };
  const char *relative = path + strlen(trusted_root) + 1;
  int target_fd = syscall(SYS_openat2, trusted_root_fd, relative, &how, sizeof(how));
  if (target_fd < 0) return 0;
  struct stat target;
  int safe_target = fstat(target_fd, &target) == 0 &&
    (S_ISDIR(target.st_mode) || S_ISREG(target.st_mode));
  close(target_fd);
  if (!safe_target) return 0;
  char resolved[PATH_MAX];
  if (!realpath(path, resolved) || !inside_root(resolved)) return 0;
  return check_path(resolved, 0) && check_tree(resolved, depth + 1);
}

static int check_tree(const char *path, unsigned int depth) {
  if (depth > MAX_DEPTH || ++entry_count > MAX_ENTRIES) return 0;
  struct stat info;
  if (lstat(path, &info) != 0) return 0;
  if (S_ISLNK(info.st_mode)) return check_link(path, &info, depth);
  if (!safe_owner(&info)) return 0;
  if (S_ISREG(info.st_mode)) return info.st_nlink == 1;
  if (!S_ISDIR(info.st_mode)) return 0;

  size_t index;
  for (index = 0; index < visited_count; index++) {
    if (visited[index].device == info.st_dev && visited[index].inode == info.st_ino) {
      return !visited[index].active;
    }
  }
  if (visited_count >= MAX_ENTRIES) return 0;
  index = visited_count++;
  visited[index] = (struct visited_dir){ .device = info.st_dev, .inode = info.st_ino, .active = 1 };

  DIR *dir = opendir(path);
  if (!dir) return 0;
  int ok = 1;
  for (;;) {
    errno = 0;
    struct dirent *item = readdir(dir);
    if (!item) {
      if (errno) ok = 0;
      break;
    }
    if (strcmp(item->d_name, ".") == 0 || strcmp(item->d_name, "..") == 0) continue;
    char child[PATH_MAX];
    int length = snprintf(child, sizeof(child), "%s/%s", path, item->d_name);
    if (length <= 0 || (size_t)length >= sizeof(child) || !check_tree(child, depth + 1)) {
      ok = 0;
      break;
    }
  }
  if (closedir(dir) != 0) ok = 0;
  visited[index].active = 0;
  return ok;
}

static int has_name(const char *entry, const char *name) {
  size_t len = strlen(name);
  return strncmp(entry, name, len) == 0 && entry[len] == '=';
}

static int has_prefix(const char *entry, const char *prefix) {
  return strncmp(entry, prefix, strlen(prefix)) == 0;
}

static int check_environment(const char *ca_path) {
  int seen_ca = 0;
  for (char **cursor = environ; *cursor; cursor++) {
    const char *entry = *cursor;
    if (has_name(entry, "NODE_EXTRA_CA_CERTS")) {
      if (++seen_ca > 1 || !ca_path || strcmp(entry + strlen("NODE_EXTRA_CA_CERTS="), ca_path) != 0)
        return 0;
      continue;
    }
    if (has_name(entry, "NODE_ENV")) {
      if (strcmp(entry, "NODE_ENV=production") != 0) return 0;
      continue;
    }
    if (has_prefix(entry, "NODE_") || has_prefix(entry, "LD_") ||
        has_prefix(entry, "DYLD_") || has_prefix(entry, "OPENSSL_") ||
        has_prefix(entry, "SSL_CERT_") || has_prefix(entry, "UV_") ||
        has_prefix(entry, "GLIBC_") || has_prefix(entry, "MALLOC_") ||
        has_name(entry, "GCONV_PATH") || has_name(entry, "LOCPATH") ||
        has_name(entry, "TZDIR") || has_name(entry, "SSLKEYLOGFILE")) return 0;
  }
  return ca_path ? seen_ca == 1 : seen_ca == 0;
}

int main(int argc, char **argv) {
  int execute = argc >= 9 && strcmp(argv[1], "verify-exec") == 0 &&
    strcmp(argv[8], "--") == 0;
  if (!execute && (argc != 8 || strcmp(argv[1], "verify") != 0)) return 64;
  trusted_root = argv[2];
  if (strcmp(trusted_root, "/") == 0 || !check_path(trusted_root, 1)) {
    fputs("unsafe runtime root\n", stderr);
    return 65;
  }
  if (!inside_root(argv[3]) || !check_path(argv[3], 2)) {
    fputs("unsafe Node executable\n", stderr);
    return 65;
  }
  if (!inside_root(argv[4]) || !check_path(argv[4], 2)) {
    fputs("unsafe broker entry\n", stderr);
    return 65;
  }
  if (!check_path(argv[5], 2)) {
    fputs("unsafe broker config\n", stderr);
    return 65;
  }

  const char *ca_path = strcmp(argv[6], "-") == 0 ? NULL : argv[6];
  const char *env_path = strcmp(argv[7], "-") == 0 ? NULL : argv[7];
  if ((ca_path && !check_path(ca_path, 2)) || !check_environment(ca_path)) return 66;
  if (env_path) {
    struct stat env_info;
    if (!check_path(env_path, 2) || lstat(env_path, &env_info) != 0 ||
        (env_info.st_mode & 0777) != 0600) return 66;
  }

  trusted_root_fd = open(trusted_root, O_PATH | O_DIRECTORY | O_CLOEXEC);
  if (trusted_root_fd < 0) return 67;
  visited = calloc(MAX_ENTRIES, sizeof(*visited));
  if (!visited || !check_tree(trusted_root, 0)) {
    free(visited);
    close(trusted_root_fd);
    return 67;
  }
  free(visited);
  if (execute) {
    char **node_args = calloc((size_t)argc, sizeof(*node_args));
    if (!node_args) return 68;
    node_args[0] = argv[3];
    node_args[1] = argv[4];
    for (int i = 9; i < argc; i++) node_args[i - 7] = argv[i];
    execve(argv[3], node_args, environ);
    free(node_args);
    close(trusted_root_fd);
    return 68;
  }
  close(trusted_root_fd);
  return 0;
}
