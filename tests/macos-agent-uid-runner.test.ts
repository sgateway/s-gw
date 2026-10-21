import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const macWithCompiler = process.platform === "darwin" &&
  spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!macWithCompiler)("macOS agent UID runner", () => {
  it("requires a root-owned socket namespace and rejects permissive ACLs", () => {
    const tmp = mkdtempSync(path.join(os.homedir(), ".sgw-uid-trust-"));
    try {
      const clean = path.join(tmp, "clean");
      const granted = path.join(tmp, "granted");
      mkdirSync(clean, { mode: 0o700 });
      mkdirSync(granted, { mode: 0o700 });
      const acl = spawnSync("chmod", ["+a", "everyone allow read,write,execute", granted], { encoding: "utf8" });
      expect(acl.status, acl.stderr).toBe(0);
      const sourceDir = fileURLToPath(new URL("../native/macos-agent-launcher/", import.meta.url));
      const harness = path.join(tmp, "trust-test.c");
      const binary = path.join(tmp, "trust-test");
      writeFileSync(harness, String.raw`
#define main sgw_uid_runner_entry
#include "uid-runner.c"
#undef main
int main(int argc, char **argv) {
    if (argc != 5) return 10;
    if (trusted_parents(argv[1], getuid())) return 11;
    if (!trusted_parents(argv[2], getuid())) return 12;
    if (no_acl_allow(argv[3]) == 0) return 13;
    char socket_path[PATH_MAX];
    if (snprintf(socket_path, sizeof(socket_path), "%s/control.sock", argv[4]) >= (int)sizeof(socket_path)) return 2;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (fd < 0 || strlen(socket_path) >= sizeof(addr.sun_path)) return 3;
    strcpy(addr.sun_path, socket_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) || chmod(socket_path, 0600)) return 4;
    if (trusted_socket_node(socket_path, getuid(), getuid())) return 5;
    if (trusted_socket_node(socket_path, getuid(), 0) == 0) return 6;
    close(fd);
    return 0;
}
`);
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-I", sourceDir,
        harness, "-o", binary], { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [path.join(clean, "launch-plan"), path.join(granted, "launch-plan"), granted, clean], {
        encoding: "utf8"
      });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("builds with strict warnings and rejects an unprivileged caller", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-uid-runner-"));
    try {
      const source = fileURLToPath(new URL("../native/macos-agent-launcher/uid-runner.c", import.meta.url));
      const binary = path.join(tmp, "uid-runner");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", source, "-o", binary], {
        encoding: "utf8"
      });
      expect(build.status, build.stderr).toBe(0);
      if (process.getuid?.() === 0) return;
      const run = spawnSync(binary, ["231000", "231000", "test-session", "/tmp/agent", "/tmp/broker.sock",
        "/usr/bin/id", "--"], { encoding: "utf8" });
      expect(run.status).not.toBe(0);
      expect(run.stderr).toContain("requires a root-owned service");
      const teardown = spawnSync(binary, ["--teardown", "231000", "test-session"], { encoding: "utf8" });
      expect(teardown.status).not.toBe(0);
      expect(teardown.stderr).toContain("requires a root-owned service");
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("closes inherited descriptors above a lowered soft limit", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-uid-fds-"));
    try {
      const sourceDir = fileURLToPath(new URL("../native/macos-agent-launcher/", import.meta.url));
      const harness = path.join(tmp, "fd-test.c");
      const binary = path.join(tmp, "fd-test");
      writeFileSync(harness, `#define main sgw_uid_runner_entry
#include "uid-runner.c"
#undef main
int main(void) {
    int original = open("/dev/null", O_RDONLY);
    if (original < 0) return 1;
    int high = fcntl(original, F_DUPFD, 256);
    if (high < 256) return 2;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return 3;
    limit.rlim_cur = 64;
    if (setrlimit(RLIMIT_NOFILE, &limit)) return 4;
    if (close_inherited_fds()) return 5;
    errno = 0;
    return fcntl(high, F_GETFD) == -1 && errno == EBADF ? 0 : 6;
}
`);
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-I", sourceDir,
        harness, "-o", binary], { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("sweeps escaped UID descendants and refuses stale or uninspectable PIDs", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-uid-teardown-"));
    try {
      const sourceDir = fileURLToPath(new URL("../native/macos-agent-launcher/", import.meta.url));
      const harness = path.join(tmp, "teardown-test.c");
      const binary = path.join(tmp, "teardown-test");
      writeFileSync(harness, String.raw`
#define proc_listpids fake_listpids
#define proc_pidinfo fake_pidinfo
#define kill fake_kill
#define nanosleep fake_sleep
#define main sgw_uid_runner_entry
#include "uid-runner.c"
#undef main
#undef proc_listpids
#undef proc_pidinfo
#undef kill
#undef nanosleep

static int scenario;
static int alive;
static int reads;
static int terms;
static int kills;
static int foreign_signals;

int fake_listpids(uint32_t type, uint32_t uid, void *buffer, int bytes) {
    if (uid != 231000 || bytes < (int)(2 * sizeof(pid_t))) return -1;
    if (scenario == 5) return bytes;
    pid_t *pids = buffer;
    if (type == PROC_UID_ONLY) {
        pids[0] = 3333; // The escaped child has another process group.
        pids[1] = 4444; // A PID that now belongs to someone else.
        return 2 * sizeof(pid_t);
    }
    if (type == PROC_RUID_ONLY) { pids[0] = 3333; return sizeof(pid_t); }
    return -1;
}

int fake_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int bytes) {
    if (flavor != PROC_PIDTBSDINFO || arg != 0 || bytes != sizeof(struct proc_bsdinfo)) return -1;
    if (scenario == 4 && pid == 3333) { errno = EPERM; return -1; }
    if (pid == 3333 && !alive) { errno = ESRCH; return -1; }
    struct proc_bsdinfo *info = buffer;
    memset(info, 0, sizeof(*info));
    info->pbi_pid = (uint32_t)pid;
    info->pbi_uid = pid == 4444 || (scenario == 2 && ++reads >= 2) ? 501 : 231000;
    info->pbi_ruid = info->pbi_uid;
    info->pbi_start_tvsec = pid == 4444 ? 99 : 42;
    info->pbi_pgid = pid == 3333 ? 7777 : 4444;
    return sizeof(*info);
}

int fake_kill(pid_t pid, int signal_number) {
    if (signal_number == 0) { errno = pid == 3333 && !alive ? ESRCH : 0; return errno ? -1 : 0; }
    if (pid != 3333) { foreign_signals++; return 0; }
    if (signal_number == SIGTERM) { terms++; if (scenario == 1) alive = 0; }
    if (signal_number == SIGKILL) { kills++; alive = 0; }
    return 0;
}

int fake_sleep(const struct timespec *duration, struct timespec *remaining) {
    (void)duration;
    (void)remaining;
    return 0;
}

int main(void) {
    scenario = 1; alive = 1;
    if (teardown_uid(231000, 0) || terms != 1 || foreign_signals) return 1;
    scenario = 2; alive = 1; reads = 0; terms = 0;
    if (teardown_uid(231000, 0) || terms || foreign_signals) return 2;
    scenario = 3; alive = 1; terms = 0; kills = 0;
    if (teardown_uid(231000, 0) || terms < 1 || kills != 1 || foreign_signals) return 3;
    scenario = 4; alive = 1; terms = 0;
    if (teardown_uid(231000, 0) == 0 || terms || foreign_signals) return 4;
    scenario = 5; alive = 1;
    if (teardown_uid(231000, 0) == 0 || foreign_signals) return 5;
    return 0;
}
`);
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-I", sourceDir,
        harness, "-o", binary], { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("finds its own PID with both macOS UID filters", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-uid-list-"));
    try {
      const sourceDir = fileURLToPath(new URL("../native/macos-agent-launcher/", import.meta.url));
      const harness = path.join(tmp, "list-test.c");
      const binary = path.join(tmp, "list-test");
      writeFileSync(harness, String.raw`
#define main sgw_uid_runner_entry
#include "uid-runner.c"
#undef main
int main(void) {
    pid_t pids[UID_SCAN_LIMIT];
    uint32_t filters[] = { PROC_UID_ONLY, PROC_RUID_ONLY };
    for (size_t filter = 0; filter < 2; filter++) {
        int bytes = proc_listpids(filters[filter], getuid(), pids, sizeof(pids));
        if (bytes <= 0 || bytes >= (int)sizeof(pids) || bytes % sizeof(pid_t)) return 1;
        int seen = 0;
        for (int i = 0; i < bytes / (int)sizeof(pid_t); i++) {
            if (pids[i] == getpid()) { seen = 1; break; }
        }
        if (!seen) return 2;
    }
    struct uid_process self;
    return read_process(getpid(), getuid(), &self) == 1 ? 0 : 3;
}
`);
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-I", sourceDir,
        harness, "-o", binary], { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });
});
