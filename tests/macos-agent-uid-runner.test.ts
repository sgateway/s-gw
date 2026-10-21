import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const macWithCompiler = process.platform === "darwin" &&
  spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!macWithCompiler)("macOS agent UID runner", () => {
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
});
