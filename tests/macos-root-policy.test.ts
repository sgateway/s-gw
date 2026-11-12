import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const macWithCompiler = process.platform === "darwin" &&
  spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!macWithCompiler)("macOS root policy source", () => {
  const sources = fileURLToPath(new URL("../native/macos-root-policy/", import.meta.url));

  it("rejects malformed frames and missing provider evidence for two distinct UIDs", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-core-"));
    try {
      const binary = path.join(tmp, "test-policy");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-policy.c"), "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("builds the IPC service and refuses an unprivileged caller", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-service-"));
    try {
      const binary = path.join(tmp, "policy-service");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "policy-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      if (process.getuid?.() === 0) return;
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status).not.toBe(0);
      expect(run.stderr).toContain("requires root");
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("returns DENIED for a registered UID while provider attestation is absent", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-denial-"));
    try {
      const binary = path.join(tmp, "test-service");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });
});
