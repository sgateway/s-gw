import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const helper = path.join(root, "native/macos-app/Sources/SgwMac/Services/ConsoleListenerVerifier.swift");
const harness = path.join(root, "native/macos-app/Tests/ConsoleListenerVerifierTests.swift");
const native = process.platform === "darwin" && spawnSync("swiftc", ["--version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!native)("native console listener verification", () => {
  it("checks the configured port and rejects noncanonical console origins", async () => {
    const tmp = await mkdtemp(path.join(os.tmpdir(), "sgw-listener-verifier-"));
    try {
      const binary = path.join(tmp, "listener-verifier-tests");
      const build = spawnSync("swiftc", ["-parse-as-library", helper, harness, "-o", binary], { encoding: "utf8" });
      expect(build.status, build.stderr || build.stdout).toBe(0);

      const run = spawnSync(binary, [], { encoding: "utf8", timeout: 10_000 });
      expect(run.status, run.stderr || run.stdout).toBe(0);
      expect(run.stdout).toContain("CONSOLE_LISTENER_VERIFIER_TESTS_OK");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, 30_000);
});
