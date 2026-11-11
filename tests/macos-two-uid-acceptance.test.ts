import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it.skipIf(process.platform !== "darwin")("checks the macOS two-UID acceptance fixture locally", () => {
  const script = fileURLToPath(new URL("../scripts/test-macos-two-uid-acceptance.mjs", import.meta.url));
  const run = spawnSync(process.execPath, [script, "--self-test"], {
    encoding: "utf8", timeout: 15_000, maxBuffer: 64 * 1024
  });
  expect(run.status, run.stderr || run.error?.message).toBe(0);
  expect(run.stdout).toContain("Native acceptance result");
});
