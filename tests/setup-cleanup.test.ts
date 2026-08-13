import { spawnSync } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expect, it } from "vitest";

const repoRoot = process.cwd();

it("does not create disposable homes for a fully skipped test file", async () => {
  const tempRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-skipped-suite-"));
  try {
    const vitest = path.join(repoRoot, "node_modules", "vitest", "vitest.mjs");
    const config = path.join(repoRoot, "tests", "fixtures", "vitest-skipped.config.ts");
    const result = spawnSync(process.execPath, [
      vitest,
      "run",
      "--config",
      config,
      "--no-file-parallelism"
    ], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        LOCALAPPDATA: tempRoot,
        TEMP: tempRoot,
        TMP: tempRoot,
        TMPDIR: tempRoot
      },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000,
      windowsHide: true
    });

    expect(result.error).toBeUndefined();
    expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
    expect(await disposableTestHomes(tempRoot)).toEqual([]);
  } finally {
    await rm(tempRoot, { recursive: true, force: true });
  }
}, 45_000);

async function disposableTestHomes(root: string): Promise<string[]> {
  const found: string[] = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) break;
    for (const entry of await readdir(current, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const target = path.join(current, entry.name);
      if (entry.name.startsWith("sgw-vitest-") || entry.name.startsWith("sgw-vitest-root-")) {
        found.push(target);
      }
      pending.push(target);
    }
  }
  return found.sort();
}
