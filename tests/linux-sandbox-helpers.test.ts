import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it } from "vitest";
import { findTrustedLinuxHelper, trustedLinuxExecutable, withTrustedLinuxPathAsync } from "../src/linux-sandbox-helpers.js";

let fixture = "";
afterEach(async () => { if (fixture) await rm(fixture, { recursive: true, force: true }); });

it.skipIf(process.platform === "win32")("rejects fake bwrap and which in an agent-writable directory", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-helper-path-"));
  const marker = path.join(fixture, "executed");
  for (const name of ["bwrap", "which"]) {
    const fake = path.join(fixture, name);
    await writeFile(fake, `#!/bin/sh\necho ran > '${marker}'\n`, { mode: 0o755 });
    expect(trustedLinuxExecutable(fake)).toBeUndefined();
    expect(() => findTrustedLinuxHelper(name, [fixture])).toThrow(`Trusted Linux sandbox helper ${name} is unavailable`);
  }
  await rm(path.join(fixture, "which"));
  await symlink("/bin/sh", path.join(fixture, "which"));
  expect(trustedLinuxExecutable(path.join(fixture, "which"))).toBeUndefined();
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
});

it.skipIf(process.platform === "win32")("accepts a root-owned helper and ignores an earlier fake which", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-helper-path-"));
  await writeFile(path.join(fixture, "which"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  const systemWhich = trustedLinuxExecutable("/usr/bin/which") || trustedLinuxExecutable("/bin/which");
  expect(systemWhich).toBeTruthy();
  expect(findTrustedLinuxHelper("which", [fixture, "/usr/bin", "/bin"])).toBe(systemWhich);
  expect(trustedLinuxExecutable("/bin/sh")).toBeTruthy();
});

it.skipIf(process.platform === "win32")("restores the caller PATH after a failed trusted upstream call", async () => {
  const previous = process.env.PATH;
  await expect(withTrustedLinuxPathAsync("/usr/bin:/bin", async () => {
    expect(process.env.PATH).toBe("/usr/bin:/bin");
    throw new Error("fixture failure");
  })).rejects.toThrow("fixture failure");
  expect(process.env.PATH).toBe(previous);
});

it.skipIf(process.platform === "win32")("restores the requested PATH only in sandbox-child", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-helper-path-"));
  const manifest = path.join(fixture, "launch.json");
  const loader = new URL("../node_modules/tsx/dist/esm/index.mjs", import.meta.url).href;
  const child = fileURLToPath(new URL("../src/sandbox-child.ts", import.meta.url));
  const run = (agentPath: string | null) => {
    const content = { command: process.execPath, args: ["-e", "console.log(JSON.stringify(process.env.PATH ?? null))"],
      tmpdir: fixture, restorePath: true, agentPath };
    return writeFile(manifest, JSON.stringify(content)).then(() =>
      execFileSync(process.execPath, ["--import", loader, child, manifest], {
        env: { PATH: "/usr/bin:/bin" }, encoding: "utf8" }).trim());
  };
  expect(await run(`${fixture}:/custom/bin`)).toBe(JSON.stringify(`${fixture}:/custom/bin`));
  expect(await run(null)).toBe("null");
});
