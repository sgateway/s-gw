import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const source = fileURLToPath(new URL("../native/linux-agent-gate/launch-gate.c", import.meta.url));
const invocation = "0123456789abcdef0123456789abcdef";
let tmp = "";

afterEach(async () => {
  if (tmp) await rm(tmp, { recursive: true, force: true });
  tmp = "";
});

async function compiledGate(): Promise<{ binary: string; marker: string }> {
  tmp = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-gate-"));
  const marker = path.join(tmp, "release");
  const binary = path.join(tmp, "gate");
  const result = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror",
    `-DSGW_GATE_RELEASE_FILE="${marker}"`, `-DSGW_GATE_OWNER_UID=${process.getuid?.() ?? 0}`,
    "-DGATE_WAIT_SECONDS=1", source, "-o", binary], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || "Could not compile Linux launch gate test binary.");
  return { binary, marker };
}

function runGate(binary: string, args: string[]) {
  const child = spawn(binary, ["--", ...args], { env: { INVOCATION_ID: invocation } });
  const finished = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", code => resolve(code ?? -1));
  });
  return { child, finished };
}

describe.skipIf(process.platform === "win32")("native Linux launch gate protocol", () => {
  it("keeps the target stopped until the exact invocation and PID are released", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    await chmod(marker, 0o444);
    const effect = path.join(tmp, "ran");
    const { child, finished } = runGate(binary, ["/bin/sh", "-c", `touch "${effect}"`]);
    await new Promise(resolve => setTimeout(resolve, 100));
    await expect(readFile(effect)).rejects.toMatchObject({ code: "ENOENT" });
    const ready = path.join(tmp, "ready.tmp");
    await writeFile(ready, `GO ${invocation} ${child.pid}\n`, { mode: 0o444 });
    await chmod(ready, 0o444);
    await rename(ready, marker);
    expect(await finished).toBe(0);
    expect(await readFile(effect, "utf8")).toBe("");
  });

  it("rejects a stale release marker without starting the target", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, `GO ${invocation} 1\n`, { mode: 0o444 });
    const effect = path.join(tmp, "ran");
    const { finished } = runGate(binary, ["/bin/sh", "-c", `touch "${effect}"`]);
    expect(await finished).toBe(72);
    await expect(readFile(effect)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("times out closed and rejects a symlinked marker", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    expect(await runGate(binary, ["/bin/true"]).finished).toBe(73);
    await rm(marker);
    const target = path.join(tmp, "other");
    await writeFile(target, `GO ${invocation} 1\n`, { mode: 0o444 });
    await symlink(target, marker);
    expect(await runGate(binary, ["/bin/true"]).finished).toBe(70);
  });
});
