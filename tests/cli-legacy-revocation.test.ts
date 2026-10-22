import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expect, it, vi } from "vitest";

const repoRoot = process.cwd();
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");

it("the opt-in CLI flag revokes a running legacy command after a new deny", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-legacy-revoke-"));
  const home = path.join(root, "store");
  const ready = path.join(root, "ready");
  const env = {
    PATH: process.env.PATH || "/usr/bin:/bin",
    HOME: root,
    TMPDIR: root,
    LANG: "en_US.UTF-8",
    SGW_HOME: home,
    SGW_RECOVERY_HOME: path.join(root, "recovery"),
    SGW_MASTER_PASSPHRASE: "synthetic CLI revocation passphrase",
    SGW_DISABLE_KEYCHAIN: "1",
    SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
    SGW_DISABLE_UPDATE_CHECK: "1",
    SGW_EXECUTION_ENGINE: "typescript",
    ...(process.platform === "linux" && process.env.SGW_ALLOW_NO_CGROUP === "1"
      ? { SGW_ALLOW_NO_CGROUP: "1" } : {})
  };
  const run = (args: string[], input?: string): string => execFileSync(process.execPath,
    [tsxCli, "src/cli.ts", ...args], {
      cwd: repoRoot, env, input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"]
    });
  let cli: ChildProcess | undefined;
  try {
    const secret = JSON.parse(run(["secret", "add", "--name", "CLI revocation fixture",
      "--type", "api-token", "--value-stdin", "--inject-env", "SGW_FIXTURE_TOKEN",
      "--allow-command", process.execPath], "synthetic-token-only")) as { handle: string };
    const command = `require('node:fs').writeFileSync(${JSON.stringify(ready)}, 'ready'); ` +
      "setTimeout(() => process.exit(0), 10000);";
    const request = JSON.parse(run(["request", "env-command", secret.handle,
      "--command", process.execPath, "--inject-env", "SGW_FIXTURE_TOKEN",
      "--args-json", JSON.stringify(["-e", command]), "--timeout-ms", "12000"])) as { id: string };
    run(["approve", request.id]);

    cli = spawn(process.execPath, [tsxCli, "src/cli.ts", "execute", request.id,
      "--strict-legacy-revocation"], { cwd: repoRoot, env, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    cli.stderr?.on("data", part => { stderr += part; });
    const finished = new Promise<number | null>((resolve, reject) => {
      cli!.once("error", reject);
      cli!.once("exit", resolve);
    });
    await Promise.race([
      vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 6_000 }),
      finished.then(code => { throw new Error(`CLI exited before the fixture was ready (${code}): ${stderr.trim()}`); })
    ]);
    run(["approval", "policy", "add", "--name", "Stop running CLI fixture",
      "--decision", "deny", "--handle", secret.handle, "--action-kind", "env_command"]);
    const code = await finished;
    expect(code).not.toBe(0);
    expect(stderr).toMatch(/denied by the current policy/i);
    const records = JSON.parse(run(["requests", "--all"])) as Array<{ id: string; state: string }>;
    expect(records.find(item => item.id === request.id)?.state).toBe("failed");
  } finally {
    cli?.kill("SIGKILL");
    await rm(root, { recursive: true, force: true });
  }
}, 20_000);
