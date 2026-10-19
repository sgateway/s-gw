import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { runAnthropicSandbox } from "../src/anthropic-sandbox.js";
import { prepareGuardedRun } from "../src/guard.js";
import { SecretStore } from "../src/store.js";

let root = "";
const originalEnv = { ...process.env };
afterEach(async () => {
  process.env = { ...originalEnv };
  if (root) await rm(root, { recursive: true, force: true });
});

it.skipIf(!["darwin", "linux"].includes(process.platform))("confined agents cannot read temporary SSH credentials kept under s-gw home", async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "sgw-ssh-sandbox-"));
  const workspace = path.join(root, "workspace");
  await mkdir(workspace);
  process.env.SGW_HOME = path.join(root, "store");
  process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
  process.env.SGW_MASTER_PASSPHRASE = randomUUID();
  process.env.SGW_ALLOW_NO_CGROUP = "1";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  process.env.SGW_DISABLE_PROCESS_AGENT_DETECTION = "1";
  const store = new SecretStore();
  await store.init();
  const tempDir = path.join(store.home, "ssh-credential-fixture");
  await mkdir(tempDir, { mode: 0o700 });
  const credential = path.join(tempDir, "identity");
  await writeFile(credential, "synthetic private key fixture", { mode: 0o600 });
  expect(await readFile(credential, "utf8")).toContain("synthetic");
  const alias = path.join(workspace, "ssh-credential-link");
  await symlink(tempDir, alias);

  const probe = path.join(workspace, "probe.mjs");
  await writeFile(probe, `import { readFileSync, writeFileSync } from 'node:fs';
const results = [];
for (const file of [process.env.SGW_TEST_SSH_CREDENTIAL, process.env.SGW_TEST_SSH_ALIAS]) {
  let denied = false;
  try { readFileSync(file); }
  catch (error) { denied = ['EPERM', 'EACCES', 'ENOENT'].includes(error.code); }
  results.push(denied);
}
writeFileSync('result.json', JSON.stringify(results));
`);
  const prepared = await prepareGuardedRun(store, {
    agent: "codex", command: process.execPath, args: [probe], cwd: workspace,
    env: { PATH: process.env.PATH, SGW_TEST_SSH_CREDENTIAL: credential,
      SGW_TEST_SSH_ALIAS: path.join(alias, "identity") }, sandbox: "anthropic"
  });
  expect(await runAnthropicSandbox(prepared, store.home)).toBe(0);
  expect(JSON.parse(await readFile(path.join(workspace, "result.json"), "utf8"))).toEqual([true, true]);
});
