import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { quote as quoteShell } from "shell-quote";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { whichSync } from "@anthropic-ai/sandbox-runtime/dist/utils/which.js";
import type { GuardRunPreparation } from "../src/guard.js";
import { runAnthropicSandbox } from "../src/anthropic-sandbox.js";
import { resolveTrustedMacSandboxHelpers } from "../src/macos-sandbox-helpers.js";

const originalEnv = { ...process.env };
let fixture = "";

afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...originalEnv };
  if (fixture) await rm(fixture, { recursive: true, force: true });
  fixture = "";
});

it.skipIf(process.platform !== "darwin")("pins the macOS launch helpers to OS files", async () => {
  const helpers = await resolveTrustedMacSandboxHelpers();
  expect(helpers).toMatchObject({
    pathEnv: "/usr/bin", which: "/usr/bin/which", env: "/usr/bin/env",
    sandboxExec: "/usr/bin/sandbox-exec", bash: "/bin/bash"
  });
});

it.skipIf(process.platform !== "darwin")("ignores fake which and env before confinement, then restores agent PATH", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-mac-helper-"));
  const workspace = path.join(fixture, "workspace");
  const fake = path.join(fixture, "fake-bin");
  await Promise.all([mkdir(workspace), mkdir(fake)]);
  const marker = path.join(fixture, "fake-helper-ran");
  for (const name of ["which", "env"]) {
    await writeFile(path.join(fake, name), `#!/bin/sh\nprintf '${name}\\n' >> '${marker}'\nexit 0\n`, { mode: 0o755 });
  }
  const agentPath = `${fake}:/usr/bin:/bin`;
  process.env.PATH = agentPath;
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  const output = path.join(workspace, "agent-path");
  const agent = path.join(workspace, "agent.mjs");
  await writeFile(agent, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(output)}, process.env.PATH ?? 'missing');`);
  const prepared = { env: { PATH: agentPath }, plan: {
    cwd: workspace, command: process.execPath, args: [agent], agent: { displayName: "Codex" }
  } } as GuardRunPreparation;

  vi.spyOn(SandboxManager, "initialize").mockImplementation(async () => {
    expect(process.env.PATH).toBe("/usr/bin");
  });
  vi.spyOn(SandboxManager, "getProxyPort").mockReturnValue(12345);
  vi.spyOn(SandboxManager, "wrapWithSandbox").mockImplementation(async command => {
    expect(process.env.PATH).toBe("/usr/bin");
    expect(whichSync("/bin/bash")).toBe("/bin/bash");
    return quoteShell(["env", "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/bin/bash", "-c", command]);
  });
  vi.spyOn(SandboxManager, "reset").mockResolvedValue(undefined);

  expect(await runAnthropicSandbox(prepared, path.join(fixture, "store"), { trustedMacHelpers: true })).toBe(0);
  expect(process.env.PATH).toBe(agentPath);
  expect(await readFile(output, "utf8")).toBe(agentPath);
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
});

it.skipIf(process.platform !== "darwin")("runs the pinned Anthropic wrapper without fake PATH helpers", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-mac-real-helper-"));
  const workspace = path.join(fixture, "workspace");
  const fake = path.join(fixture, "fake-bin");
  await Promise.all([mkdir(workspace), mkdir(fake)]);
  const marker = path.join(fixture, "fake-helper-ran");
  for (const name of ["which", "env"]) {
    await writeFile(path.join(fake, name), `#!/bin/sh\nprintf '${name}\\n' >> '${marker}'\nexit 0\n`, { mode: 0o755 });
  }
  const agentPath = `${fake}:/usr/bin:/bin`;
  process.env.PATH = agentPath;
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  const output = path.join(workspace, "agent-path");
  const agent = path.join(workspace, "agent.mjs");
  await writeFile(agent, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(output)}, process.env.PATH ?? 'missing');`);
  const prepared = { env: { PATH: agentPath }, plan: {
    cwd: workspace, command: process.execPath, args: [agent], agent: { displayName: "Codex" }
  } } as GuardRunPreparation;

  expect(await runAnthropicSandbox(prepared, path.join(fixture, "store"), {
    trustedMacHelpers: true, strictEgress: true, denyAgentAuth: true, denyKeychain: true
  })).toBe(0);
  expect(process.env.PATH).toBe(agentPath);
  expect(await readFile(output, "utf8")).toBe(agentPath);
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
}, 15_000);

it.skipIf(process.platform !== "darwin")("rejects a wrapper command before sandbox-exec", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-mac-helper-"));
  const workspace = path.join(fixture, "workspace");
  await mkdir(workspace);
  const marker = path.join(fixture, "pre-sandbox-ran");
  const prepared = { env: { PATH: "/usr/bin" }, plan: {
    cwd: workspace, command: process.execPath, args: [], agent: { displayName: "Codex" }
  } } as GuardRunPreparation;
  vi.spyOn(SandboxManager, "initialize").mockResolvedValue(undefined);
  vi.spyOn(SandboxManager, "getProxyPort").mockReturnValue(12345);
  vi.spyOn(SandboxManager, "wrapWithSandbox").mockImplementation(async command =>
    quoteShell(["env", "/bin/bash", "-c", `printf unsafe > '${marker}'`, "/usr/bin/sandbox-exec", "-p",
      "(version 1)(allow default)", "/bin/bash", "-c", command]));
  vi.spyOn(SandboxManager, "reset").mockResolvedValue(undefined);

  await expect(runAnthropicSandbox(prepared, path.join(fixture, "store"), { trustedMacHelpers: true }))
    .rejects.toThrow("wrapper changed its sandbox launch format");
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
});
