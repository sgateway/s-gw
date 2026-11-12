import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import type { GuardRunPreparation } from "../src/guard.js";

vi.mock("../src/linux-sandbox-helpers.js", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/linux-sandbox-helpers.js")>();
  return { ...actual, resolveTrustedLinuxSandboxHelpers: () => ({
    pathEnv: "/usr/bin", bwrap: "/usr/bin/bwrap", socat: "/usr/bin/socat",
    rg: "/usr/bin/rg", which: "/usr/bin/which", bash: "/bin/bash",
    applySeccomp: "/trusted/apply-seccomp"
  }) };
});

import { runAnthropicSandbox } from "../src/anthropic-sandbox.js";

let fixture = "";
const originalPlatform = process.platform;
const originalEnv = { ...process.env };

afterEach(async () => {
  vi.restoreAllMocks();
  Object.defineProperty(process, "platform", { value: originalPlatform });
  process.env = { ...originalEnv };
  if (fixture) await rm(fixture, { recursive: true, force: true });
});

it("uses trusted PATH through the outer wrapper, then restores agent PATH", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-trusted-launch-"));
  const workspace = path.join(fixture, "workspace");
  const fake = path.join(fixture, "fake-path");
  await Promise.all([mkdir(workspace), mkdir(fake)]);
  const marker = path.join(fixture, "fake-helper-ran");
  for (const name of ["which", "bwrap"]) {
    await writeFile(path.join(fake, name), `#!/bin/sh\necho ${name} >> '${marker}'\n`, { mode: 0o755 });
  }
  const agentPath = `${fake}:/usr/bin:/bin`;
  const resultFile = path.join(workspace, "agent-path");
  const agent = path.join(workspace, "agent.mjs");
  await writeFile(agent, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(resultFile)}, process.env.PATH ?? 'missing');`);
  const prepared = { env: { PATH: agentPath }, plan: {
    cwd: workspace, command: process.execPath, args: [agent], agent: { displayName: "Codex" }
  } } as GuardRunPreparation;
  const previousPath = process.env.PATH;
  process.env.SGW_ALLOW_NO_CGROUP = "1";
  Object.defineProperty(process, "platform", { value: "linux" });
  vi.spyOn(SandboxManager, "initialize").mockImplementation(async config => {
    expect(process.env.PATH).toBe("/usr/bin");
    expect(config).toMatchObject({ bwrapPath: "/usr/bin/bwrap", socatPath: "/usr/bin/socat",
      ripgrep: { command: "/usr/bin/rg" }, seccomp: { applyPath: "/trusted/apply-seccomp" } });
  });
  vi.spyOn(SandboxManager, "wrapWithSandbox").mockImplementation(async command => {
    expect(process.env.PATH).toBe("/usr/bin");
    return `bwrap >/dev/null 2>&1; which bash >/dev/null 2>&1; ${command}`;
  });
  vi.spyOn(SandboxManager, "reset").mockResolvedValue(undefined);
  expect(await runAnthropicSandbox(prepared, path.join(fixture, "store"), { trustedLinuxHelpers: true })).toBe(0);
  expect(process.env.PATH).toBe(previousPath);
  expect(await readFile(resultFile, "utf8")).toBe(agentPath);
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
});

it("rejects missing Unix-socket filtering before a trusted isolated launch", async () => {
  fixture = await mkdtemp(path.join(os.tmpdir(), "sgw-trusted-launch-"));
  const workspace = path.join(fixture, "workspace");
  await mkdir(workspace);
  process.env.SGW_ALLOW_NO_CGROUP = "1";
  Object.defineProperty(process, "platform", { value: "linux" });
  vi.spyOn(SandboxManager, "initialize").mockResolvedValue(undefined);
  const check = vi.spyOn(SandboxManager, "checkDependencies").mockImplementation(() => {
    expect(process.env.PATH).toBe("/usr/bin");
    return { errors: [], warnings: ["seccomp not available - unix socket access not restricted"] };
  });
  const wrap = vi.spyOn(SandboxManager, "wrapWithSandbox");
  vi.spyOn(SandboxManager, "reset").mockResolvedValue(undefined);
  const prepared = { env: { PATH: "/usr/bin" }, plan: {
    cwd: workspace, command: process.execPath, args: [], agent: { displayName: "Codex" }
  } } as GuardRunPreparation;
  await expect(runAnthropicSandbox(prepared, path.join(fixture, "store"),
    { trustedLinuxHelpers: true, isolatedAuth: true })).rejects.toThrow("Unix-socket seccomp filter");
  expect(check).toHaveBeenCalledOnce();
  expect(wrap).not.toHaveBeenCalled();
});
