import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const lockFaults = vi.hoisted(() => ({
  ownerRead: 0,
  markerUnlink: 0,
  lockRmdir: 0
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const denied = () => Object.assign(new Error("simulated Windows sharing violation"), { code: "EPERM" });
  const directMarker = (input: unknown) => typeof input === "string" &&
    /\.s-gw-agent-integrations\.lock[\\/]owner-[^\\/]+\.json$/u.test(input);
  const directLock = (input: unknown) => typeof input === "string" &&
    /\.s-gw-agent-integrations\.lock$/u.test(input);

  return {
    ...actual,
    openSync: (...args: unknown[]) => {
      if (directMarker(args[0]) && lockFaults.ownerRead > 0) {
        lockFaults.ownerRead -= 1;
        throw denied();
      }
      return Reflect.apply(actual.openSync, actual, args);
    },
    unlinkSync: (...args: unknown[]) => {
      if (directMarker(args[0]) && lockFaults.markerUnlink > 0) {
        lockFaults.markerUnlink -= 1;
        throw denied();
      }
      return Reflect.apply(actual.unlinkSync, actual, args);
    },
    rmdirSync: (...args: unknown[]) => {
      if (directLock(args[0]) && lockFaults.lockRmdir > 0) {
        lockFaults.lockRmdir -= 1;
        throw denied();
      }
      return Reflect.apply(actual.rmdirSync, actual, args);
    }
  };
});

import { installAgentIntegrations } from "../src/agent-install.js";

const nativePlatform = process.platform;
const tmpDirs: string[] = [];

afterEach(() => {
  lockFaults.ownerRead = 0;
  lockFaults.markerUnlink = 0;
  lockFaults.lockRmdir = 0;
  vi.restoreAllMocks();
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("Windows agent integration lock cleanup", () => {
  it("retries a sharing violation while reading an abandoned owner", () => {
    const fixture = staleLockFixture();
    lockFaults.ownerRead = 2;

    const result = withWindowsLockErrors(() => installAgentIntegrations(fixture.options));

    expect(result[0]).toMatchObject({ state: "installed", changed: true });
    expect(lockFaults.ownerRead).toBe(0);
    expect(existsSync(fixture.lockPath)).toBe(false);
  });

  it("retries a sharing violation while removing an abandoned marker", () => {
    const fixture = staleLockFixture();
    lockFaults.markerUnlink = 2;

    const result = withWindowsLockErrors(() => installAgentIntegrations(fixture.options));

    expect(result[0]).toMatchObject({ state: "installed", changed: true });
    expect(lockFaults.markerUnlink).toBe(0);
    expect(existsSync(fixture.lockPath)).toBe(false);
  });

  it("retries sharing violations while releasing its own lock", () => {
    const fixture = cleanFixture();
    lockFaults.markerUnlink = 2;
    lockFaults.lockRmdir = 2;

    const result = withWindowsLockErrors(() => installAgentIntegrations(fixture.options));

    expect(result[0]).toMatchObject({ state: "installed", changed: true });
    expect(lockFaults.markerUnlink).toBe(0);
    expect(lockFaults.lockRmdir).toBe(0);
    expect(existsSync(fixture.lockPath)).toBe(false);
  });
});

function cleanFixture() {
  const homeDir = mkdtempSync(path.join(os.tmpdir(), "s-gw-agent-lock-windows-"));
  tmpDirs.push(homeDir);
  const binDir = path.join(homeDir, "bin");
  mkdirSync(binDir, { recursive: true });
  fakeCommand(binDir, "codex");
  fakeCommand(binDir, "s-gw-mcp");

  return {
    lockPath: path.join(homeDir, ".s-gw-agent-integrations.lock"),
    options: {
      homeDir,
      pathEnv: binDir,
      sgwHome: path.join(homeDir, ".s-gw"),
      agentIds: ["codex"],
      env: {
        HOME: homeDir,
        USERPROFILE: homeDir,
        PATH: binDir,
        PATHEXT: process.env.PATHEXT
      },
      platform: nativePlatform,
      skillSourcePath: path.join(process.cwd(), "skills", "s-gw", "SKILL.md")
    }
  };
}

function staleLockFixture() {
  const fixture = cleanFixture();
  const deadProcess = spawnSync(process.execPath, ["-e", ""]);
  expect(deadProcess.status).toBe(0);
  expect(deadProcess.pid).toBeTypeOf("number");
  const owner = {
    pid: deadProcess.pid,
    startedAt: Date.now(),
    token: "abandoned-windows-lock"
  };
  mkdirSync(fixture.lockPath, { mode: 0o700 });
  writeFileSync(
    path.join(fixture.lockPath, `owner-${owner.token}.json`),
    `${JSON.stringify(owner)}\n`,
    { mode: 0o600 }
  );
  return fixture;
}

function fakeCommand(binDir: string, name: string): void {
  const extension = nativePlatform === "win32" ? ".cmd" : "";
  const filePath = path.join(binDir, `${name}${extension}`);
  const contents = nativePlatform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n";
  writeFileSync(filePath, contents, { mode: 0o755 });
  if (nativePlatform !== "win32") chmodSync(filePath, 0o755);
}

function withWindowsLockErrors<T>(body: () => T): T {
  if (nativePlatform === "win32") return body();
  const platform = vi.spyOn(process, "platform", "get").mockReturnValue("win32");
  try {
    return body();
  } finally {
    platform.mockRestore();
  }
}
