import os from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
  spawnSync: vi.fn()
}));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawnSync: native.spawnSync };
});

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: native.existsSync,
    readFileSync: native.readFileSync
  };
});

import { getSgwLoginSessionId } from "../src/paths.js";

const macBootId = "11111111-2222-3333-4444-555555555555";
const linuxBootId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

beforeEach(() => {
  delete process.env.SGW_LOGIN_SESSION_ID;
  vi.spyOn(os, "userInfo").mockReturnValue({
    uid: 501,
    gid: 20,
    username: "test-user",
    homedir: "/Users/test-user",
    shell: "/bin/zsh"
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  native.existsSync.mockReset();
  native.readFileSync.mockReset();
  native.spawnSync.mockReset();
});

describe("native login-session identity", () => {
  it("separates macOS processes in different audit sessions", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("darwin");
    let auditSession = "100025";
    native.spawnSync.mockImplementation((command: string) => {
      if (command === "/usr/sbin/sysctl") {
        return { status: 0, stdout: `${macBootId}\n` };
      }
      if (command === "/usr/bin/id") {
        return { status: 0, stdout: `auid=501\nasid=${auditSession}\n` };
      }
      return { status: 1, stdout: "" };
    });

    const first = getSgwLoginSessionId();
    auditSession = "100026";
    const second = getSgwLoginSessionId();

    expect(first).toBeTruthy();
    expect(second).toBeTruthy();
    expect(second).not.toBe(first);
  });

  it("does not map a detached Linux caller to the user's display or only session", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("linux");
    vi.spyOn(os, "userInfo").mockReturnValue({
      uid: 1000,
      gid: 1000,
      username: "test-user",
      homedir: "/home/test-user",
      shell: "/bin/bash"
    });
    native.existsSync.mockImplementation((input: string) => input === "/usr/bin/loginctl");
    native.readFileSync.mockImplementation((input: string) => {
      if (input === "/proc/self/loginuid") return "4294967295\n";
      if (input === "/proc/self/sessionid") return "77\n";
      if (input === "/proc/sys/kernel/random/boot_id") return `${linuxBootId}\n`;
      throw new Error(`Unexpected read: ${input}`);
    });
    native.spawnSync.mockImplementation((_command: string, args: string[]) => {
      if (args[0] === "show-session" && args[1] === "self") {
        return { status: 1, stdout: "" };
      }
      if (args[0] === "show-user") {
        return { status: 0, stdout: "Display=2\nSessions=2\n" };
      }
      if (args[0] === "show-session" && args[1] === "2") {
        return { status: 0, stdout: "Id=2\nUser=1000\nTimestampMonotonic=1234\n" };
      }
      return { status: 1, stdout: "" };
    });

    expect(getSgwLoginSessionId()).toBeUndefined();
    expect(native.spawnSync.mock.calls.some(([, args]) => args[0] === "show-user")).toBe(false);
  });

  it("fails closed when native session lookup is unavailable", () => {
    vi.spyOn(process, "platform", "get").mockReturnValue("darwin");
    native.spawnSync.mockReturnValue({ status: 1, stdout: "" });

    expect(getSgwLoginSessionId()).toBeUndefined();
    expect(getSgwLoginSessionId()).toBeUndefined();
  });
});
