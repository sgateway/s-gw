import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const io = vi.hoisted(() => ({ mkdir: vi.fn(), mkdtemp: vi.fn(), read: vi.fn(), readdir: vi.fn(), rmdir: vi.fn(), write: vi.fn(), spawn: vi.fn() }));
vi.mock("node:fs", async importOriginal => ({
  ...await importOriginal<typeof import("node:fs")>(),
  mkdirSync: io.mkdir, mkdtempSync: io.mkdtemp, readFileSync: io.read, readdirSync: io.readdir, rmdirSync: io.rmdir, writeFileSync: io.write
}));
vi.mock("node:child_process", async importOriginal => ({ ...await importOriginal<typeof import("node:child_process")>(), spawn: io.spawn }));

import { attachLinuxCgroup, killLinuxCgroup, releaseLinuxCgroup, writableCgroupRoot } from "../src/linux-cgroup.js";
import { spawnIsolated } from "../src/process-tree.js";

const platform = process.platform;
const bypass = process.env.SGW_ALLOW_NO_CGROUP;
const root = "/sys/fs/cgroup/acceptance";
const group = root + "/sgw-fixture";

beforeEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(process, "platform", { value: "linux" });
  delete process.env.SGW_ALLOW_NO_CGROUP;
  io.read.mockImplementation(file => file === "/proc/self/cgroup" ? "0::/acceptance\n" : "cpu memory\n");
  io.mkdir.mockImplementation(() => undefined);
  io.rmdir.mockImplementation(() => undefined);
  io.readdir.mockReturnValue([]);
  io.mkdtemp.mockReturnValue(group);
  io.write.mockImplementation(() => undefined);
});
afterEach(() => {
  killLinuxCgroup(987654321);
  vi.useRealTimers();
  vi.restoreAllMocks();
  Object.defineProperty(process, "platform", { value: platform });
  if (bypass === undefined) delete process.env.SGW_ALLOW_NO_CGROUP;
  else process.env.SGW_ALLOW_NO_CGROUP = bypass;
});

describe("Linux cgroup lifecycle", () => {
  it("uses rmdir for probes and removes a killed group's kernel directory", () => {
    expect(writableCgroupRoot()).toBe(root);
    expect(io.rmdir).toHaveBeenCalledWith(root + "/.sgw-probe-" + process.pid);
    expect(attachLinuxCgroup(987654321, root)).toBe(group);
    expect(io.write).toHaveBeenCalledWith(group + "/cgroup.procs", "987654321");
    killLinuxCgroup(987654321);
    expect(io.write).toHaveBeenCalledWith(group + "/cgroup.kill", "1");
    expect(io.rmdir).toHaveBeenCalledWith(group);
  });

  it("retries removal while the kernel is finishing a killed process", async () => {
    vi.useFakeTimers();
    attachLinuxCgroup(987654321, root);
    io.rmdir.mockImplementationOnce(() => { throw Object.assign(new Error("busy"), { code: "EBUSY" }); });
    killLinuxCgroup(987654321);
    await vi.runAllTimersAsync();
    expect(io.rmdir.mock.calls.filter(call => call[0] === group)).toHaveLength(2);
  });

  it("removes the new group when attaching its process fails", () => {
    io.write.mockImplementation(() => { throw new Error("membership denied"); });
    expect(() => attachLinuxCgroup(987654321, root)).toThrow("membership denied");
    expect(io.rmdir).toHaveBeenCalledWith(group);
  });

  it("releases empty nested groups after normal exit without killing background work", () => {
    attachLinuxCgroup(987654321, root);
    io.readdir.mockImplementation(dir => dir === group ? [{ name: "sgw-nested", isDirectory: () => true }, { name: "cgroup.events", isDirectory: () => false }] : []);
    releaseLinuxCgroup(987654321);
    expect(io.rmdir).toHaveBeenCalledWith(group + "/sgw-nested");
    expect(io.rmdir).toHaveBeenCalledWith(group);
    expect(io.write).not.toHaveBeenCalledWith(group + "/cgroup.kill", "1");
  });

  it("retains a populated group for explicit tree termination after its parent exits", () => {
    vi.useFakeTimers();
    attachLinuxCgroup(987654321, root);
    io.rmdir.mockImplementationOnce(() => { throw Object.assign(new Error("busy"), { code: "EBUSY" }); });
    releaseLinuxCgroup(987654321);
    killLinuxCgroup(987654321);
    expect(io.write).toHaveBeenCalledWith(group + "/cgroup.kill", "1");
    vi.clearAllTimers();
  });

  it("rejects missing delegation before launching any child", () => {
    io.mkdir.mockImplementation(() => { throw new Error("permission denied"); });
    expect(() => spawnIsolated("/trusted/tool", [], {})).toThrow("writable cgroup v2");
    expect(io.spawn).not.toHaveBeenCalled();
  });

  it("kills a launched child if membership changes after the preflight", () => {
    const child = { pid: 987654321, kill: vi.fn() };
    io.spawn.mockReturnValue(child);
    io.write.mockImplementation(() => { throw new Error("membership denied"); });
    const kill = vi.spyOn(process, "kill").mockReturnValue(true);
    expect(() => spawnIsolated("/trusted/tool", [], {})).toThrow("membership denied");
    expect(kill).toHaveBeenCalledWith(-child.pid, "SIGKILL");
  });
});
