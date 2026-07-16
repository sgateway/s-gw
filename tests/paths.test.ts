import { mkdtemp, mkdir, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ensureSgwHome, getSgwHome, getSgwRecoveryHome, getStorePath } from "../src/paths.js";

let testRoot = "";
let outsideRoot = "";
let previousEnv: NodeJS.ProcessEnv;

beforeEach(async () => {
  previousEnv = { ...process.env };
  testRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-paths-root-"));
  outsideRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-paths-outside-"));
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = testRoot;
  process.env.SGW_HOME = path.join(testRoot, "home");
  process.env.SGW_RECOVERY_HOME = path.join(testRoot, "recovery");
});

afterEach(async () => {
  process.env = previousEnv;
  await rm(testRoot, { recursive: true, force: true });
  await rm(outsideRoot, { recursive: true, force: true });
});

describe("test-mode s-gw paths", () => {
  it("uses explicit isolated primary and recovery homes", async () => {
    const home = process.env.SGW_HOME as string;
    const recoveryHome = process.env.SGW_RECOVERY_HOME as string;

    expect(getSgwHome()).toBe(home);
    expect(getSgwRecoveryHome()).toBe(recoveryHome);
    expect(getStorePath()).toBe(path.join(home, "store.json"));

    await ensureSgwHome();
  });

  it("requires both test homes to be explicit", () => {
    delete process.env.SGW_HOME;
    expect(() => getSgwHome()).toThrow(/explicit SGW_HOME/i);

    process.env.SGW_HOME = path.join(testRoot, "home");
    delete process.env.SGW_RECOVERY_HOME;
    expect(() => getSgwRecoveryHome()).toThrow(/explicit SGW_RECOVERY_HOME/i);
  });

  it("requires a temporary test root", () => {
    delete process.env.SGW_TEST_HOME_ROOT;
    expect(() => getSgwHome()).toThrow(/without SGW_TEST_HOME_ROOT/i);
  });

  it("rejects a primary path that escapes the test root", () => {
    process.env.SGW_HOME = path.join(outsideRoot, "home");
    expect(() => getSgwHome()).toThrow(/outside SGW_TEST_HOME_ROOT/i);
  });

  it("rejects a recovery path that escapes the test root", () => {
    process.env.SGW_RECOVERY_HOME = path.join(outsideRoot, "recovery");
    expect(() => getSgwRecoveryHome()).toThrow(/outside SGW_TEST_HOME_ROOT/i);
  });

  it("rejects primary and recovery symlinks that escape the test root", async () => {
    const homeLink = path.join(testRoot, "home-link");
    const recoveryLink = path.join(testRoot, "recovery-link");
    await mkdir(path.join(outsideRoot, "home"));
    await mkdir(path.join(outsideRoot, "recovery"));
    await symlink(path.join(outsideRoot, "home"), homeLink);
    await symlink(path.join(outsideRoot, "recovery"), recoveryLink);

    process.env.SGW_HOME = homeLink;
    expect(() => getSgwHome()).toThrow(/outside SGW_TEST_HOME_ROOT/i);

    process.env.SGW_HOME = path.join(testRoot, "home");
    process.env.SGW_RECOVERY_HOME = recoveryLink;
    expect(() => getSgwRecoveryHome()).toThrow(/outside SGW_TEST_HOME_ROOT/i);
  });

  it("rejects a recovery symlink that resolves inside the primary ledger", async () => {
    const home = path.join(testRoot, "home");
    const recoveryLink = path.join(testRoot, "recovery-link");
    await mkdir(home);
    await symlink(home, recoveryLink);

    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = recoveryLink;
    expect(() => getSgwRecoveryHome()).toThrow(/must be outside the primary ledger/i);
  });

  it("rejects equal and nested primary and recovery homes", () => {
    const home = path.join(testRoot, "home");
    process.env.SGW_HOME = home;

    process.env.SGW_RECOVERY_HOME = home;
    expect(() => getSgwRecoveryHome()).toThrow(/must be outside the primary ledger/i);

    process.env.SGW_RECOVERY_HOME = path.join(home, "recovery");
    expect(() => getSgwRecoveryHome()).toThrow(/must be outside the primary ledger/i);
  });

  it("rejects a dangling home symlink before it can become a write target", async () => {
    const link = path.join(testRoot, "dangling-home-link");
    await symlink(path.join(outsideRoot, "missing-home"), link);

    process.env.SGW_HOME = link;
    expect(() => getSgwHome()).toThrow(/symlinked s-gw test path/i);
  });

  it("checks explicit path arguments too", async () => {
    const outsideHome = path.join(outsideRoot, "home");
    expect(() => getStorePath(outsideHome)).toThrow(/outside SGW_TEST_HOME_ROOT/i);
    await expect(ensureSgwHome(outsideHome)).rejects.toThrow(/outside SGW_TEST_HOME_ROOT/i);
  });
});
