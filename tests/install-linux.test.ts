import { execFileSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  buildSystemdUserUnit,
  installSystemdUserService,
  startInstalledSystemdUserService,
  stopInstalledSystemdUserService,
  systemdUserServicePath,
  systemdUserServiceStatus,
  uninstallSystemdUserService
} from "../src/install.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
let tmpDir = "";

beforeEach(async () => {
  Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-install-"));
  process.env.SGW_HOME = path.join(tmpDir, "ledger home");
  process.env.SGW_RECOVERY_HOME = path.join(tmpDir, "recovery");
  process.env.XDG_CONFIG_HOME = path.join(tmpDir, "config");
  process.env.SGW_FAKE_SYSTEMD_STATE = path.join(tmpDir, "systemd-state.json");
  process.env.SGW_FAKE_SYSTEMD_CAPTURE = path.join(tmpDir, "systemctl.log");
  process.env.SGW_SYSTEMCTL = await installFakeSystemctl();
  process.env.SGW_FAKE_SECRET_DB = path.join(tmpDir, "secret.txt");
  process.env.SGW_SECRET_TOOL = await installFakeSecretTool();
  await writeFile(process.env.SGW_FAKE_SECRET_DB, "synthetic-systemd-unlock", { mode: 0o600 });
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
});

afterEach(async () => {
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  for (const key of [
    "SGW_MASTER_PASSPHRASE",
    "SGW_DISABLE_KEYCHAIN",
    "SGW_SYSTEMCTL",
    "SGW_SECRET_TOOL",
    "SGW_FAKE_SYSTEMD_STATE",
    "SGW_FAKE_SYSTEMD_CAPTURE",
    "SGW_FAKE_SECRET_DB",
    "SGW_FAKE_SECRET_LOOKUP_ERROR",
    "XDG_CONFIG_HOME"
  ]) {
    delete process.env[key];
  }
  await rm(tmpDir, { recursive: true, force: true });
});

describe.sequential("Linux systemd user service", () => {
  it("routes setup and service commands through systemd", async () => {
    await rm(process.env.SGW_FAKE_SECRET_DB!, { force: true });
    const setup = runLinuxCli([
      "setup",
      "--port",
      "9554",
      "--no-open-app",
      "--no-menubar",
      "--no-agents"
    ]);
    expect(setup).toMatchObject({
      ok: true,
      unlock: "generated-keychain-passphrase",
      service: { installed: true, enabled: true, active: true }
    });
    expect(runLinuxCli(["service", "status"])).toMatchObject({ installed: true, active: true });
    expect(runLinuxCli(["stop"]).service).toMatchObject({ installed: true, active: false });
    expect(runLinuxCli(["start", "--port", "9665", "--no-open-app"]).service)
      .toMatchObject({ installed: true, active: true });
    expect(await readFile(systemdUserServicePath(), "utf8")).toContain('"9665"');
    expect(runLinuxCli(["service", "uninstall"])).toMatchObject({ installed: false, active: false });
  });

  it("does not replace an existing unlock secret when Secret Service lookup fails", async () => {
    const existing_passphrase = "synthetic-existing-linux-unlock";
    await writeFile(process.env.SGW_FAKE_SECRET_DB!, existing_passphrase, { mode: 0o600 });
    process.env.SGW_MASTER_PASSPHRASE = existing_passphrase;
    runLinuxCli(["setup", "--no-open-app", "--no-service", "--no-menubar", "--no-agents"]);
    delete process.env.SGW_MASTER_PASSPHRASE;

    const storePath = path.join(process.env.SGW_HOME!, "store.json");
    const ledger_before = await readFile(storePath, "utf8");
    process.env.SGW_FAKE_SECRET_LOOKUP_ERROR = "1";

    expect(() => runLinuxCli([
      "setup",
      "--no-open-app",
      "--no-service",
      "--no-menubar",
      "--no-agents"
    ])).toThrow(/will not generate or replace it/);
    expect(await readFile(process.env.SGW_FAKE_SECRET_DB!, "utf8")).toBe(existing_passphrase);
    expect(await readFile(storePath, "utf8")).toBe(ledger_before);
  });

  it("does not try to launch a browser during headless environment-only setup", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "synthetic-headless-environment-unlock";
    process.env.SGW_DISABLE_KEYCHAIN = "1";

    const setup = runLinuxCli([
      "setup",
      "--no-service",
      "--no-menubar",
      "--no-agents"
    ], { DISPLAY: "", WAYLAND_DISPLAY: "" });
    expect(setup).toMatchObject({
      ok: true,
      unlock: "existing-env"
    });
    expect(setup.opened).toBeUndefined();
  });

  it("installs, starts, stops, and uninstalls a hardened owner-only unit", async () => {
    const installed = await installSystemdUserService({ port: 9443, start: true });
    const unitPath = systemdUserServicePath();
    const unit = await readFile(unitPath, "utf8");

    expect(installed).toMatchObject({ installed: true, loaded: true, enabled: true, active: true });
    expect((await stat(unitPath)).mode & 0o777).toBe(0o600);
    expect(unit).toContain("ExecStart=");
    expect(unit).toContain('"9443"');
    expect(unit).toContain("Type=exec");
    expect(unit).toContain('ExecStartPre="/usr/bin/test" "-x"');
    expect(unit).toContain('ExecStartPre="/usr/bin/test" "-r"');
    expect(unit).toContain('"/usr/bin/env" "-i"');
    expect(unit).toContain("UnsetEnvironment=SGW_MASTER_PASSPHRASE");
    expect(unit).toContain("PartOf=graphical-session.target");
    expect(unit).toContain("WantedBy=graphical-session.target");
    expect(unit).toContain("NoNewPrivileges=true");
    expect(unit).toContain("ProtectSystem=strict");
    expect(unit).toContain("ProtectHome=read-only");
    expect(unit).not.toContain("ProtectKernelModules=true");
    expect(unit).toContain("UMask=0077");
    expect(unit).not.toMatch(/"SGW_MASTER_PASSPHRASE=/);
    expect(unit).not.toContain("synthetic-systemd-unlock");
    expect(unit).not.toContain("SGW_SECRET_TOOL");

    expect(stopInstalledSystemdUserService()).toMatchObject({ installed: true, active: false });
    expect(startInstalledSystemdUserService()).toMatchObject({ installed: true, active: true });
    expect(systemdUserServiceStatus()).toMatchObject({ enabled: true, active: true, mainPid: 4242 });

    const removed = await uninstallSystemdUserService();
    expect(removed).toMatchObject({ installed: false, enabled: false, active: false });
    await expect(lstat(unitPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("restarts an active service after updating its port", async () => {
    await installSystemdUserService({ port: 8718, start: true });
    await writeFile(process.env.SGW_FAKE_SYSTEMD_CAPTURE!, "", { mode: 0o600 });

    const updated = await installSystemdUserService({ port: 8719, start: true });

    expect(updated).toMatchObject({ installed: true, enabled: true, active: true });
    expect(await readFile(systemdUserServicePath(), "utf8")).toContain('"8719"');
    expect(await readFile(process.env.SGW_FAKE_SYSTEMD_CAPTURE!, "utf8")).toBe([
      "daemon-reload",
      "enable s-gw.service",
      "restart s-gw.service",
      "show s-gw.service --property=LoadState --property=UnitFileState --property=ActiveState " +
        "--property=SubState --property=MainPID --no-pager"
    ].join("\n") + "\n");
  });

  it("refuses to persist an environment-only unlock in a service", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "synthetic-environment-only-unlock";

    await expect(installSystemdUserService({ start: true })).rejects.toThrow(/will not persist SGW_MASTER_PASSPHRASE/);
    await expect(lstat(systemdUserServicePath())).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses to replace a symlinked user unit", async () => {
    const unitPath = systemdUserServicePath();
    const target = path.join(tmpDir, "not-a-unit");
    await mkdir(path.dirname(unitPath), { recursive: true });
    await writeFile(target, "leave me alone\n");
    await symlink(target, unitPath);

    await expect(installSystemdUserService()).rejects.toThrow(/unsafe systemd user unit/);
    expect(await readFile(target, "utf8")).toBe("leave me alone\n");
  });

  it("refuses a systemd unit directory writable by other users", async () => {
    const configRoot = process.env.XDG_CONFIG_HOME!;
    await mkdir(configRoot, { recursive: true });
    await chmod(configRoot, 0o777);

    await expect(installSystemdUserService()).rejects.toThrow(/unsafe directory/);
    await expect(lstat(systemdUserServicePath())).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("disables a stale enabled unit even when its service file is missing", async () => {
    await writeFile(process.env.SGW_FAKE_SYSTEMD_STATE!, JSON.stringify({ enabled: true, active: false }));

    expect(await uninstallSystemdUserService()).toMatchObject({ installed: false, active: false });
    expect(await readFile(process.env.SGW_FAKE_SYSTEMD_CAPTURE!, "utf8"))
      .toContain("disable --now s-gw.service");
  });

  it("escapes systemd specifiers and variable markers in paths", () => {
    process.env.SGW_HOME = path.join(tmpDir, "ledger%$home");
    process.env.SGW_RECOVERY_HOME = path.join(tmpDir, "recovery%$home");

    const unit = buildSystemdUserUnit();
    const execStart = unit.split("\n").find((line) => line.startsWith("ExecStart="));
    const writable = unit.split("\n").find((line) => line.startsWith("ReadWritePaths="));
    expect(execStart).toContain("ledger%%$$home");
    expect(execStart).toContain("recovery%%$$home");
    expect(writable).toContain("ledger%%$home");
    expect(writable).toContain("recovery%%$home");
  });
});

async function installFakeSecretTool(): Promise<string> {
  const helper = path.join(tmpDir, "secret-tool");
  await writeFile(helper, `#!/usr/bin/env node
const { existsSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const [command] = process.argv.slice(2);
const db = process.env.SGW_FAKE_SECRET_DB;
if (!db) process.exit(2);
if (command === "store") {
  writeFileSync(db, readFileSync(0, "utf8"), { mode: 0o600 });
  process.exit(0);
}
if (command === "lookup") {
  if (process.env.SGW_FAKE_SECRET_LOOKUP_ERROR === "1") {
    process.stderr.write("synthetic Secret Service lookup failure\\n");
    process.exit(2);
  }
  if (!existsSync(db)) process.exit(1);
  process.stdout.write(readFileSync(db, "utf8") + "\\n");
  process.exit(0);
}
if (command === "clear") {
  rmSync(db, { force: true });
  process.exit(0);
}
process.exit(2);
`);
  await chmod(helper, 0o700);
  return helper;
}

function runLinuxCli(args: string[], extraEnv: NodeJS.ProcessEnv = {}): any {
  const cliPath = path.resolve("src", "cli.ts");
  const script = [
    'Object.defineProperty(process, "platform", { configurable: true, value: "linux" });',
    `process.argv = ${JSON.stringify([process.execPath, cliPath, ...args])};`,
    `await import(${JSON.stringify(pathToFileURL(cliPath).href)});`
  ].join("\n");
  return JSON.parse(execFileSync(process.execPath, [
    "--import",
    "tsx",
    "--input-type=module",
    "--eval",
    script
  ], {
    cwd: process.cwd(),
    env: { ...process.env, ...extraEnv },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }));
}

async function installFakeSystemctl(): Promise<string> {
  const helper = path.join(tmpDir, "systemctl");
  await writeFile(helper, `#!/usr/bin/env node
const { existsSync, readFileSync, writeFileSync, appendFileSync } = require("node:fs");
const args = process.argv.slice(2);
if (args.shift() !== "--user") process.exit(2);
const statePath = process.env.SGW_FAKE_SYSTEMD_STATE;
const capture = process.env.SGW_FAKE_SYSTEMD_CAPTURE;
if (!statePath || !capture) process.exit(2);
appendFileSync(capture, args.join(" ") + "\\n");
const state = existsSync(statePath)
  ? JSON.parse(readFileSync(statePath, "utf8"))
  : { enabled: false, active: false };
const command = args[0];
if (command === "enable") {
  state.enabled = true;
  if (args.includes("--now")) state.active = true;
} else if (command === "disable") {
  state.enabled = false;
  if (args.includes("--now")) state.active = false;
} else if (command === "start" || command === "restart") {
  state.active = true;
} else if (command === "stop") {
  state.active = false;
} else if (command === "show") {
  process.stdout.write([
    "LoadState=loaded",
    "UnitFileState=" + (state.enabled ? "enabled" : "disabled"),
    "ActiveState=" + (state.active ? "active" : "inactive"),
    "SubState=" + (state.active ? "running" : "dead"),
    "MainPID=" + (state.active ? "4242" : "0")
  ].join("\\n") + "\\n");
  process.exit(0);
}
writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
`);
  await chmod(helper, 0o700);
  return helper;
}
