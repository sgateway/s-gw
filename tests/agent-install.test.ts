import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  uninstallAgentIntegrations
} from "../src/agent-install.js";

const tmpDirs: string[] = [];

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function testHome(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "s-gw-agent-install-"));
  tmpDirs.push(dir);
  return dir;
}

function fakeCommand(homeDir: string, name: string): string {
  const binDir = path.join(homeDir, "bin");
  mkdirSync(binDir, { recursive: true });
  const commandPath = path.join(binDir, process.platform === "win32" ? `${name}.cmd` : name);
  writeFileSync(commandPath, process.platform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  if (process.platform !== "win32") chmodSync(commandPath, 0o755);
  const mcpPath = path.join(binDir, process.platform === "win32" ? "s-gw-mcp.cmd" : "s-gw-mcp");
  if (!existsSync(mcpPath)) {
    writeFileSync(mcpPath, process.platform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    if (process.platform !== "win32") chmodSync(mcpPath, 0o755);
  }
  return binDir;
}

function opts(homeDir: string, pathEnv: string, agentIds?: string[]) {
  return {
    homeDir,
    pathEnv,
    sgwHome: path.join(homeDir, ".s-gw"),
    agentIds,
    skillSourcePath: path.join(process.cwd(), "skills", "s-gw", "SKILL.md")
  };
}

describe("agent integration installation", () => {
  it("connects detected Codex and Claude while preserving unrelated config", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    fakeCommand(homeDir, "claude");

    const codexConfig = path.join(homeDir, ".codex", "config.toml");
    mkdirSync(path.dirname(codexConfig), { recursive: true });
    writeFileSync(codexConfig, 'model = "gpt-5"\n\n[mcp_servers.other]\ncommand = "other-mcp"\n');

    const claudeConfig = path.join(homeDir, ".claude.json");
    writeFileSync(claudeConfig, JSON.stringify({ theme: "dark", mcpServers: { other: { command: "other-mcp" } } }, null, 2));

    const first = installAgentIntegrations(opts(homeDir, binDir));
    const installed = first.filter((item) => item.changed).map((item) => item.agentId).sort();
    expect(installed).toEqual(["claudecode", "codex"]);

    const codexText = readFileSync(codexConfig, "utf8");
    expect(codexText).toContain('model = "gpt-5"');
    expect(codexText).toContain("[mcp_servers.other]");
    expect(codexText).toContain("[mcp_servers.s-gw]");

    const claude = JSON.parse(readFileSync(claudeConfig, "utf8"));
    expect(claude.theme).toBe("dark");
    expect(claude.mcpServers.other.command).toBe("other-mcp");
    expect(claude.mcpServers["s-gw"].command).toBe(path.join(binDir, process.platform === "win32" ? "s-gw-mcp.cmd" : "s-gw-mcp"));

    const packagedSkill = readFileSync(path.join(process.cwd(), "skills", "s-gw", "SKILL.md"), "utf8");
    expect(readFileSync(path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md"), "utf8")).toBe(packagedSkill);
    expect(readFileSync(path.join(homeDir, ".claude", "skills", "s-gw", "SKILL.md"), "utf8")).toBe(packagedSkill);

    const backupDir = path.join(homeDir, ".s-gw", "backups", "agents");
    const backupCount = readdirSync(backupDir).length;
    const second = installAgentIntegrations(opts(homeDir, binDir));
    expect(second.filter((item) => item.changed)).toEqual([]);
    expect(readdirSync(backupDir)).toHaveLength(backupCount);
  });

  it("accepts an existing working absolute s-gw MCP command as already connected", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const mcpPath = path.join(binDir, process.platform === "win32" ? "s-gw-mcp.cmd" : "s-gw-mcp");
    const configPath = path.join(homeDir, ".codex", "config.toml");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(
      configPath,
      `[mcp_servers.s-gw]\ncommand = ${JSON.stringify(mcpPath)}\nargs = []\nenv = { SGW_HOME = "/Users/example/.s-gw", SGW_AGENT_NAME = "Codex" }\n`
    );

    const result = installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    expect(result[0].state).toBe("installed");
    expect(result[0].mcp.state).toBe("existing");
    expect(result[0].skill.state).toBe("installed");
    expect(readFileSync(configPath, "utf8")).toContain(mcpPath);
  });

  it("writes the effective data home and an absolute MCP command", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const sgwHome = path.join(homeDir, "custom-gateway-data");

    installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    const updated = installAgentIntegrations({ ...opts(homeDir, binDir, ["codex"]), sgwHome });
    const config = readFileSync(path.join(homeDir, ".codex", "config.toml"), "utf8");
    expect(updated[0]).toMatchObject({ changed: true, state: "installed" });
    expect(config).toContain(`SGW_HOME = ${JSON.stringify(sgwHome)}`);
    expect(config).toContain(`command = ${JSON.stringify(path.join(binDir, process.platform === "win32" ? "s-gw-mcp.cmd" : "s-gw-mcp"))}`);
    expect(config.match(/\[mcp_servers\.s-gw\]/g)).toHaveLength(1);
  });

  it("does not report a stale absolute MCP command as connected", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const configPath = path.join(homeDir, ".codex", "config.toml");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '[mcp_servers.s-gw]\ncommand = "/missing/s-gw-mcp"\nargs = []\n');

    const result = installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/no longer available/);
    expect(readFileSync(configPath, "utf8")).toContain('/missing/s-gw-mcp');
  });

  it("updates an owned packaged skill without treating the new version as a user conflict", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const skillSourcePath = path.join(homeDir, "packaged-skill.md");
    writeFileSync(skillSourcePath, "# s-gw skill\n\nVersion one.\n");
    const options = { homeDir, pathEnv: binDir, agentIds: ["codex"], skillSourcePath };

    installAgentIntegrations(options);
    writeFileSync(skillSourcePath, "# s-gw skill\n\nVersion two.\n");
    const updated = installAgentIntegrations(options);

    const installedPath = path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md");
    expect(updated[0]).toMatchObject({ changed: true, state: "installed" });
    expect(readFileSync(installedPath, "utf8")).toContain("Version two");
    expect(updated[0].backups.some((backup) => backup.includes("skill"))).toBe(true);
  });

  it("refuses conflicting server entries without partially installing the skill", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "gemini");
    const configPath = path.join(homeDir, ".gemini", "settings.json");
    mkdirSync(path.dirname(configPath), { recursive: true });
    const original = JSON.stringify({ mcpServers: { "s-gw": { command: "not-s-gw" } }, ui: { theme: "ansi" } }, null, 2);
    writeFileSync(configPath, original);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["geminicli"]));
    expect(result[0].state).toBe("conflict");
    expect(result[0].changed).toBe(false);
    expect(readFileSync(configPath, "utf8")).toBe(original);
    expect(existsSync(path.join(homeDir, ".gemini", "skills", "s-gw", "SKILL.md"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".s-gw", "agent-integrations.json"))).toBe(false);
  });

  it("refuses malformed config without creating a backup or rewriting the file", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "cursor");
    const configPath = path.join(homeDir, ".cursor", "mcp.json");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{ "mcpServers": {');

    const result = installAgentIntegrations(opts(homeDir, binDir, ["cursor"]));
    expect(result[0].state).toBe("conflict");
    expect(result[0].reason).toMatch(/not valid JSON/);
    expect(readFileSync(configPath, "utf8")).toBe('{ "mcpServers": {');
    expect(existsSync(path.join(homeDir, ".s-gw"))).toBe(false);
  });

  it("reports malformed ownership as a conflict without taking down agent status", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    writeFileSync(manifestPath, "{ not valid json");

    const status = agentIntegrationStatus(opts(homeDir, binDir, ["codex"]));
    expect(status[0].state).toBe("conflict");
    expect(status[0].reason).toMatch(/Cannot read/);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(existsSync(path.join(homeDir, ".codex", "config.toml"))).toBe(false);
    expect(readFileSync(manifestPath, "utf8")).toBe("{ not valid json");
  });

  it("rejects invalid owned resource fields before using them as paths", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    const malformed = JSON.stringify({
      version: 1,
      agents: {
        codex: {
          updatedAt: "2026-07-11T00:00:00.000Z",
          mcp: { path: 1, kind: "toml-block", fingerprint: "f".repeat(64) }
        }
      }
    });
    writeFileSync(manifestPath, malformed);

    const status = agentIntegrationStatus(opts(homeDir, binDir, ["codex"]));
    expect(status[0]).toMatchObject({ state: "conflict" });
    expect(status[0].reason).toMatch(/unsupported manifest shape/);
    expect(readFileSync(manifestPath, "utf8")).toBe(malformed);
  });

  it("preserves existing config file permissions across install and uninstall", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "gemini");
    const configPath = path.join(homeDir, ".gemini", "settings.json");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, JSON.stringify({ ui: { theme: "dark" } }, null, 2), { mode: 0o640 });
    chmodSync(configPath, 0o640);

    installAgentIntegrations(opts(homeDir, binDir, ["geminicli"]));
    expect(statSync(configPath).mode & 0o777).toBe(0o640);
    const backupDir = path.join(homeDir, ".s-gw", "backups", "agents");
    for (const file of readdirSync(backupDir)) {
      expect(statSync(path.join(backupDir, file)).mode & 0o777).toBe(0o600);
    }
    uninstallAgentIntegrations(opts(homeDir, binDir, ["geminicli"]));
    expect(statSync(configPath).mode & 0o777).toBe(0o640);
    for (const file of readdirSync(backupDir)) {
      expect(statSync(path.join(backupDir, file)).mode & 0o777).toBe(0o600);
    }
  });

  it("rolls back config and ownership when the manifest cannot be written", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    writeFileSync(path.join(homeDir, ".s-gw"), "blocks the manifest directory");

    const result = installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    expect(result[0].state).toBe("conflict");
    expect(result[0].changed).toBe(false);
    expect(existsSync(path.join(homeDir, ".codex", "config.toml"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md"))).toBe(false);

    rmSync(path.join(homeDir, ".s-gw"));
    const status = agentIntegrationStatus(opts(homeDir, binDir, ["codex"]));
    expect(status[0].mcp.owned).toBe(false);
    expect(status[0].skill.owned).toBe(false);
  });

  it("does not detect an agent from a shared or skill-only directory", () => {
    const homeDir = testHome();
    mkdirSync(path.join(homeDir, ".gemini", "skills", "other-skill"), { recursive: true });
    mkdirSync(path.join(homeDir, ".agents", "skills", "shared-skill"), { recursive: true });

    const status = agentIntegrationStatus(opts(homeDir, "", ["geminicli"]));
    expect(status[0].detected).toBe(false);
    expect(status[0].state).toBe("not-detected");
  });

  it("shows a dry run without writing config, backups, skills, or ownership", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "cursor");
    const result = installAgentIntegrations({ ...opts(homeDir, binDir), dryRun: true });
    const cursor = result.find((item) => item.agentId === "cursor");

    expect(cursor?.state).toBe("available");
    expect(cursor?.plannedChanges).toEqual(expect.arrayContaining(["mcp", "skill"]));
    expect(existsSync(path.join(homeDir, ".cursor", "mcp.json"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".cursor", "skills", "s-gw", "SKILL.md"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".s-gw"))).toBe(false);
  });

  it("uninstalls only owned resources and keeps later unrelated changes", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "cursor");
    const configPath = path.join(homeDir, ".cursor", "mcp.json");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, JSON.stringify({ mcpServers: { other: { command: "other-mcp" } }, editor: "vim" }, null, 2));

    installAgentIntegrations(opts(homeDir, binDir, ["cursor"]));
    const edited = JSON.parse(readFileSync(configPath, "utf8"));
    edited.newPreference = true;
    writeFileSync(configPath, JSON.stringify(edited, null, 2));

    const result = uninstallAgentIntegrations(opts(homeDir, binDir, ["cursor"]));
    expect(result[0].changed).toBe(true);
    const remaining = JSON.parse(readFileSync(configPath, "utf8"));
    expect(remaining.mcpServers["s-gw"]).toBeUndefined();
    expect(remaining.mcpServers.other.command).toBe("other-mcp");
    expect(remaining.editor).toBe("vim");
    expect(remaining.newPreference).toBe(true);
    expect(existsSync(path.join(homeDir, ".cursor", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("refuses uninstall when an owned MCP entry was changed", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "gemini");
    installAgentIntegrations(opts(homeDir, binDir, ["geminicli"]));

    const configPath = path.join(homeDir, ".gemini", "settings.json");
    const changed = JSON.parse(readFileSync(configPath, "utf8"));
    changed.mcpServers["s-gw"].command = "custom-wrapper";
    writeFileSync(configPath, JSON.stringify(changed, null, 2));

    const result = uninstallAgentIntegrations(opts(homeDir, binDir, ["geminicli"]));
    expect(result[0].state).toBe("conflict");
    expect(result[0].changed).toBe(false);
    expect(JSON.parse(readFileSync(configPath, "utf8")).mcpServers["s-gw"].command).toBe("custom-wrapper");
    expect(existsSync(path.join(homeDir, ".gemini", "skills", "s-gw", "SKILL.md"))).toBe(true);
  });

  it("rolls back MCP and skill removal when uninstall cannot update ownership", () => {
    if (process.platform === "win32") return;
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    const configPath = path.join(homeDir, ".codex", "config.toml");
    const skillPath = path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md");
    const configBefore = readFileSync(configPath, "utf8");
    const skillBefore = readFileSync(skillPath, "utf8");
    const sgwDir = path.join(homeDir, ".s-gw");

    chmodSync(sgwDir, 0o500);
    let result;
    try {
      result = uninstallAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    } finally {
      chmodSync(sgwDir, 0o700);
    }

    expect(result![0].state).toBe("conflict");
    expect(result![0].changed).toBe(false);
    expect(readFileSync(configPath, "utf8")).toBe(configBefore);
    expect(readFileSync(skillPath, "utf8")).toBe(skillBefore);
    for (const backup of result![0].backups) expect(existsSync(backup)).toBe(true);
    expect(JSON.parse(readFileSync(path.join(sgwDir, "agent-integrations.json"), "utf8")).agents.codex).toBeDefined();
  });

  it("does not claim or remove an identical pre-existing skill", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "claude");
    const skillPath = path.join(homeDir, ".claude", "skills", "s-gw", "SKILL.md");
    mkdirSync(path.dirname(skillPath), { recursive: true });
    writeFileSync(skillPath, readFileSync(path.join(process.cwd(), "skills", "s-gw", "SKILL.md")));

    installAgentIntegrations(opts(homeDir, binDir, ["claudecode"]));
    const removed = uninstallAgentIntegrations(opts(homeDir, binDir, ["claudecode"]));
    expect(removed[0].changed).toBe(true);
    expect(existsSync(skillPath)).toBe(true);
  });

  it("keeps manual profiles snippet-only", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "openclaw");
    const status = agentIntegrationStatus(opts(homeDir, binDir));
    const openclaw = status.find((item) => item.agentId === "openclaw");

    expect(openclaw?.detected).toBe(true);
    expect(openclaw?.state).toBe("manual");
    expect(openclaw?.reason).toMatch(/snippet/i);

    const install = installAgentIntegrations(opts(homeDir, binDir, ["openclaw"]));
    expect(install[0].state).toBe("manual");
    expect(install[0].changed).toBe(false);
  });

  it("wires status, dry-run, install, and uninstall through the CLI", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const tsxBin = path.join(process.cwd(), "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");
    const env = {
      ...process.env,
      HOME: homeDir,
      USERPROFILE: homeDir,
      PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
      SGW_HOME: path.join(homeDir, ".s-gw"),
      SGW_DISABLE_UPDATE_CHECK: "1"
    };

    const dryRun = JSON.parse(execFileSync(tsxBin, ["src/cli.ts", "agent", "install", "codex", "--dry-run"], { cwd: process.cwd(), env, encoding: "utf8" }));
    expect(dryRun.results[0].plannedChanges).toContain("mcp");
    expect(existsSync(path.join(homeDir, ".codex", "config.toml"))).toBe(false);

    execFileSync(tsxBin, ["src/cli.ts", "agent", "install", "codex"], { cwd: process.cwd(), env, encoding: "utf8" });
    const status = JSON.parse(execFileSync(tsxBin, ["src/cli.ts", "agent", "status", "codex"], { cwd: process.cwd(), env, encoding: "utf8" }));
    expect(status.results[0].state).toBe("installed");

    execFileSync(tsxBin, ["src/cli.ts", "agent", "uninstall", "codex"], { cwd: process.cwd(), env, encoding: "utf8" });
    expect(readFileSync(path.join(homeDir, ".codex", "config.toml"), "utf8")).not.toContain("mcp_servers.s-gw");

    const conflictHome = testHome();
    const conflictBin = fakeCommand(conflictHome, "codex");
    const conflictConfig = path.join(conflictHome, ".codex", "config.toml");
    mkdirSync(path.dirname(conflictConfig), { recursive: true });
    writeFileSync(conflictConfig, '[mcp_servers.s-gw]\ncommand = "unrelated-tool"\n');
    const conflict = spawnSync(tsxBin, ["src/cli.ts", "agent", "install", "codex"], {
      cwd: process.cwd(),
      env: {
        ...env,
        HOME: conflictHome,
        USERPROFILE: conflictHome,
        PATH: `${conflictBin}${path.delimiter}${process.env.PATH || ""}`,
        SGW_HOME: path.join(conflictHome, ".s-gw")
      },
      encoding: "utf8",
      shell: process.platform === "win32"
    });
    expect(conflict.status).toBe(1);
    expect(JSON.parse(conflict.stdout)).toMatchObject({ ok: false, results: [{ state: "conflict" }] });
  });

  it("setup connects detected agents unless --no-agents is set", () => {
    const tsxBin = path.join(process.cwd(), "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");
    const runSetup = (homeDir: string, extraArgs: string[]) => {
      const binDir = fakeCommand(homeDir, "codex");
      const env = {
        ...process.env,
        HOME: homeDir,
        USERPROFILE: homeDir,
        PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
        SGW_HOME: path.join(homeDir, ".s-gw"),
        SGW_MASTER_PASSPHRASE: "test-only-passphrase",
        SGW_DISABLE_KEYCHAIN: "1",
        SGW_DISABLE_UPDATE_CHECK: "1"
      };
      return JSON.parse(execFileSync(
        tsxBin,
        ["src/cli.ts", "setup", "--no-service", "--no-menubar", "--no-open-app", ...extraArgs],
        { cwd: process.cwd(), env, encoding: "utf8" }
      ));
    };

    const autoHome = testHome();
    const setup = runSetup(autoHome, []);
    expect(setup.agents.skipped).toBe(false);
    expect(setup.agents.results.find((item: { agentId: string }) => item.agentId === "codex").state).toBe("installed");
    expect(existsSync(path.join(autoHome, ".codex", "config.toml"))).toBe(true);

    const skippedHome = testHome();
    const skipped = runSetup(skippedHome, ["--no-agents"]);
    expect(skipped.agents).toEqual({ skipped: true, results: [] });
    expect(existsSync(path.join(skippedHome, ".codex", "config.toml"))).toBe(false);
  });
});
