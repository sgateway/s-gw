import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import { afterEach, describe, expect, it } from "vitest";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  uninstallAgentIntegrations
} from "../src/agent-install.js";
import { getPackageLayout } from "../src/install.js";

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
    env: {
      HOME: homeDir,
      USERPROFILE: homeDir,
      APPDATA: path.join(homeDir, "AppData", "Roaming"),
      XDG_CONFIG_HOME: path.join(homeDir, ".config"),
      PATH: pathEnv,
      PATHEXT: process.env.PATHEXT
    },
    skillSourcePath: path.join(process.cwd(), "skills", "s-gw", "SKILL.md")
  };
}

function vscodeConfigPath(homeDir: string): string {
  if (process.platform === "win32") {
    return path.join(homeDir, "AppData", "Roaming", "Code", "User", "mcp.json");
  }
  if (process.platform === "darwin") {
    return path.join(homeDir, "Library", "Application Support", "Code", "User", "mcp.json");
  }
  return path.join(homeDir, ".config", "Code", "User", "mcp.json");
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
    if (process.platform === "win32") {
      expect(claude.mcpServers["s-gw"].command).toBe(process.execPath);
      expect(claude.mcpServers["s-gw"].args).toEqual([getPackageLayout().mcpPath]);
    } else {
      expect(claude.mcpServers["s-gw"].command).toBe(path.join(binDir, "s-gw-mcp"));
    }

    const packagedSkill = readFileSync(path.join(process.cwd(), "skills", "s-gw", "SKILL.md"), "utf8");
    expect(readFileSync(path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md"), "utf8")).toBe(packagedSkill);
    expect(readFileSync(path.join(homeDir, ".claude", "skills", "s-gw", "SKILL.md"), "utf8")).toBe(packagedSkill);

    const backupDir = path.join(homeDir, ".s-gw", "backups", "agents");
    const backupCount = readdirSync(backupDir).length;
    const second = installAgentIntegrations(opts(homeDir, binDir));
    expect(second.filter((item) => item.changed)).toEqual([]);
    expect(readdirSync(backupDir)).toHaveLength(backupCount);
  });

  it("installs the complete GitHub Copilot CLI local server entry", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "copilot");

    const result = installAgentIntegrations(opts(homeDir, binDir, ["copilot"]));
    const config = JSON.parse(readFileSync(path.join(homeDir, ".copilot", "mcp-config.json"), "utf8"));
    const server = config.mcpServers["s-gw"];

    expect(result[0]).toMatchObject({ state: "installed", changed: true });
    expect(server.type).toBe("local");
    if (process.platform === "win32") {
      expect(server.command).toBe(process.execPath);
      expect(server.args).toHaveLength(1);
      expect(server.args[0]).toMatch(/[\\/]dist[\\/]mcp-server\.js$/);
    } else {
      expect(server.command).toBe(path.join(binDir, "s-gw-mcp"));
      expect(server.args).toEqual([]);
    }
    expect(server.env.SGW_AGENT_NAME).toBe("GitHub Copilot CLI");
    expect(server.tools).toEqual(["*"]);
  });

  it("does not accept an incomplete unowned GitHub Copilot CLI entry", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "copilot");
    const configPath = path.join(homeDir, ".copilot", "mcp-config.json");
    const command = process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp");
    const args = process.platform === "win32" ? [getPackageLayout().mcpPath] : [];
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, `${JSON.stringify({ mcpServers: { "s-gw": { command, args } } }, null, 2)}\n`);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["copilot"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/complete GitHub Copilot CLI/);
    expect(existsSync(path.join(homeDir, ".copilot", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("upgrades an unchanged Copilot entry owned by the earlier installer", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "copilot");
    const configPath = path.join(homeDir, ".copilot", "mcp-config.json");
    const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
    const command = process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp");
    const args = process.platform === "win32" ? [getPackageLayout().mcpPath] : [];
    const env = {
      SGW_HOME: path.join(homeDir, ".s-gw"),
      SGW_AGENT_NAME: "GitHub Copilot CLI"
    };
    const oldEntry = { command, args, env };
    const canonicalEntry = { args, command, env: { SGW_AGENT_NAME: env.SGW_AGENT_NAME, SGW_HOME: env.SGW_HOME } };
    const fingerprint = createHash("sha256").update(JSON.stringify(canonicalEntry)).digest("hex");
    mkdirSync(path.dirname(configPath), { recursive: true });
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    writeFileSync(configPath, `${JSON.stringify({ mcpServers: { "s-gw": oldEntry } }, null, 2)}\n`);
    writeFileSync(manifestPath, `${JSON.stringify({
      version: 1,
      agents: {
        copilot: {
          mcp: { path: configPath, kind: "json-entry", fingerprint },
          updatedAt: "2026-07-11T00:00:00.000Z"
        }
      }
    }, null, 2)}\n`);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["copilot"]));
    const updated = JSON.parse(readFileSync(configPath, "utf8")).mcpServers["s-gw"];
    expect(result[0]).toMatchObject({ state: "installed", changed: true });
    expect(updated.type).toBe("local");
    expect(updated.tools).toEqual(["*"]);
  });

  it("accepts Copilot's stdio transport alias when tools are selected", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "copilot");
    const configPath = path.join(homeDir, ".copilot", "mcp-config.json");
    const command = process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp");
    const args = process.platform === "win32" ? [getPackageLayout().mcpPath] : [];
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, `${JSON.stringify({
      mcpServers: { "s-gw": { type: "stdio", command, args, tools: ["*"] } }
    }, null, 2)}\n`);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["copilot"]));
    const unchanged = JSON.parse(readFileSync(configPath, "utf8")).mcpServers["s-gw"];
    expect(result[0]).toMatchObject({ state: "installed", mcp: { state: "existing" } });
    expect(unchanged.type).toBe("stdio");
  });

  it("installs and removes OpenCode without stripping JSONC comments", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(
      configPath,
      '{\n  // keep this user note\n  "$schema": "https://opencode.ai/config.json",\n  "mcp": {\n    "other": { "type": "local", "command": ["other-mcp"], },\n  },\n}\n'
    );

    const options = opts(homeDir, binDir, ["opencode"]);
    const installed = installAgentIntegrations(options);
    const afterInstall = readFileSync(configPath, "utf8");
    const parsed = parseJsonc(afterInstall) as Record<string, any>;

    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(afterInstall).toContain("// keep this user note");
    expect(parsed.mcp.other.command).toEqual(["other-mcp"]);
    expect(parsed.mcp["s-gw"]).toMatchObject({ type: "local", enabled: true });
    expect(parsed.mcp["s-gw"].command[0]).toBe(
      process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp")
    );
    expect(existsSync(path.join(homeDir, ".config", "opencode", "skills", "s-gw", "SKILL.md"))).toBe(true);

    const backupCount = readdirSync(path.join(homeDir, ".s-gw", "backups", "agents")).length;
    const second = installAgentIntegrations(options);
    expect(second[0]).toMatchObject({ state: "installed", changed: false });
    expect(readdirSync(path.join(homeDir, ".s-gw", "backups", "agents"))).toHaveLength(backupCount);

    const removed = uninstallAgentIntegrations(options);
    const afterRemove = readFileSync(configPath, "utf8");
    const remaining = parseJsonc(afterRemove) as Record<string, any>;
    expect(removed[0].changed).toBe(true);
    expect(afterRemove).toContain("// keep this user note");
    expect(remaining.mcp.other.command).toEqual(["other-mcp"]);
    expect(remaining.mcp["s-gw"]).toBeUndefined();
  });

  it("installs and removes VS Code from the default user profile", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "code");
    const configPath = vscodeConfigPath(homeDir);
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(
      configPath,
      '{\n  // default profile MCP servers\n  "servers": {\n    "other": { "type": "stdio", "command": "other-mcp", },\n  },\n}\n'
    );

    const options = opts(homeDir, binDir, ["vscode"]);
    const installed = installAgentIntegrations(options);
    const afterInstall = readFileSync(configPath, "utf8");
    const parsed = parseJsonc(afterInstall) as Record<string, any>;

    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(afterInstall).toContain("// default profile MCP servers");
    expect(parsed.servers.other.command).toBe("other-mcp");
    expect(parsed.servers["s-gw"].type).toBe("stdio");
    expect(parsed.servers["s-gw"].command).toBe(
      process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp")
    );
    expect(existsSync(path.join(homeDir, ".agents", "skills", "s-gw", "SKILL.md"))).toBe(true);

    const second = installAgentIntegrations(options);
    expect(second[0]).toMatchObject({ state: "installed", changed: false });

    const removed = uninstallAgentIntegrations(options);
    const afterRemove = readFileSync(configPath, "utf8");
    const remaining = parseJsonc(afterRemove) as Record<string, any>;
    expect(removed[0].changed).toBe(true);
    expect(afterRemove).toContain("// default profile MCP servers");
    expect(remaining.servers.other.command).toBe("other-mcp");
    expect(remaining.servers["s-gw"]).toBeUndefined();
    expect(existsSync(path.join(homeDir, ".agents", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("does not accept a non-stdio VS Code MCP entry", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "code");
    const configPath = vscodeConfigPath(homeDir);
    const command = process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp");
    const args = process.platform === "win32" ? [getPackageLayout().mcpPath] : [];
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(
      configPath,
      `${JSON.stringify({ servers: { "s-gw": { type: "http", command, args } } }, null, 2)}\n`
    );

    const result = installAgentIntegrations(opts(homeDir, binDir, ["vscode"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/valid VS Code stdio/);
    expect(existsSync(path.join(homeDir, ".agents", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("detects the macOS VS Code app when the code shell command is absent", () => {
    if (process.platform !== "darwin") return;
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "unrelated-tool");
    mkdirSync(path.join(homeDir, "Applications", "Visual Studio Code.app"), { recursive: true });
    const options = opts(homeDir, binDir, ["vscode"]);

    const status = agentIntegrationStatus(options);
    expect(status[0]).toMatchObject({ detected: true, state: "available" });

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(existsSync(vscodeConfigPath(homeDir))).toBe(true);
  });

  it("detects the macOS OpenCode app when its shell command is absent", () => {
    if (process.platform !== "darwin") return;
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "unrelated-tool");
    mkdirSync(path.join(homeDir, "Applications", "OpenCode.app"), { recursive: true });
    const options = opts(homeDir, binDir, ["opencode"]);

    const status = agentIntegrationStatus(options);
    expect(status[0]).toMatchObject({ detected: true, state: "available" });

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(existsSync(path.join(homeDir, ".config", "opencode", "opencode.jsonc"))).toBe(true);
  });

  it("removes only the owned OpenCode entry and preserves comments in its parent", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{\n  // keep schema\n  "$schema": "https://opencode.ai/config.json"\n}\n');
    const options = opts(homeDir, binDir, ["opencode"]);

    installAgentIntegrations(options);
    const installed = readFileSync(configPath, "utf8");
    writeFileSync(configPath, installed.replace('"mcp": {', '"mcp": {\n    // keep this MCP note'));
    uninstallAgentIntegrations(options);

    const text = readFileSync(configPath, "utf8");
    const parsed = parseJsonc(text) as Record<string, unknown>;
    expect(text).toContain("// keep schema");
    expect(text).toContain("// keep this MCP note");
    expect(parsed.mcp).toEqual({});
  });

  it("does not remove a replacement entry from an s-gw-created OpenCode parent", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    const options = opts(homeDir, binDir, ["opencode"]);

    installAgentIntegrations(options);
    writeFileSync(
      configPath,
      '{\n  "mcp": {\n    "other": { "type": "local", "command": ["other-mcp"] }\n  }\n}\n'
    );

    const removed = uninstallAgentIntegrations(options);
    const remaining = parseJsonc(readFileSync(configPath, "utf8")) as Record<string, any>;
    expect(removed[0].changed).toBe(true);
    expect(remaining.mcp.other.command).toEqual(["other-mcp"]);
  });

  it("honors OpenCode's custom config file", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, "custom", "my-opencode.jsonc");
    const options = opts(homeDir, binDir, ["opencode"]);
    options.env.OPENCODE_CONFIG = configPath;

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(existsSync(configPath)).toBe(true);
    expect(existsSync(path.join(homeDir, ".config", "opencode", "skills", "s-gw", "SKILL.md"))).toBe(true);
    expect(existsSync(path.join(homeDir, ".config", "opencode", "opencode.jsonc"))).toBe(false);
  });

  it("uses OpenCode's higher-priority custom config directory", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const lowerPriority = path.join(homeDir, "custom", "my-opencode.jsonc");
    const configDir = path.join(homeDir, "custom-opencode-dir");
    const configPath = path.join(configDir, "opencode.json");
    mkdirSync(configDir, { recursive: true });
    writeFileSync(configPath, '{ "theme": "dark" }\n');
    const options = opts(homeDir, binDir, ["opencode"]);
    options.env.OPENCODE_CONFIG = lowerPriority;
    options.env.OPENCODE_CONFIG_DIR = configDir;

    const installed = installAgentIntegrations(options);
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(config.theme).toBe("dark");
    expect(config.mcp["s-gw"].type).toBe("local");
    expect(existsSync(path.join(configDir, "skills", "s-gw", "SKILL.md"))).toBe(true);
    expect(existsSync(lowerPriority)).toBe(false);
  });

  it("creates OpenCode config inside OPENCODE_CONFIG_DIR when used alone", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configDir = path.join(homeDir, "isolated-opencode");
    const options = opts(homeDir, binDir, ["opencode"]);
    options.env.OPENCODE_CONFIG_DIR = configDir;

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(existsSync(path.join(configDir, "opencode.jsonc"))).toBe(true);
    expect(existsSync(path.join(configDir, "skills", "s-gw", "SKILL.md"))).toBe(true);
  });

  it("refuses a disabled OpenCode MCP entry instead of reporting it connected", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    const command = process.platform === "win32"
      ? [process.execPath, getPackageLayout().mcpPath]
      : [path.join(binDir, "s-gw-mcp")];
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, `${JSON.stringify({
      mcp: { "s-gw": { type: "local", command, enabled: false } }
    }, null, 2)}\n`);

    const result = installAgentIntegrations(opts(homeDir, binDir, ["opencode"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/disabled/);
    expect(existsSync(path.join(homeDir, ".config", "opencode", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("refuses malformed OpenCode JSONC without a partial skill install", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "opencode");
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(configPath, '{ "mcp": { // unfinished\n');

    const result = installAgentIntegrations(opts(homeDir, binDir, ["opencode"]));
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/not valid JSONC/);
    expect(readFileSync(configPath, "utf8")).toBe('{ "mcp": { // unfinished\n');
    expect(existsSync(path.join(homeDir, ".config", "opencode", "skills", "s-gw", "SKILL.md"))).toBe(false);
  });

  it("accepts an existing working absolute s-gw MCP command as already connected", () => {
    const homeDir = testHome();
    const binDir = fakeCommand(homeDir, "codex");
    const mcpPath = process.platform === "win32" ? getPackageLayout().mcpPath : path.join(binDir, "s-gw-mcp");
    const command = process.platform === "win32" ? process.execPath : mcpPath;
    const args = process.platform === "win32" ? [mcpPath] : [];
    const configPath = path.join(homeDir, ".codex", "config.toml");
    mkdirSync(path.dirname(configPath), { recursive: true });
    writeFileSync(
      configPath,
      `[mcp_servers.s-gw]\ncommand = ${JSON.stringify(command)}\nargs = ${JSON.stringify(args)}\nenv = { SGW_HOME = "/Users/example/.s-gw", SGW_AGENT_NAME = "Codex" }\n`
    );

    const result = installAgentIntegrations(opts(homeDir, binDir, ["codex"]));
    expect(result[0].state).toBe("installed");
    expect(result[0].mcp.state).toBe("existing");
    expect(result[0].skill.state).toBe("installed");
    expect(readFileSync(configPath, "utf8")).toContain(JSON.stringify(mcpPath));
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
    expect(config).toContain(`command = ${JSON.stringify(process.platform === "win32" ? process.execPath : path.join(binDir, "s-gw-mcp"))}`);
    if (process.platform === "win32") expect(config).toContain(`args = ${JSON.stringify([getPackageLayout().mcpPath])}`);
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
    if (process.platform === "win32") return;
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
    const tsxCli = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");
    const env = {
      ...process.env,
      HOME: homeDir,
      USERPROFILE: homeDir,
      PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
      SGW_HOME: path.join(homeDir, ".s-gw"),
      SGW_DISABLE_UPDATE_CHECK: "1"
    };

    const dryRun = JSON.parse(execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "install", "codex", "--dry-run"], { cwd: process.cwd(), env, encoding: "utf8" }));
    expect(dryRun.results[0].plannedChanges).toContain("mcp");
    expect(existsSync(path.join(homeDir, ".codex", "config.toml"))).toBe(false);

    execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "install", "codex"], { cwd: process.cwd(), env, encoding: "utf8" });
    const status = JSON.parse(execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "status", "codex"], { cwd: process.cwd(), env, encoding: "utf8" }));
    expect(status.results[0].state).toBe("installed");

    execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "uninstall", "codex"], { cwd: process.cwd(), env, encoding: "utf8" });
    expect(readFileSync(path.join(homeDir, ".codex", "config.toml"), "utf8")).not.toContain("mcp_servers.s-gw");

    const conflictHome = testHome();
    const conflictBin = fakeCommand(conflictHome, "codex");
    const conflictConfig = path.join(conflictHome, ".codex", "config.toml");
    mkdirSync(path.dirname(conflictConfig), { recursive: true });
    writeFileSync(conflictConfig, '[mcp_servers.s-gw]\ncommand = "unrelated-tool"\n');
    const conflict = spawnSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "install", "codex"], {
      cwd: process.cwd(),
      env: {
        ...env,
        HOME: conflictHome,
        USERPROFILE: conflictHome,
        PATH: `${conflictBin}${path.delimiter}${process.env.PATH || ""}`,
        SGW_HOME: path.join(conflictHome, ".s-gw")
      },
      encoding: "utf8"
    });
    expect(conflict.status).toBe(1);
    expect(JSON.parse(conflict.stdout)).toMatchObject({ ok: false, results: [{ state: "conflict" }] });
  });

  it("setup connects detected agents unless --no-agents is set", () => {
    const tsxCli = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");
    const runSetup = (homeDir: string, extraArgs: string[]) => {
      const binDir = fakeCommand(homeDir, "codex");
      fakeCommand(homeDir, "opencode");
      fakeCommand(homeDir, "code");
      const env = {
        ...process.env,
        HOME: homeDir,
        USERPROFILE: homeDir,
        APPDATA: path.join(homeDir, "AppData", "Roaming"),
        XDG_CONFIG_HOME: path.join(homeDir, ".config"),
        PATH: `${binDir}${path.delimiter}${process.env.PATH || ""}`,
        SGW_HOME: path.join(homeDir, ".s-gw"),
        SGW_MASTER_PASSPHRASE: "test-only-passphrase",
        SGW_DISABLE_KEYCHAIN: "1",
        SGW_DISABLE_UPDATE_CHECK: "1"
      };
      return JSON.parse(execFileSync(
        process.execPath,
        [tsxCli, "src/cli.ts", "setup", "--no-service", "--no-menubar", "--no-open-app", ...extraArgs],
        { cwd: process.cwd(), env, encoding: "utf8" }
      ));
    };

    const autoHome = testHome();
    const setup = runSetup(autoHome, []);
    expect(setup.agents.skipped).toBe(false);
    expect(setup.agents.results.find((item: { agentId: string }) => item.agentId === "codex").state).toBe("installed");
    expect(setup.agents.results.find((item: { agentId: string }) => item.agentId === "opencode").state).toBe("installed");
    expect(setup.agents.results.find((item: { agentId: string }) => item.agentId === "vscode").state).toBe("installed");
    expect(existsSync(path.join(autoHome, ".codex", "config.toml"))).toBe(true);
    expect(existsSync(path.join(autoHome, ".config", "opencode", "opencode.jsonc"))).toBe(true);
    expect(existsSync(vscodeConfigPath(autoHome))).toBe(true);

    const skippedHome = testHome();
    const skipped = runSetup(skippedHome, ["--no-agents"]);
    expect(skipped.agents).toEqual({ skipped: true, results: [] });
    expect(existsSync(path.join(skippedHome, ".codex", "config.toml"))).toBe(false);
    expect(existsSync(path.join(skippedHome, ".config", "opencode", "opencode.jsonc"))).toBe(false);
    expect(existsSync(vscodeConfigPath(skippedHome))).toBe(false);
  });
});
