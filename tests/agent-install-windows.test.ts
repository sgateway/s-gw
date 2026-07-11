import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  type AgentIntegrationOptions
} from "../src/agent-install.js";
import { getPackageLayout } from "../src/install.js";

const tmpDirs: string[] = [];

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function testHome(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "s-gw-agent-windows-"));
  tmpDirs.push(dir);
  return dir;
}

function mcpFixture(homeDir: string): string {
  const serverPath = path.join(homeDir, "package", "dist", "mcp-server.js");
  mkdirSync(path.dirname(serverPath), { recursive: true });
  writeFileSync(
    serverPath,
    'process.stdin.resume(); process.stdin.on("end", () => process.stdout.write("mcp-ok"));\n'
  );
  return serverPath;
}

function windowsOptions(
  homeDir: string,
  agentIds: string[]
): AgentIntegrationOptions & { mcpServerPath: string } {
  return {
    homeDir,
    pathEnv: "",
    sgwHome: path.join(homeDir, ".s-gw"),
    agentIds,
    platform: "win32",
    mcpServerPath: mcpFixture(homeDir),
    skillSourcePath: path.join(process.cwd(), "skills", "s-gw", "SKILL.md")
  };
}

describe("Windows managed agent registration", () => {
  it("uses node directly, ignores a stale npm cmd shim, and launches the rendered command", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["claudecode"]);
    const staleBin = path.join(homeDir, "old-npm-prefix");
    mkdirSync(staleBin, { recursive: true });
    writeFileSync(path.join(staleBin, "s-gw-mcp.CMD"), "@exit /b 9\r\n");
    options.pathEnv = staleBin;

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });

    const config = JSON.parse(readFileSync(path.join(homeDir, ".claude.json"), "utf8"));
    const server = config.mcpServers["s-gw"] as { command: string; args: string[] };
    expect(server.command).toBe(process.execPath);
    expect(server.args).toEqual([options.mcpServerPath]);
    expect(server.command.toLowerCase()).not.toContain("s-gw-mcp.cmd");

    const child = spawnSync(server.command, server.args, { input: "", encoding: "utf8", windowsHide: true });
    expect(child.error).toBeUndefined();
    expect(child.status).toBe(0);
    expect(child.stdout).toBe("mcp-ok");

    const second = installAgentIntegrations(options);
    expect(second[0]).toMatchObject({ state: "installed", changed: false });
  });

  it("does not report a directly configured npm cmd shim as connected", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["claudecode"]);
    const shim = path.join(homeDir, "npm", "s-gw-mcp.cmd");
    mkdirSync(path.dirname(shim), { recursive: true });
    writeFileSync(shim, "@exit /b 0\r\n");
    writeFileSync(
      path.join(homeDir, ".claude.json"),
      `${JSON.stringify({ mcpServers: { "s-gw": { command: shim, args: [] } } }, null, 2)}\n`
    );

    const result = installAgentIntegrations(options);
    expect(result[0]).toMatchObject({ state: "conflict", changed: false });
    expect(result[0].reason).toMatch(/no longer available/);
    expect(JSON.parse(readFileSync(path.join(homeDir, ".claude.json"), "utf8")).mcpServers["s-gw"].command).toBe(shim);
  });

  it("honors custom Codex, Gemini CLI, and Copilot homes", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["codex", "geminicli", "copilot"]);
    const codexDir = path.join(homeDir, "custom-codex");
    const geminiRoot = path.join(homeDir, "custom-gemini-root");
    const copilotDir = path.join(homeDir, "custom-copilot");
    options.env = {
      ...process.env,
      CODEX_HOME: codexDir,
      GEMINI_CLI_HOME: geminiRoot,
      COPILOT_HOME: copilotDir
    };

    const installed = installAgentIntegrations(options);
    expect(installed.map((item) => item.state)).toEqual(["installed", "installed", "installed"]);

    expect(existsSync(path.join(codexDir, "config.toml"))).toBe(true);
    expect(existsSync(path.join(codexDir, "skills", "s-gw", "SKILL.md"))).toBe(true);
    expect(existsSync(path.join(geminiRoot, ".gemini", "settings.json"))).toBe(true);
    expect(existsSync(path.join(geminiRoot, ".gemini", "skills", "s-gw", "SKILL.md"))).toBe(true);
    expect(existsSync(path.join(copilotDir, "mcp-config.json"))).toBe(true);
    expect(existsSync(path.join(copilotDir, "skills", "s-gw", "SKILL.md"))).toBe(true);

    expect(existsSync(path.join(homeDir, ".codex", "config.toml"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".gemini", "settings.json"))).toBe(false);
    expect(existsSync(path.join(homeDir, ".copilot", "mcp-config.json"))).toBe(false);

    const status = agentIntegrationStatus(options);
    expect(status.map((item) => item.state)).toEqual(["installed", "installed", "installed"]);
  });

  it("detects a VS Code desktop install without requiring its shell command", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["vscode"]);
    const localAppData = path.join(homeDir, "AppData", "Local");
    const codePath = path.join(localAppData, "Programs", "Microsoft VS Code", "Code.exe");
    mkdirSync(path.dirname(codePath), { recursive: true });
    writeFileSync(codePath, "fixture");
    options.env = {
      HOME: homeDir,
      USERPROFILE: homeDir,
      APPDATA: path.join(homeDir, "AppData", "Roaming"),
      LOCALAPPDATA: localAppData,
      PATH: ""
    };

    const before = agentIntegrationStatus(options);
    expect(before[0]).toMatchObject({ detected: true, state: "available" });

    const installed = installAgentIntegrations(options);
    const configPath = path.join(homeDir, "AppData", "Roaming", "Code", "User", "mcp.json");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(config.servers["s-gw"].command).toBe(process.execPath);
  });

  it("detects an OpenCode desktop install without requiring its shell command", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["opencode"]);
    const localAppData = path.join(homeDir, "AppData", "Local");
    const appPath = path.join(localAppData, "OpenCode", "OpenCode.exe");
    mkdirSync(path.dirname(appPath), { recursive: true });
    writeFileSync(appPath, "fixture");
    options.env = {
      HOME: homeDir,
      USERPROFILE: homeDir,
      LOCALAPPDATA: localAppData,
      PATH: ""
    };

    const before = agentIntegrationStatus(options);
    expect(before[0]).toMatchObject({ detected: true, state: "available" });

    const installed = installAgentIntegrations(options);
    const configPath = path.join(homeDir, ".config", "opencode", "opencode.jsonc");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
    expect(config.mcp["s-gw"].command).toEqual([process.execPath, options.mcpServerPath]);
  });

  it("detects the official Scoop OpenCode desktop install", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["opencode"]);
    const appPath = path.join(homeDir, "scoop", "apps", "opencode-desktop", "current", "OpenCode.exe");
    mkdirSync(path.dirname(appPath), { recursive: true });
    writeFileSync(appPath, "fixture");
    options.env = { HOME: homeDir, USERPROFILE: homeDir, PATH: "" };

    const before = agentIntegrationStatus(options);
    expect(before[0]).toMatchObject({ detected: true, state: "available" });

    const installed = installAgentIntegrations(options);
    expect(installed[0]).toMatchObject({ state: "installed", changed: true });
  });

  it("launches the packaged MCP server and completes a Windows stdio handshake", () => {
    if (process.platform !== "win32") return;
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["claudecode"]);
    options.mcpServerPath = getPackageLayout().mcpPath;
    expect(existsSync(options.mcpServerPath)).toBe(true);

    installAgentIntegrations(options);
    const config = JSON.parse(readFileSync(path.join(homeDir, ".claude.json"), "utf8"));
    const server = config.mcpServers["s-gw"] as {
      command: string;
      args: string[];
      env: Record<string, string>;
    };
    const initialize = `${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "s-gw-windows-test", version: "1.0.0" }
      }
    })}\n`;
    const child = spawnSync(server.command, server.args, {
      input: initialize,
      encoding: "utf8",
      timeout: 10_000,
      windowsHide: true,
      env: { ...process.env, ...server.env }
    });

    expect(child.error).toBeUndefined();
    expect(child.status).toBe(0);
    const response = JSON.parse(child.stdout.trim());
    expect(response).toMatchObject({ id: 1, result: { serverInfo: { name: "s-gw" } } });
  });

  it("treats tracked Windows config paths as case-insensitive", () => {
    const homeDir = testHome();
    const options = windowsOptions(homeDir, ["codex"]);
    installAgentIntegrations(options);

    const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.agents.codex.mcp.path = manifest.agents.codex.mcp.path.toUpperCase();
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const status = agentIntegrationStatus(options);
    expect(status[0]).toMatchObject({ state: "installed", reason: undefined });
  });
});
