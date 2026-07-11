import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getAgentCodeGuardPlan, listAgentProfiles, renderAgentMcpSnippet, resolveAgentProfile } from "../src/agents.js";

const defenseClawConnectors = [
  "openclaw",
  "zeptoclaw",
  "claudecode",
  "codex",
  "hermes",
  "cursor",
  "windsurf",
  "geminicli",
  "copilot",
  "openhands",
  "antigravity",
  "opencode",
  "omnigent"
];

describe("agent profiles", () => {
  it("includes DefenseClaw's first-class connector set", () => {
    const profiles = listAgentProfiles();
    const byConnector = new Set(profiles.map((profile) => profile.defenseClawConnector).filter(Boolean));

    for (const name of defenseClawConnectors) {
      expect(byConnector.has(name)).toBe(true);
    }
  });

  it("resolves common agent aliases", () => {
    expect(resolveAgentProfile("claude-code").id).toBe("claudecode");
    expect(resolveAgentProfile("gemini").id).toBe("geminicli");
    expect(resolveAgentProfile("github-copilot-cli").id).toBe("copilot");
    expect(resolveAgentProfile("open-code").id).toBe("opencode");
    expect(resolveAgentProfile("open-hands").id).toBe("openhands");
    expect(resolveAgentProfile("agy").id).toBe("antigravity");
    expect(resolveAgentProfile("omniagent").id).toBe("omnigent");
  });

  it("renders Codex config.toml snippets", () => {
    const snippet = renderAgentMcpSnippet("codex", {
      command: "node",
      args: ["/opt/s-gw/dist/mcp-server.js"],
      env: { SGW_HOME: "/Users/test/.s-gw" }
    });

    expect(snippet).toContain("[mcp_servers.s-gw]");
    expect(snippet).toContain('command = "node"');
    expect(snippet).toContain('args = ["/opt/s-gw/dist/mcp-server.js"]');
    expect(snippet).toContain('SGW_HOME = "/Users/test/.s-gw"');
    expect(snippet).toContain('default_tools_approval_mode = "prompt"');
  });

  it("keeps project MCP registrations explicitly attributed", () => {
    const codexConfig = renderAgentMcpSnippet("codex");
    const claudeConfig = JSON.parse(readFileSync(path.join(process.cwd(), ".mcp.json"), "utf8"));

    expect(codexConfig).toContain('SGW_AGENT_NAME = "Codex"');
    expect(claudeConfig.mcpServers["s-gw"].env.SGW_AGENT_NAME).toBe("Claude Code");
  });

  it("uses the current Codex project skill path from CodeGuard", () => {
    const profile = resolveAgentProfile("codex");
    expect(profile.skills.configPaths).toContain("~/.codex/skills");
    expect(profile.skills.configPaths).toContain("./.agents/skills");
    expect(profile.skills.configPaths).not.toContain("./.codex/skills");

    const plan = getAgentCodeGuardPlan("codex");
    expect(plan.supported).toBe(true);
    expect(plan.route).toBe("agent-skill");
    expect(plan.releaseArtifact).toBe("codeguard-codex.zip");
    expect(plan.installPaths).toContain("./.agents/skills/codeguard");
    expect(plan.notes.join(" ")).toContain(".codex/skills");
  });

  it("renders OpenClaw and ZeptoClaw mcp.servers snippets", () => {
    const openclaw = JSON.parse(renderAgentMcpSnippet("openclaw"));
    const zepto = JSON.parse(renderAgentMcpSnippet("zepto-claw"));

    expect(openclaw.mcp.servers["s-gw"].command).toBe("s-gw-mcp");
    expect(openclaw.mcp.servers["s-gw"].env.SGW_HOME).toBe("~/.s-gw");
    expect(openclaw.mcp.servers["s-gw"].env.SGW_AGENT_NAME).toBe("OpenClaw");
    expect(zepto.mcp.servers["s-gw"].command).toBe("s-gw-mcp");
  });

  it("points Claude Code at .mcp.json, never settings.json", () => {
    // settings.json holds hooks/permissions/env — Claude Code does not read MCP
    // servers from it, so guiding users there silently fails to register s-gw.
    const profile = resolveAgentProfile("claude-code");
    const paths = profile.mcp.configPaths.join(" ");
    expect(paths).not.toContain("settings.json");
    expect(profile.mcp.configPaths).toContain("./.mcp.json");

    const allNotes = profile.mcp.notes.join(" ").toLowerCase();
    expect(allNotes).toContain("claude mcp add");

    // The emitted snippet must be the mcpServers shape .mcp.json expects.
    const snippet = JSON.parse(renderAgentMcpSnippet("claude-code"));
    expect(snippet.mcpServers["s-gw"].command).toBe("s-gw-mcp");
    expect(snippet.mcpServers["s-gw"].env.SGW_HOME).toBe("~/.s-gw");
    expect(snippet.mcpServers["s-gw"].env.SGW_AGENT_NAME).toBe("Claude Code");
  });

  it("renders OpenCode and VS Code-specific shapes", () => {
    const opencode = JSON.parse(renderAgentMcpSnippet("opencode"));
    const vscode = JSON.parse(renderAgentMcpSnippet("vscode"));

    expect(opencode.mcp["s-gw"].type).toBe("local");
    expect(opencode.mcp["s-gw"].command).toEqual(["s-gw-mcp"]);
    expect(opencode.mcp["s-gw"].environment.SGW_AGENT_NAME).toBe("OpenCode");
    expect(resolveAgentProfile("opencode").mcp.writeMode).toBe("safe");
    expect(vscode.servers["s-gw"].type).toBe("stdio");
    expect(vscode.servers["s-gw"].env.SGW_AGENT_NAME).toBe("VS Code / GitHub Copilot Agent Mode");
    expect(resolveAgentProfile("vscode").skills.supported).toBe(true);

    const profile = resolveAgentProfile("opencode");
    expect(profile.defenseClawConnector).toBe("opencode");
    expect(profile.mcp.configPaths).toContain("~/.config/opencode/opencode.json");
    expect(profile.hooks?.kind).toBe("plugin");
  });

  it("renders the complete GitHub Copilot CLI local server shape", () => {
    const copilot = JSON.parse(renderAgentMcpSnippet("copilot"));
    const server = copilot.mcpServers["s-gw"];

    expect(server.type).toBe("local");
    expect(server.command).toBe("s-gw-mcp");
    expect(server.args).toEqual([]);
    expect(server.env.SGW_AGENT_NAME).toBe("GitHub Copilot CLI");
    expect(server.tools).toEqual(["*"]);
  });

  it("profiles DefenseClaw's newer hook and policy connectors without overclaiming", () => {
    const openhands = JSON.parse(renderAgentMcpSnippet("openhands"));
    const antigravity = JSON.parse(renderAgentMcpSnippet("antigravity"));
    const omnigent = resolveAgentProfile("omnigent");

    expect(openhands.mcpServers["s-gw"].command).toBe("s-gw-mcp");
    expect(resolveAgentProfile("openhands").hooks?.configPaths).toContain("~/.openhands/hooks.json");
    expect(antigravity.mcpServers["s-gw"].command).toBe("s-gw-mcp");
    expect(resolveAgentProfile("antigravity").hooks?.configPaths).toEqual(["~/.gemini/config/hooks.json"]);
    expect(resolveAgentProfile("antigravity").hooks?.events).toContain("PreToolUse");

    expect(omnigent.mcp.status).toBe("planned");
    expect(omnigent.hooks?.kind).toBe("policy");
    expect(() => renderAgentMcpSnippet("omnigent")).toThrow(/does not have a supported s-gw MCP snippet/);
  });

  it("exposes profiles through the CLI", () => {
    const tsxCli = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");
    const out = execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "mcp-snippet", "codex"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });

    expect(out).toContain("[mcp_servers.s-gw]");
    expect(out).toContain("s-gw-mcp");
    expect(out).toContain('SGW_AGENT_NAME = "Codex"');

    const planned = execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "show", "omnigent"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });
    expect(JSON.parse(planned).mcpSnippet).toBeNull();
  });

  it("exposes CodeGuard hardening plans through the CLI", () => {
    const tsxCli = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");
    const codex = execFileSync(process.execPath, [tsxCli, "src/cli.ts", "agent", "codeguard-plan", "codex"], {
      cwd: process.cwd(),
      encoding: "utf8"
    });
    const codexPlan = JSON.parse(codex);
    expect(codexPlan.sourceRepo).toBe("https://github.com/cosai-oasis/project-codeguard");
    expect(codexPlan.installPaths).toContain("./.agents/skills/codeguard");

    const claude = getAgentCodeGuardPlan("claude-code");
    expect(claude.route).toBe("plugin-marketplace");
    expect(claude.commands).toContain("/plugin install codeguard-security@project-codeguard");

    const gemini = getAgentCodeGuardPlan("gemini");
    expect(gemini.supported).toBe(false);
    expect(gemini.route).toBe("not-available");
  });

  it("keeps manual profiles out of blanket support claims", () => {
    const profiles = listAgentProfiles();
    const manual = profiles.filter((profile) => profile.mcpStatus === "manual").map((profile) => profile.id).sort();
    expect(manual).toEqual(["antigravity", "hermes", "openclaw", "openhands", "windsurf", "zeptoclaw"]);

    const docs = readFileSync(path.join(process.cwd(), "docs", "agents.md"), "utf8");
    expect(docs).toContain("`Profiled/manual` means");
    expect(docs).toContain("should not be described as fully compatible");

    for (const id of manual) {
      expect(docs).toContain(`| \`${id}\` |`);
      expect(docs).toContain(`| \`${id}\` | ${resolveAgentProfile(id).displayName} | Profiled/manual |`);
    }

    expect(() => resolveAgentProfile("not-real")).toThrow(/known profiles/);
    expect(() => resolveAgentProfile("not-real")).not.toThrow(/supported profiles/);
  });
});
