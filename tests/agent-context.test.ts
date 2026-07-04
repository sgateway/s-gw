import { describe, expect, it } from "vitest";
import {
  agentNameFromMcpClient,
  detectProcessTreeAgentName,
  detectRuntimeAgentName,
  requestAgentIdentity,
  requestAgentName
} from "../src/agent-context.js";

describe("agent context detection", () => {
  it("uses runtime identity before incidental agent names in request reasons", () => {
    expect(requestAgentName("Run the Claude compatibility test", { CODEX_SHELL: "1" })).toBe("Codex");
  });

  it("detects Codex from the local runtime environment", () => {
    expect(detectRuntimeAgentName({ CODEX_SHELL: "1" })).toBe("Codex");
    expect(detectRuntimeAgentName({ __CFBundleIdentifier: "com.openai.codex" })).toBe("Codex");
  });

  it("uses an explicit s-gw override when a wrapper knows the agent", () => {
    expect(requestAgentName("Local CLI request", { SGW_AGENT_NAME: "opencode" })).toBe("OpenCode");
  });

  it("uses MCP client identity when the request reason is generic", () => {
    expect(
      requestAgentIdentity("Agent requested local secret-backed execution.", {
        mcpClientName: "codex-mcp-client",
        env: { SGW_DISABLE_PROCESS_AGENT_DETECTION: "1" }
      })
    ).toEqual({ name: "Codex", source: "mcp-client" });
  });

  it("keeps generic MCP clients unknown", () => {
    expect(agentNameFromMcpClient("mcp-client")).toBeUndefined();
  });

  it("uses configured identity before MCP client metadata", () => {
    expect(
      requestAgentIdentity("Agent requested local secret-backed execution.", {
        mcpClientName: "Claude Code",
        env: { SGW_AGENT_NAME: "codex" }
      })
    ).toEqual({ name: "Codex", source: "configured" });
  });

  it("detects Codex from the launcher process tree when the reason is generic", () => {
    expect(
      requestAgentName("Agent requested local secret-backed execution.", {
        SGW_AGENT_PROCESS_TREE: "/Applications/Codex.app/Contents/MacOS/Codex Helper"
      })
    ).toBe("Codex");
  });

  it("does not treat generic agent helper process names as known agents", () => {
    expect(detectProcessTreeAgentName({ SGW_AGENT_PROCESS_TREE: "/usr/local/bin/agent-helper" })).toBeUndefined();
  });
});
