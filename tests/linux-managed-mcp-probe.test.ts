import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const source = readFileSync(fileURLToPath(new URL("../scripts/linux-managed-mcp-probe.c", import.meta.url)), "utf8");

describe("native managed MCP probe", () => {
  it("sends valid newline-delimited JSON for fixed MCP requests", () => {
    const messages = [...source.matchAll(/send_line\([^,]+,\s*("(?:\\.|[^"\\])*")\)/g)];
    expect(messages.length).toBeGreaterThanOrEqual(8);
    for (const match of messages) {
      const line = JSON.parse(match[1]) as string;
      expect(line.endsWith("\n")).toBe(true);
      expect(JSON.parse(line).jsonrpc).toBe("2.0");
    }
  });
});
