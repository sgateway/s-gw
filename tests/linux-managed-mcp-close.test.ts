import { describe, expect, it, vi } from "vitest";
import { closeLinuxManagedMcpResources } from "../src/linux-managed-mcp.js";

describe("Linux managed MCP teardown", () => {
  it("closes root control after a failed agent stop while MCP cleanup is pending", async () => {
    const events: string[] = [];
    const stopError = new Error("root stop rejected");
    let finishMcp: (() => void) | undefined;
    const mcpClosed = new Promise<void>(resolve => { finishMcp = resolve; });
    const stop = vi.fn(async () => { events.push("stop"); throw stopError; });
    const mcp = { close: vi.fn(async () => {
      events.push("mcp close");
      await mcpClosed;
      events.push("mcp closed");
    }) };
    const control = { close: vi.fn(async () => {
      events.push("control close");
      finishMcp!();
    }) };

    await expect(closeLinuxManagedMcpResources(stop, mcp, control)).rejects.toMatchObject({
      errors: [stopError]
    });
    expect(events).toEqual(["stop", "mcp close", "control close", "mcp closed"]);
    expect(control.close).toHaveBeenCalledOnce();
  });

  it("waits for a successful agent stop before closing root control", async () => {
    const events: string[] = [];
    let finishStop: (() => void) | undefined;
    const stopped = new Promise<void>(resolve => { finishStop = resolve; });
    const stop = vi.fn(async () => { events.push("stop"); await stopped; events.push("stopped"); });
    const mcp = { close: vi.fn(async () => { events.push("mcp close"); }) };
    const relay = { close: vi.fn(async () => { events.push("relay close"); }) };
    const control = { close: vi.fn(async () => { events.push("control close"); }) };

    const teardown = closeLinuxManagedMcpResources(stop, mcp, control, relay);
    await vi.waitFor(() => expect(events).toContain("relay close"));
    expect(events).toEqual(["stop", "mcp close", "relay close"]);
    finishStop!();
    await teardown;
    expect(events).toEqual(["stop", "mcp close", "relay close", "stopped", "control close"]);
  });
});
