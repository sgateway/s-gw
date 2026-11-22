import { describe, expect, it } from "vitest";
import { LongRuns, foregroundBudgetMs } from "../src/mcp-long-run.js";

const later = <T>(ms: number, value: T) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));
const failing = (ms: number, message: string) => new Promise<never>((_, reject) => setTimeout(() => reject(new Error(message)), ms));

describe("long MCP executions", () => {
  it("answers directly when the work finishes inside the budget", async () => {
    const runs = new LongRuns<string>(200);
    expect(await runs.start("quick", () => later(10, "done"))).toEqual({ done: true, value: "done" });
  });

  it("hands out a run id when the work outlives the budget and delivers the result later", async () => {
    const runs = new LongRuns<string>(60);
    const first = await runs.start("deploy", () => later(200, "deployed"));
    expect(first.done).toBe(false);
    if (first.done) return;
    expect(first.runId).toMatch(/^run_[A-Za-z0-9_-]{16}$/);
    expect(first.label).toBe("deploy");

    const early = await runs.wait(first.runId, 20);
    expect(early.done).toBe(false);

    let result = await runs.wait(first.runId);
    while (!result.done) result = await runs.wait(first.runId);
    expect(result).toEqual({ done: true, value: "deployed" });
    // a repeated call after a lost answer still gets the result
    expect(await runs.wait(first.runId)).toEqual({ done: true, value: "deployed" });
  });

  it("runs the work once, however often the result is asked for", async () => {
    const runs = new LongRuns<number>(40);
    let started = 0;
    const first = await runs.start("once", () => { started += 1; return later(120, 7); });
    expect(first.done).toBe(false);
    if (first.done) return;
    await runs.wait(first.runId, 10);
    let result = await runs.wait(first.runId);
    while (!result.done) result = await runs.wait(first.runId);
    expect(started).toBe(1);
  });

  it("reports a failure that happens after the first answer", async () => {
    const runs = new LongRuns<string>(40);
    const first = await runs.start("broken", () => failing(120, "exit 1"));
    expect(first.done).toBe(false);
    if (first.done) return;
    await later(150, null);
    await expect(runs.wait(first.runId)).rejects.toThrow("exit 1");
  });

  it("fails fast work straight away", async () => {
    const runs = new LongRuns<string>(200);
    await expect(runs.start("bad", () => failing(5, "not approved"))).rejects.toThrow("not approved");
  });

  it("rejects an unknown run id", async () => {
    await expect(new LongRuns<string>(50).wait("run_missing")).rejects.toThrow(/Unknown or expired run id/);
  });

  it("drops results half an hour after the work ended", async () => {
    let clock = 1_000;
    const runs = new LongRuns<string>(40, () => clock);
    const first = await runs.start("old", () => later(80, "x"));
    if (first.done) throw new Error("expected a deferred run");
    await later(120, null);
    clock += 31 * 60_000;
    await expect(runs.wait(first.runId)).rejects.toThrow(/Unknown or expired run id/);
  });

  it("reads the budget from the environment with sane limits", () => {
    expect(foregroundBudgetMs({})).toBe(45_000);
    expect(foregroundBudgetMs({ SGW_MCP_FOREGROUND_MS: "400" })).toBe(400);
    expect(foregroundBudgetMs({ SGW_MCP_FOREGROUND_MS: "10" })).toBe(45_000);
    expect(foregroundBudgetMs({ SGW_MCP_FOREGROUND_MS: "nope" })).toBe(45_000);
    expect(foregroundBudgetMs({ SGW_MCP_FOREGROUND_MS: "99999999" })).toBe(600_000);
  });
});
