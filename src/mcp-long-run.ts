import { randomBytes } from "node:crypto";

// MCP clients stop waiting for a tool call after a fixed time (60 seconds in the reference SDK).
// A command that outlived that used to finish with nobody listening, so its result was lost and
// the agent only saw "Request timed out". Work that runs past the foreground budget now gets a
// run id, and the caller collects the result later with a second, short call.
const DEFAULT_FOREGROUND_MS = 45_000;
const MAX_FOREGROUND_MS = 10 * 60_000;
const KEEP_MS = 30 * 60_000;
const MAX_RUNS = 64;

interface Run<T> {
  label: string;
  startedAt: number;
  work: Promise<T>;
  finishedAt?: number;
}

type Settled<T> = { done: true; value: T } | { done: false; label: string; elapsedMs: number };
export type LongRunOutcome<T> = { done: true; value: T } | { done: false; runId: string; label: string; elapsedMs: number };

export function foregroundBudgetMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.SGW_MCP_FOREGROUND_MS);
  if (!Number.isFinite(raw) || raw < 50) return DEFAULT_FOREGROUND_MS;
  return Math.min(raw, MAX_FOREGROUND_MS);
}

export class LongRuns<T> {
  private readonly runs = new Map<string, Run<T>>();

  constructor(
    private readonly budgetMs = foregroundBudgetMs(),
    private readonly now: () => number = () => Date.now()
  ) {}

  async start(label: string, work: () => Promise<T>): Promise<LongRunOutcome<T>> {
    const run: Run<T> = { label, startedAt: this.now(), work: work() };
    const stamp = () => { run.finishedAt = this.now(); };
    // also keeps a late failure from becoming an unhandled rejection when nobody is waiting yet
    run.work.then(stamp, stamp);

    const first = await this.settle(run, this.budgetMs);
    if (first.done) return first;

    this.prune();
    const runId = `run_${randomBytes(12).toString("base64url")}`;
    this.runs.set(runId, run);
    return { ...first, runId };
  }

  async wait(runId: string, waitMs = this.budgetMs): Promise<LongRunOutcome<T>> {
    this.prune();
    const run = this.runs.get(runId);
    if (!run) {
      throw new Error("Unknown or expired run id. Results are kept for 30 minutes after the command ends.");
    }
    const bounded = Math.min(Math.max(0, waitMs), this.budgetMs);
    const outcome = await this.settle(run, bounded);
    return outcome.done ? outcome : { ...outcome, runId };
  }

  private async settle(run: Run<T>, ms: number): Promise<Settled<T>> {
    let timer: NodeJS.Timeout | undefined;
    const waited = new Promise<"waiting">((resolve) => {
      timer = setTimeout(() => resolve("waiting"), ms);
    });
    try {
      const result = await Promise.race([run.work.then((value) => ({ value })), waited]);
      if (result === "waiting") {
        return { done: false, label: run.label, elapsedMs: this.now() - run.startedAt };
      }
      return { done: true, value: result.value };
    } finally {
      clearTimeout(timer);
    }
  }

  private prune() {
    for (const [id, run] of this.runs) {
      if (run.finishedAt !== undefined && this.now() - run.finishedAt > KEEP_MS) this.runs.delete(id);
    }
    // a Map keeps insertion order, so the first key is the oldest run
    while (this.runs.size >= MAX_RUNS) {
      const oldest = this.runs.keys().next().value;
      if (oldest === undefined) break;
      this.runs.delete(oldest);
    }
  }
}
