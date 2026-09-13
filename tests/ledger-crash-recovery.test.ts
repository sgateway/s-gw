import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildEnvCommandAction } from "../src/gateway.js";
import { SecretStore } from "../src/store.js";
import type { RequestRecord, StoreFile } from "../src/types.js";

/**
 * Fault-injection coverage for the P0 ledger crash/recovery gap.
 *
 * The failure being guarded against: a crash or mixed-runtime startup left the home with its
 * credentials and policies intact but zero requests and zero audit events, which emptied Usage
 * Flow even though retained full backups still held the history. Every test here asserts exact
 * pre/post counts so a regression cannot pass by restoring "something".
 */

let tmpHome = "";

function fakeOpenAiToken(label: string): string {
  return ["sk", "-proj-", label, "_1234567890abcdef"].join("");
}

async function seedLedger(requestCount: number): Promise<{
  handle: string;
  ruleId: string;
  requests: RequestRecord[];
}> {
  const store = new SecretStore();
  const secret = await store.addSecret({
    name: "crash drill token",
    type: "api-token",
    value: fakeOpenAiToken("crash_drill"),
    policy: { injectEnv: "CRASH_DRILL_TOKEN", allowedCommands: [process.execPath] }
  });
  // Requests are created before any approval policy exists, so they are unambiguously pending.
  const requests: RequestRecord[] = [];
  for (let index = 0; index < requestCount; index += 1) {
    requests.push(await store.createRequest(
      secret.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", String(index)],
        injectEnv: "CRASH_DRILL_TOKEN"
      }),
      `Codex crash drill request ${index}`
    ));
  }

  const rule = await store.addApprovalPolicyRule({
    name: "Crash drill policy",
    decision: "allow",
    conditions: { agents: ["never-matches-this-agent"] }
  });

  return { handle: secret.handle, ruleId: rule.id, requests };
}

async function readLedger(): Promise<StoreFile> {
  return JSON.parse(await readFile(path.join(tmpHome, "store.json"), "utf8")) as StoreFile;
}

async function latestFullBackup(): Promise<string> {
  const backupDir = path.join(tmpHome, "backups");
  const entries = (await readdir(backupDir)).filter((entry) => entry.endsWith(".json")).sort();
  if (entries.length === 0) {
    throw new Error(`Expected at least one retained full backup in ${backupDir}.`);
  }
  return path.join(backupDir, entries[entries.length - 1]);
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-ledger-crash-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "local test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_DISABLE_ONEPASSWORD_BACKUP;
  await rm(tmpHome, { recursive: true, force: true });
  await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
});

describe("ledger crash and recovery drills", () => {
  it("keeps every request and audit row when the primary ledger disappears", async () => {
    const seeded = await seedLedger(3);
    const before = await readLedger();
    expect(before.requests).toHaveLength(3);
    expect(before.audit.length).toBeGreaterThan(0);

    // Crash: the primary ledger is gone, control state and backups remain.
    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const requests = await recovered.listRequests();
    const audit = await recovered.auditLog();

    expect((await recovered.listHandles()).map((entry) => entry.handle)).toContain(seeded.handle);
    expect((await recovered.listApprovalPolicyRules()).map((entry) => entry.id)).toContain(seeded.ruleId);

    expect(requests.map((entry) => entry.id).sort()).toEqual(before.requests.map((entry) => entry.id).sort());
    for (const original of before.audit) {
      expect(audit.some((entry) => entry.id === original.id)).toBe(true);
    }

    const recoveryEvents = audit.filter((entry) => entry.type === "store.recovered");
    expect(recoveryEvents).toHaveLength(1);
    expect(recoveryEvents[0].message).toContain("request(s)");
  });

  it("records a durable recovery event naming the history it restored", async () => {
    await seedLedger(2);
    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const event = (await recovered.auditLog()).find((entry) => entry.type === "store.recovered");

    expect(event).toBeDefined();
    expect(event!.message).toMatch(/Recovered the s-gw ledger from /);
    // The event must survive the next write, not just the recovery turn.
    await recovered.addApprovalPolicyRule({
      name: "post recovery rule",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    const persisted = await readLedger();
    expect(persisted.audit.some((entry) => entry.id === event!.id)).toBe(true);
  });

  it("never restores a request that still held an approval", async () => {
    const seeded = await seedLedger(1);
    const approved = await new SecretStore().approveRequest(seeded.requests[0].id);
    expect(approved.state).toBe("approved");

    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const restored = (await recovered.listRequests()).find((entry) => entry.id === seeded.requests[0].id);

    expect(restored).toBeDefined();
    expect(restored!.state).toBe("failed");
    expect(restored!.approvalGrantId).toBeUndefined();
    expect(restored!.approvedAt).toBeUndefined();
    expect(restored!.error).toContain("closed without authority");
  });

  it("restores a pending request as pending so the operator's queue survives", async () => {
    const seeded = await seedLedger(1);
    expect(seeded.requests[0].state).toBe("pending");

    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const restored = (await recovered.listRequests()).find((entry) => entry.id === seeded.requests[0].id);

    expect(restored!.state).toBe("pending");
    expect(restored!.error).toBeUndefined();
  });

  it("refuses to initialize an empty ledger when a full backup is still on disk", async () => {
    const seeded = await seedLedger(2);
    const backupContent = await readFile(await latestFullBackup(), "utf8");
    const inBackup = (JSON.parse(backupContent) as StoreFile).requests.length;

    // Wipe everything that anchors the ledger except the retained full backup and journal.
    await rm(path.join(tmpHome, "store.json"));
    await rm(path.join(tmpHome, ".store-control.json"), { force: true });
    await rm(path.join(tmpHome, ".store-initialized"), { force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });

    const recovered = new SecretStore();
    const requests = await recovered.listRequests();

    // Never a silent empty ledger, and never merely what the sparse backup happened to hold.
    expect(requests).toHaveLength(seeded.requests.length);
    expect(requests.length).toBeGreaterThanOrEqual(inBackup);
  });

  it("rebuilds history from the journal when the crash lands between full backups", async () => {
    // Backups are written on control-plane change or after an interval, so requests made
    // between backups exist only in the journal. This is the exact window that lost the ledger.
    const seeded = await seedLedger(4);
    await rm(path.join(tmpHome, "backups"), { recursive: true, force: true });
    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const requests = await recovered.listRequests();

    expect(requests.map((entry) => entry.id).sort()).toEqual(seeded.requests.map((entry) => entry.id).sort());
    const event = (await recovered.auditLog()).find((entry) => entry.type === "store.recovered");
    expect(event!.message).toContain("journal");
  });

  it("tolerates a journal line torn by a crash mid-append", async () => {
    const seeded = await seedLedger(3);
    const journalDir = path.join(tmpHome, "journal");
    const segments = (await readdir(journalDir)).filter((entry) => entry.endsWith(".jsonl")).sort();
    expect(segments.length).toBeGreaterThan(0);

    const segmentPath = path.join(journalDir, segments[segments.length - 1]);
    // Simulate a process killed partway through appending its last line.
    await writeFile(segmentPath, `${await readFile(segmentPath, "utf8")}{"kind":"request","row":{"id":"tor`, "utf8");

    await rm(path.join(tmpHome, "backups"), { recursive: true, force: true });
    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const requests = await recovered.listRequests();

    expect(requests.map((entry) => entry.id).sort()).toEqual(seeded.requests.map((entry) => entry.id).sort());
  });

  it("journals the final state of a request, not only its creation", async () => {
    const seeded = await seedLedger(1);
    const denied = await new SecretStore().denyRequest(seeded.requests[0].id);
    expect(denied.state).toBe("denied");

    await rm(path.join(tmpHome, "backups"), { recursive: true, force: true });
    await rm(path.join(tmpHome, "store.json"));

    const recovered = new SecretStore();
    const restored = (await recovered.listRequests()).find((entry) => entry.id === seeded.requests[0].id);

    // A terminal state is history, so it must come back exactly as recorded.
    expect(restored!.state).toBe("denied");
    expect(restored!.error).toBeUndefined();
  });

  it("writes only request and audit rows to the journal, never credentials or authority", async () => {
    await seedLedger(2);
    const journalDir = path.join(tmpHome, "journal");
    const segments = (await readdir(journalDir)).filter((entry) => entry.endsWith(".jsonl")).sort();

    let lineCount = 0;
    for (const segment of segments) {
      const raw = await readFile(path.join(journalDir, segment), "utf8");
      expect(raw).not.toContain(fakeOpenAiToken("crash_drill"));
      for (const line of raw.split("\n").filter((entry) => entry.trim())) {
        lineCount += 1;
        const parsed = JSON.parse(line) as { kind: string; row: Record<string, unknown> };
        expect(["request", "audit"]).toContain(parsed.kind);
        expect(Object.keys(parsed)).toEqual(["kind", "row"]);
        for (const forbidden of ["secrets", "approvalGrants", "approvalPolicyRules", "approvalSettings", "value", "cache"]) {
          expect(parsed.row).not.toHaveProperty(forbidden);
        }
      }
    }
    expect(lineCount).toBeGreaterThan(0);
  });

  it("fails closed instead of emptying the ledger when the store is corrupt and nothing can be restored", async () => {
    await seedLedger(1);
    await writeFile(path.join(tmpHome, "store.json"), "{ not json", "utf8");
    await rm(path.join(tmpHome, "backups"), { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });

    const recovered = new SecretStore();
    await expect(recovered.listRequests()).rejects.toThrow();

    // The corrupt ledger is preserved for investigation rather than replaced with an empty one.
    const preserved = await readdir(path.join(tmpHome, "recovery", "automatic")).catch(() => []);
    expect(preserved.some((entry) => entry.includes("store-invalid"))).toBe(true);
  });

  it("survives repeated crash and restart cycles with unchanged counts", async () => {
    const seeded = await seedLedger(3);
    const before = await readLedger();

    for (let cycle = 0; cycle < 3; cycle += 1) {
      await rm(path.join(tmpHome, "store.json"));
      const recovered = new SecretStore();
      const requests = await recovered.listRequests();
      expect(requests).toHaveLength(before.requests.length);
      expect((await recovered.listHandles()).map((entry) => entry.handle)).toContain(seeded.handle);
    }

    const after = await readLedger();
    expect(after.requests).toHaveLength(before.requests.length);
    expect(after.secrets).toHaveLength(before.secrets.length);
    expect(after.approvalPolicyRules).toHaveLength(before.approvalPolicyRules.length);
  });

  it("serializes simultaneous writers without losing a request", async () => {
    const seeded = await seedLedger(0);
    const writers = Array.from({ length: 8 }, (_unused, index) => {
      const store = new SecretStore();
      return store.createRequest(
        seeded.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-e", "0"],
          injectEnv: "CRASH_DRILL_TOKEN"
        }),
        `Codex concurrent request ${index}`
      );
    });

    const created = await Promise.all(writers);
    const persisted = await readLedger();
    const persistedIds = new Set(persisted.requests.map((entry) => entry.id));

    expect(new Set(created.map((entry) => entry.id)).size).toBe(created.length);
    for (const request of created) {
      expect(persistedIds.has(request.id)).toBe(true);
    }
  });

  it("refuses to write a home that a newer runtime owns", async () => {
    await seedLedger(1);
    const controlPath = path.join(tmpHome, ".store-control.json");
    const control = JSON.parse(await readFile(controlPath, "utf8")) as { writerVersion?: string };
    expect(control.writerVersion).toBeDefined();

    control.writerVersion = "99.0.0";
    await writeFile(controlPath, `${JSON.stringify(control, null, 2)}\n`, "utf8");

    const older = new SecretStore();
    await expect(older.addApprovalPolicyRule({
      name: "written by an older runtime",
      decision: "allow",
      conditions: { agents: ["codex"] }
    })).rejects.toThrow(/older runtime/);
  });
});
