import { randomBytes } from "node:crypto";
import { copyFile, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SealedHistoryPrototype } from "./support/sealed-history-generation.js";
import type { HistoryRows } from "../src/sealed-history-codec.js";

let home = "";
let recoveryHome = "";
const key = randomBytes(32);
const ts = "2026-11-12T10:00:00.000Z";

function rows(reason: string): HistoryRows {
  return {
    requests: [{
      revision: 1,
      record: {
        id: "req_disposable", handle: "s-gw:test:one", reason,
        action: { kind: "env_command", command: "/usr/bin/true", args: ["private argument marker"],
          injectEnv: "TEST_TOKEN", timeoutMs: 1000 },
        state: "failed", createdAt: ts, updatedAt: ts
      }
    }],
    audit: [{ revision: 1, record: { id: "audit_disposable", ts, type: "request.failed",
      message: "private audit marker" } }]
  };
}

beforeEach(async () => {
  const suffix = randomBytes(5).toString("hex");
  home = path.join(process.env.SGW_HOME!, `history-v3-${suffix}`);
  recoveryHome = path.join(process.env.SGW_RECOVERY_HOME!, `history-v3-${suffix}`);
  process.env.SGW_HOME = home;
  process.env.SGW_RECOVERY_HOME = recoveryHome;
  await mkdir(home, { recursive: true, mode: 0o700 });
});

afterEach(async () => {
  await rm(home, { recursive: true, force: true });
  await rm(recoveryHome, { recursive: true, force: true });
});

describe("disposable sealed history generations", () => {
  it("keeps full detail readable without the master passphrase and seals every copy", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const candidate = await store.stage(rows("private reason marker"));
    await store.commit(candidate);

    delete process.env.SGW_MASTER_PASSPHRASE;
    expect(await new SealedHistoryPrototype(home, recoveryHome, key).read())
      .toEqual({ generation: 1, rows: rows("private reason marker") });

    for (const copy of [candidate.primaryPath, candidate.journalPath, candidate.recoveryPath]) {
      const raw = await readFile(copy, "utf8");
      expect(raw).not.toMatch(/private reason marker|private argument marker|private audit marker/);
    }
  });

  it("ignores a fully staged but uncommitted next generation after a restart", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const first = await store.stage(rows("first private reason"));
    await store.commit(first);
    const next = rows("second private reason");
    next.requests[0].revision = 2;
    const second = await store.stage(next);

    expect(await new SealedHistoryPrototype(home, recoveryHome, key).read())
      .toEqual({ generation: 1, rows: rows("first private reason") });
    await store.commit(second);
    expect(await new SealedHistoryPrototype(home, recoveryHome, key).read())
      .toEqual({ generation: 2, rows: next });
  });

  it("recovers only the committed generation from recovery or its sealed journal", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const first = await store.stage(rows("old private reason"));
    await store.commit(first);
    const latest = rows("latest private reason");
    latest.requests[0].revision = 2;
    const second = await store.stage(latest);
    await store.commit(second);

    await writeFile(second.primaryPath, await readFile(first.primaryPath));
    expect(await store.read()).toEqual({ generation: 2, rows: latest });
    await writeFile(second.recoveryPath, await readFile(first.recoveryPath));
    expect(await store.read()).toEqual({ generation: 2, rows: latest });
    await writeFile(second.journalPath, await readFile(first.journalPath));
    await expect(store.read()).rejects.toThrow("No complete copy matches committed sealed history generation 2");
  });

  it("rejects a stale staged writer after another writer commits", async () => {
    const firstWriter = new SealedHistoryPrototype(home, recoveryHome, key);
    await firstWriter.commit(await firstWriter.stage(rows("initial writer")));
    const secondWriter = new SealedHistoryPrototype(home, recoveryHome, key);
    const firstRows = rows("first writer");
    firstRows.requests[0].revision = 2;
    const staleRows = rows("second writer");
    staleRows.requests[0].revision = 2;
    const first = await firstWriter.stage(firstRows);
    const stale = await secondWriter.stage(staleRows);
    await firstWriter.commit(first);
    await expect(secondWriter.commit(stale)).rejects.toThrow("generation changed before commit");
    expect(await firstWriter.read()).toEqual({ generation: 2, rows: firstRows });
  });

  it("keeps the last committed generation when any staged copy is torn", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const oldRows = rows("committed private reason");
    await store.commit(await store.stage(oldRows));

    for (const role of ["primaryPath", "journalPath", "recoveryPath"] as const) {
      const changed = rows(`new private reason in ${role}`);
      changed.requests[0].revision = 2;
      const candidate = await store.stage(changed);
      const raw = await readFile(candidate[role], "utf8");
      await writeFile(candidate[role], raw.slice(0, -8));

      await expect(store.commit(candidate)).rejects.toThrow();
      expect(await new SealedHistoryPrototype(home, recoveryHome, key).read())
        .toEqual({ generation: 1, rows: oldRows });
    }
  });

  it("does not recover from data files when the committed head is damaged", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const candidate = await store.stage(rows("private reason"));
    await store.commit(candidate);
    await writeFile(path.join(path.dirname(candidate.recoveryPath), "head.json"), "{");

    await expect(store.read()).rejects.toThrow("Invalid sealed history generation head");
  });

  it("refuses to recreate generation one after a committed head is deleted", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const committed = await store.stage(rows("original private reason"));
    await store.commit(committed);
    await rm(path.join(path.dirname(committed.recoveryPath), "head.json"));

    await expect(store.read()).rejects.toThrow("generation head is missing");
    await expect(store.stage(rows("rolled back private reason")))
      .rejects.toThrow("generation head is missing");
    await expect(store.commit(committed)).rejects.toThrow("generation head is missing");
  });

  it("refuses a fresh start when head and marker are gone but generation files remain", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const first = await store.stage(rows("first private reason"));
    await store.commit(first);
    const secondRows = rows("second private reason");
    secondRows.requests[0].revision = 2;
    await store.commit(await store.stage(secondRows));

    await rm(path.join(path.dirname(first.recoveryPath), "head.json"));
    await rm(path.join(home, "sealed-history-v3-prototype", "initialized.json"));

    await expect(store.read()).rejects.toThrow("generation head is missing");
    await expect(store.stage(rows("forged fresh reason"))).rejects.toThrow("generation head is missing");
    await expect(store.commit(first)).rejects.toThrow("generation head is missing");
  });

  it("demonstrates the known old-head rollback limit while old generations are retained", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const firstRows = rows("first private reason");
    const first = await store.stage(firstRows);
    await store.commit(first);
    const headPath = path.join(path.dirname(first.recoveryPath), "head.json");
    const oldHead = await readFile(headPath, "utf8");

    const nextRows = rows("second private reason");
    nextRows.requests[0].revision = 2;
    await store.commit(await store.stage(nextRows));
    await writeFile(headPath, oldHead);

    // The head is not backed by an external monotonic anchor in this prototype.
    expect(await store.read()).toEqual({ generation: 1, rows: firstRows });
  });

  it("rejects a matching head and ciphertext copied from another home using the same key", async () => {
    const first = new SealedHistoryPrototype(home, recoveryHome, key);
    const source = await first.stage(rows("first home's private reason"));
    await first.commit(source);

    const otherHome = `${home}-other`;
    const otherRecovery = `${recoveryHome}-other`;
    process.env.SGW_HOME = otherHome;
    process.env.SGW_RECOVERY_HOME = otherRecovery;
    await mkdir(otherHome, { recursive: true, mode: 0o700 });
    try {
      const other = new SealedHistoryPrototype(otherHome, otherRecovery, key);
      const target = await other.stage(rows("second home's private reason"));
      await other.commit(target);
      for (const role of ["primaryPath", "journalPath", "recoveryPath"] as const) {
        await copyFile(source[role], path.join(path.dirname(target[role]), path.basename(source[role])));
      }
      await copyFile(
        path.join(path.dirname(source.recoveryPath), "head.json"),
        path.join(path.dirname(target.recoveryPath), "head.json")
      );

      await expect(other.read()).rejects.toThrow("another home");
    } finally {
      await rm(otherHome, { recursive: true, force: true });
      await rm(otherRecovery, { recursive: true, force: true });
    }
  });

  it("rejects stale rows against the current committed head", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const firstRows = rows("first private reason");
    await store.commit(await store.stage(firstRows));

    const unchangedRevision = await store.stage(rows("changed without revision"));
    await expect(store.commit(unchangedRevision)).rejects.toThrow("revision");

    const nextRows = rows("second private reason");
    nextRows.requests[0].revision = 2;
    await store.commit(await store.stage(nextRows));
    const replay = await store.stage(firstRows);
    await expect(store.commit(replay)).rejects.toThrow("revision");
    expect(await store.read()).toEqual({ generation: 2, rows: nextRows });
  });

  it("refuses to share a home with a v1 ledger or recovery evidence", async () => {
    await writeFile(path.join(home, "store.json"), '{"version":1}\n');
    expect(() => new SealedHistoryPrototype(home, recoveryHome, key)).toThrow("v1 ledger evidence");
    await rm(path.join(home, "store.json"));
    await mkdir(path.join(recoveryHome, "control-plane"), { recursive: true });
    expect(() => new SealedHistoryPrototype(home, recoveryHome, key)).toThrow("v1 ledger evidence");
  });

  it("refuses a v1 ledger created after prototype construction", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    await writeFile(path.join(home, "store.json"), '{"version":1}\n');
    await expect(store.stage(rows("private reason"))).rejects.toThrow("v1 ledger evidence");
  });

  it.skipIf(process.platform === "win32")("refuses a nested primary symlink before writing outside its home", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    const outside = `${home}-outside`;
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await mkdir(path.join(home, "sealed-history-v3-prototype"), { recursive: true, mode: 0o700 });
    await symlink(outside, path.join(home, "sealed-history-v3-prototype", "primary"), "dir");
    try {
      await expect(store.stage(rows("private reason"))).rejects.toThrow("symlink");
      expect(await readdir(outside)).toEqual([]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("refuses a wrong key and refuses use outside disposable test mode", async () => {
    const store = new SealedHistoryPrototype(home, recoveryHome, key);
    await store.commit(await store.stage(rows("private reason")));
    await expect(new SealedHistoryPrototype(home, recoveryHome, randomBytes(32)).read())
      .rejects.toThrow("not authenticated");

    const prior = process.env.SGW_TEST_MODE;
    process.env.SGW_TEST_MODE = "0";
    try {
      expect(() => new SealedHistoryPrototype(home, recoveryHome, key)).toThrow("disposable test home");
    } finally {
      process.env.SGW_TEST_MODE = prior;
    }
  });
});
