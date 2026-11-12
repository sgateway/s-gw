import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sealHistory, type HistoryRows } from "../src/sealed-history-codec.js";
import { verifySealedHistoryClone } from "../src/sealed-history-clone-verifier.js";

const key = randomBytes(32);
const ts = "2026-11-12T00:00:00.000Z";

function fixture() {
  const baseline: HistoryRows = {
    requests: [{
      revision: 2,
      record: {
        id: "req_synthetic", handle: "s-gw:synthetic:one", reason: "private reason canary",
        action: { kind: "env_command", command: "/usr/bin/true", args: ["private argument canary"],
          injectEnv: "SYNTHETIC_TOKEN", timeoutMs: 1000 },
        state: "failed", createdAt: ts, updatedAt: ts
      }
    }],
    audit: [{
      revision: 1,
      record: { id: "audit_synthetic", ts, type: "request.failed", message: "private audit canary" }
    }]
  };
  const sealed = sealHistory(baseline, key);
  const raw = JSON.stringify(sealed);
  const journal = [
    ...sealed.requests.map(row => JSON.stringify({ kind: "request", row })),
    ...sealed.audit.map(row => JSON.stringify({ kind: "audit", row }))
  ].join("\n") + "\n";
  return {
    baseline, key, expectedRevisions: new Map([["req_synthetic", 2], ["audit_synthetic", 1]]),
    primaryRaw: raw, fullBackupRaws: [raw], recoveryCopyRaws: [raw],
    journalSegmentRaws: [journal],
    trustedBaselineSha256: createHash("sha256").update(JSON.stringify(baseline)).digest("hex"),
    leakMarkers: ["private reason canary", "private argument canary", "private audit canary"]
  };
}

describe("synthetic v3 complete-copy verifier", () => {
  it("checks every copy against a trusted complete baseline without returning detail", () => {
    const result = verifySealedHistoryClone(fixture());
    expect(result).toEqual({ requests: 1, audit: 1, completeCopies: 3, journalSegments: 1 });
    expect(JSON.stringify(result)).not.toContain("private");
  });

  it("requires an independent digest for the baseline it verifies", () => {
    const input = fixture();
    input.trustedBaselineSha256 = "0".repeat(64);
    expect(() => verifySealedHistoryClone(input)).toThrow("trusted history baseline digest");
  });

  it("rejects a stale backup and a missing recovery row", () => {
    const input = fixture();
    const old = structuredClone(input.baseline);
    old.requests[0].revision = 1;
    input.fullBackupRaws = [JSON.stringify(sealHistory(old, key))];
    expect(() => verifySealedHistoryClone(input)).toThrow("revision anchor mismatch");

    const fresh = fixture();
    fresh.recoveryCopyRaws = [JSON.stringify(sealHistory({ requests: fresh.baseline.requests,
      audit: [] }, key))];
    expect(() => verifySealedHistoryClone(fresh)).toThrow("revision anchor mismatch");
  });

  it("rejects altered detail even when a copy uses the right key and revision", () => {
    const input = fixture();
    const altered = structuredClone(input.baseline);
    altered.requests[0].record.reason = "private changed canary";
    input.primaryRaw = JSON.stringify(sealHistory(altered, key));
    expect(() => verifySealedHistoryClone(input)).toThrow("differs from the trusted baseline");
  });

  it("rejects plaintext leakage and missing test canaries", () => {
    const input = fixture();
    input.fullBackupRaws = [input.fullBackupRaws[0] + "private audit canary"];
    expect(() => verifySealedHistoryClone(input)).toThrow("canary leaked");

    const missing = fixture();
    missing.leakMarkers = ["not in baseline"];
    expect(() => verifySealedHistoryClone(missing)).toThrow("leak canary");

    const journal = fixture();
    journal.journalSegmentRaws = [journal.journalSegmentRaws[0] + "private reason canary\n"];
    expect(() => verifySealedHistoryClone(journal)).toThrow("canary leaked");
  });

  it("requires independent revisions and all complete-copy roles", () => {
    const input = fixture();
    input.expectedRevisions = new Map([["req_synthetic", 1], ["audit_synthetic", 1]]);
    expect(() => verifySealedHistoryClone(input)).toThrow("trusted revision anchor");
    const noBackup = fixture();
    noBackup.fullBackupRaws = [];
    expect(() => verifySealedHistoryClone(noBackup)).toThrow("full backup");
    const noRecovery = fixture();
    noRecovery.recoveryCopyRaws = [];
    expect(() => verifySealedHistoryClone(noRecovery)).toThrow("recovery copy");
    const noJournal = fixture();
    noJournal.journalSegmentRaws = [];
    expect(() => verifySealedHistoryClone(noJournal)).toThrow("journal");
  });

  it("rejects a torn journal and a missing or extra row", () => {
    const torn = fixture();
    torn.journalSegmentRaws = [torn.journalSegmentRaws[0].slice(0, -1)];
    expect(() => verifySealedHistoryClone(torn)).toThrow("Torn or invalid");

    const missing = fixture();
    missing.journalSegmentRaws = [missing.journalSegmentRaws[0].split("\n")[0] + "\n"];
    expect(() => verifySealedHistoryClone(missing)).toThrow("revision anchor mismatch");

    const extra = fixture();
    extra.journalSegmentRaws = [extra.journalSegmentRaws[0].replace(/\n$/, "\n")
      + extra.journalSegmentRaws[0].split("\n")[0] + "\n"];
    expect(() => verifySealedHistoryClone(extra)).toThrow("Duplicate sealed history ID");
  });
});
