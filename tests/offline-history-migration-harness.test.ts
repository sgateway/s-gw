import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { buildSyntheticHistoryMigration } from "../src/offline-history-migration-harness.js";
import { verifySealedHistoryClone } from "../src/sealed-history-clone-verifier.js";
import type { HistoryRows } from "../src/sealed-history-codec.js";
import type { OfflineReconciliationInput } from "../src/offline-ledger-reconciliation.js";
import type { AuditEvent, RequestRecord } from "../src/types.js";

const ts = "2026-11-12T00:00:00.000Z";
const home = path.resolve(path.parse(process.cwd()).root, "synthetic", ".s-gw");
const recoveryHome = path.resolve(path.parse(process.cwd()).root, "synthetic", ".s-gw-recovery");
const passphrase = "synthetic-only-passphrase";

function sha(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const name of Object.keys(value).sort()) sorted[name] = canonical((value as Record<string, unknown>)[name]);
    return sorted;
  }
  return value;
}

function wrapSynthetic(value: object) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
  return {
    alg: "aes-256-gcm" as const, kdf: "scrypt" as const,
    salt: salt.toString("base64"), iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64")
  };
}

function unwrapSynthetic(box: ReturnType<typeof wrapSynthetic>): string {
  const key = scryptSync(passphrase, Buffer.from(box.salt, "base64"), 32);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(box.iv, "base64"));
  decipher.setAuthTag(Buffer.from(box.authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(box.ciphertext, "base64")), decipher.final()
  ]).toString("utf8");
}

function fixture() {
  const shared: RequestRecord = {
    id: "req_synthetic_shared", handle: "s-gw:synthetic:one", reason: "private old reason canary",
    action: {
      kind: "http_request", command: "http-request", args: ["private old argument canary"],
      injectEnv: "SYNTHETIC_TOKEN", timeoutMs: 1000,
      http: { url: "https://private-http-canary.test/owned", method: "POST",
        headers: { "x-test": "private header canary" }, body: "private body canary",
        auth: { kind: "bearer" } }
    },
    state: "failed", createdAt: ts, updatedAt: ts,
    resultSummary: {
      exitCode: 1, signal: null, stdout: "private output canary", stderr: "private stderr canary",
      proof: "synthetic proof", durationMs: 10, timeoutMs: 1000, timedOut: false, sanitized: true
    }
  };
  const newer: RequestRecord = {
    ...structuredClone(shared), id: "req_synthetic_new", reason: "private new reason canary",
    action: { ...structuredClone(shared.action), args: ["private new argument canary"] }
  };
  const sharedAudit: AuditEvent = {
    id: "audit_synthetic_shared", ts, type: "request.failed", requestId: shared.id,
    message: "private old audit canary"
  };
  const newerAudit: AuditEvent = {
    id: "audit_synthetic_new", ts, type: "request.failed", requestId: newer.id,
    message: "private new audit canary"
  };
  const app = {
    version: 1, secrets: [], requests: [shared, newer], audit: [sharedAudit, newerAudit],
    approvalSettings: { mode: "per-transaction", durationMs: 900000 },
    approvalGrants: [], approvalPolicyRules: [], managedSshRoutes: []
  };
  const sensitiveMetadata = wrapSynthetic({
    requests: {
      [shared.id]: { reason: shared.reason, args: shared.action.args,
        stdout: shared.resultSummary?.stdout, stderr: shared.resultSummary?.stderr }
    },
    audit: { [sharedAudit.id]: sharedAudit.message }
  });
  const donor = {
    version: 1, writerGeneration: 2, secrets: [],
    requests: [{ ...shared, reason: "", action: { ...shared.action, args: [] },
      resultSummary: { ...shared.resultSummary, stdout: "", stderr: "" } }],
    agentIdentities: [], audit: [{ ...sharedAudit, message: "" }],
    approvalSettings: app.approvalSettings, approvalGrants: [], approvalPolicyRules: [],
    sensitiveMetadata
  };
  const control = {
    version: 1, secrets: [], approvalSettings: app.approvalSettings,
    approvalGrants: [], approvalPolicyRules: []
  };
  const fingerprint = sha(JSON.stringify(canonical(control)));
  const checkpointName = `checkpoint-1700000000000-cp_synthetic-${fingerprint}.json`;
  const reconciliation: OfflineReconciliationInput = {
    sealedLedgerRaw: JSON.stringify(app), generationTwoLedgerRaw: JSON.stringify(donor),
    controlManifestRaw: JSON.stringify({
      version: 1, fingerprint, updatedAt: ts, secrets: 0, approvalPolicyRules: 0,
      recoverySealed: true, recoveryCheckpoint: checkpointName,
      recoveryNamespace: sha(home).slice(0, 24), recoveryVaultId: sha(recoveryHome),
      writerVersion: "0.1.22"
    }),
    checkpointName, checkpointRaw: JSON.stringify({ ...app, requests: [], audit: [] }),
    recoveryHeadRaw: JSON.stringify({ version: 1, checkpoint: checkpointName, fingerprint }),
    originalHome: home, originalRecoveryHome: recoveryHome, pendingControlRaw: null
  };
  const expectedRevisions = new Map([
    [shared.id, 1], [newer.id, 1], [sharedAudit.id, 1], [newerAudit.id, 1]
  ]);
  const baseline: HistoryRows = {
    requests: app.requests.map(record => ({ revision: 1, record })),
    audit: app.audit.map(record => ({ revision: 1, record }))
  };
  const leakMarkers = [
    "private old reason canary", "private old argument canary", "private output canary",
    "private stderr canary", "private-http-canary.test", "private header canary",
    "private body canary", "private old audit canary", "private new reason canary",
    "private new argument canary", "private new audit canary"
  ];
  return { reconciliation, expectedRevisions, baseline, leakMarkers, key: randomBytes(32),
    trustedBaselineSha256: sha(JSON.stringify(baseline)),
    unwrapLegacyMetadata: unwrapSynthetic };
}

describe("synthetic generation-2 history migration harness", () => {
  it("converts donor and app-only detail into sealed primary, backup, recovery, and journal copies", () => {
    const input = fixture();
    const result = buildSyntheticHistoryMigration(input);
    expect(result.check).toEqual({ requests: 2, audit: 2, completeCopies: 3, journalSegments: 2 });
    expect(result.primaryRaw).not.toBe(result.fullBackupRaws[0]);
    expect(JSON.stringify(result)).not.toMatch(/private old|private new|private-http|private header|private body/);
    for (const segment of result.journalSegmentRaws) {
      for (const line of segment.trimEnd().split("\n")) {
        expect(Object.keys(JSON.parse(line))).toEqual(["kind", "row"]);
      }
    }
    expect(verifySealedHistoryClone({ ...result, baseline: input.baseline,
      expectedRevisions: input.expectedRevisions, key: input.key,
      leakMarkers: input.leakMarkers, trustedBaselineSha256: input.trustedBaselineSha256 })).toEqual(result.check);
  });

  it("rejects changed app-only detail against the independent baseline digest", () => {
    const input = fixture();
    const app = JSON.parse(input.reconciliation.sealedLedgerRaw);
    app.requests[1].resultSummary.proof = "changed after the snapshot";
    input.reconciliation.sealedLedgerRaw = JSON.stringify(app);
    expect(() => buildSyntheticHistoryMigration(input)).toThrow("trusted history baseline digest");
  });

  it("rejects duplicate request IDs in the decrypted envelope JSON", () => {
    const input = fixture();
    const unwrap = input.unwrapLegacyMetadata;
    input.unwrapLegacyMetadata = box => unwrap(box).replace(
      '"req_synthetic_shared":',
      '"req_synthetic_shared":{"reason":"conflicting detail","args":[]},"req_synthetic_shared":'
    );
    expect(() => buildSyntheticHistoryMigration(input)).toThrow("duplicate key");
  });

  it("rejects duplicate audit IDs in the decrypted envelope JSON", () => {
    const input = fixture();
    const unwrap = input.unwrapLegacyMetadata;
    input.unwrapLegacyMetadata = box => unwrap(box).replace(
      '"audit_synthetic_shared":',
      '"audit_synthetic_shared":"conflicting message","audit_synthetic_shared":'
    );
    expect(() => buildSyntheticHistoryMigration(input)).toThrow("duplicate key");
  });

  it("rejects duplicate request collections in the sealed app ledger JSON", () => {
    const input = fixture();
    input.reconciliation.sealedLedgerRaw = input.reconciliation.sealedLedgerRaw.replace(
      '"requests":', '"requests":[{"id":"req_discarded"}],"requests":'
    );
    expect(() => buildSyntheticHistoryMigration(input)).toThrow("duplicate key");
  });

  it("rejects duplicate request collections in the generation-2 ledger JSON", () => {
    const input = fixture();
    input.reconciliation.generationTwoLedgerRaw = input.reconciliation.generationTwoLedgerRaw.replace(
      '"requests":', '"requests":[{"id":"req_discarded"}],"requests":'
    );
    expect(() => buildSyntheticHistoryMigration(input)).toThrow("duplicate key");
  });

  it("rejects a tampered legacy ciphertext and mismatched shared detail", () => {
    const tampered = fixture();
    const donor = JSON.parse(tampered.reconciliation.generationTwoLedgerRaw);
    donor.sensitiveMetadata.ciphertext = "AAAA";
    tampered.reconciliation.generationTwoLedgerRaw = JSON.stringify(donor);
    expect(() => buildSyntheticHistoryMigration(tampered)).toThrow();

    const changed = fixture();
    const app = JSON.parse(changed.reconciliation.sealedLedgerRaw);
    app.requests[0].reason = "private conflicting reason";
    changed.reconciliation.sealedLedgerRaw = JSON.stringify(app);
    expect(() => buildSyntheticHistoryMigration(changed)).toThrow();
  });

  it("rejects missing legacy envelope rows and incompatible donor authority", () => {
    const missing = fixture();
    missing.unwrapLegacyMetadata = () => JSON.stringify({ requests: {}, audit: {} });
    expect(() => buildSyntheticHistoryMigration(missing)).toThrow("envelope and row IDs differ");

    const authority = fixture();
    const donor = JSON.parse(authority.reconciliation.generationTwoLedgerRaw);
    donor.approvalSettings.mode = "always";
    authority.reconciliation.generationTwoLedgerRaw = JSON.stringify(donor);
    expect(() => buildSyntheticHistoryMigration(authority)).toThrow("approval settings differ");
  });

  it("detects missing journal rows and stale complete copies after conversion", () => {
    const input = fixture();
    const result = buildSyntheticHistoryMigration(input);
    const incompleteJournal = { ...result, journalSegmentRaws: result.journalSegmentRaws.slice(0, 1) };
    expect(() => verifySealedHistoryClone({ ...incompleteJournal, baseline: input.baseline,
      expectedRevisions: input.expectedRevisions, key: input.key,
      leakMarkers: input.leakMarkers, trustedBaselineSha256: input.trustedBaselineSha256 }))
      .toThrow("revision anchor mismatch");
    const staleBackup = { ...result, fullBackupRaws: [result.fullBackupRaws[0].replace('"revision":1', '"revision":2')] };
    expect(() => verifySealedHistoryClone({ ...staleBackup, baseline: input.baseline,
      expectedRevisions: input.expectedRevisions, key: input.key,
      leakMarkers: input.leakMarkers, trustedBaselineSha256: input.trustedBaselineSha256 })).toThrow();
  });
});
