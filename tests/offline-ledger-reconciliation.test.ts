import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  assessOfflineLedgerReconciliation,
  type OfflineReconciliationInput
} from "../src/offline-ledger-reconciliation.js";

const home = "/synthetic/operator/.s-gw";
const recoveryHome = "/synthetic/operator/.s-gw-recovery";
const timestamp = "2026-10-21T00:00:00.000Z";

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonical((value as Record<string, unknown>)[key]);
    return sorted;
  }
  return value;
}

function sha(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fixture() {
  const app = {
    version: 1,
    secrets: [{
      handle: "s-gw:synthetic:one", name: "Synthetic", encrypted: { ciphertext: "synthetic" },
      policy: { injectEnv: "SYNTHETIC_TOKEN", allowedCommands: ["/usr/bin/true"] },
      updatedAt: timestamp
    }],
    requests: [{
      id: "req_one", handle: "s-gw:synthetic:one", reason: "synthetic current reason",
      action: { kind: "env_command", command: "/usr/bin/true", args: ["synthetic argument"] },
      state: "failed", createdAt: timestamp, updatedAt: timestamp
    }],
    audit: [{ id: "audit_one", ts: timestamp, type: "request.failed", message: "synthetic audit" }],
    approvalSettings: { mode: "per-transaction", durationMs: 900000 },
    approvalGrants: [{ id: "grant_one", handle: "s-gw:synthetic:one", mode: "timed-session" }],
    approvalPolicyRules: [{
      id: "rule_one", name: "Exact command", enabled: true, priority: 100, decision: "allow",
      conditions: {
        handles: ["s-gw:synthetic:one"], commands: ["/usr/bin/true"],
        envBindings: [{ handle: "s-gw:synthetic:one", injectEnv: "SYNTHETIC_TOKEN" }],
        resolvedCommands: ["/usr/bin/true"]
      },
      createdAt: timestamp, updatedAt: timestamp
    }],
    managedSshRoutes: [{ id: "route_one", name: "Synthetic route", route: { host: "example.test", port: 22 } }]
  };
  const donor = {
    ...structuredClone(app),
    writerGeneration: 2,
    requests: [{
      ...app.requests[0], reason: "", action: { ...app.requests[0].action, args: [] }
    }],
    audit: [{ ...app.audit[0], message: "" }],
    approvalPolicyRules: [{
      ...app.approvalPolicyRules[0],
      conditions: { handles: ["s-gw:synthetic:one"], commands: ["/usr/bin/true"] }
    }],
    agentIdentities: [{
      id: "agent_one", canonicalName: "Claude", customName: "Synthetic Claude",
      sources: ["mcp-client"], firstSeenAt: timestamp, lastSeenAt: timestamp
    }],
    sensitiveMetadata: {
      alg: "aes-256-gcm", kdf: "scrypt", salt: "synthetic-salt", iv: "synthetic-iv",
      authTag: "synthetic-tag", ciphertext: "synthetic-ciphertext"
    }
  };
  const { managedSshRoutes: _routes, ...donorWithoutRoutes } = donor;
  const input = seal(app, donorWithoutRoutes);
  return { app, donor: donorWithoutRoutes, input };
}

function seal(app: {
  secrets: Record<string, unknown>[];
  requests: Record<string, unknown>[];
  audit: Record<string, unknown>[];
  approvalSettings: Record<string, unknown>;
  approvalGrants: Record<string, unknown>[];
  approvalPolicyRules: Record<string, unknown>[];
  managedSshRoutes: Record<string, unknown>[];
}, donor: object): OfflineReconciliationInput {
  const secrets = app.secrets.map(({ updatedAt: _updatedAt, ...secret }) => secret);
  const controls = {
    version: 1, secrets, approvalSettings: app.approvalSettings,
    approvalGrants: app.approvalGrants, approvalPolicyRules: app.approvalPolicyRules,
    managedSshRoutes: app.managedSshRoutes
  };
  const fingerprint = sha(JSON.stringify(canonical(controls)));
  const checkpointName = `checkpoint-1700000000000-cp_synthetic-${fingerprint}.json`;
  return {
    sealedLedgerRaw: JSON.stringify(app),
    controlManifestRaw: JSON.stringify({
      version: 1, fingerprint, updatedAt: timestamp, secrets: app.secrets.length,
      approvalPolicyRules: app.approvalPolicyRules.length, recoverySealed: true,
      recoveryCheckpoint: checkpointName, recoveryNamespace: sha(home).slice(0, 24),
      recoveryVaultId: sha(recoveryHome), writerVersion: "0.1.22"
    }),
    checkpointName,
    checkpointRaw: JSON.stringify({ ...app, requests: [], audit: [] }),
    recoveryHeadRaw: JSON.stringify({ version: 1, checkpoint: checkpointName, fingerprint }),
    generationTwoLedgerRaw: JSON.stringify(donor),
    originalHome: home,
    originalRecoveryHome: recoveryHome,
    pendingControlRaw: null
  };
}

function editDonor(input: OfflineReconciliationInput, change: (value: any) => void): OfflineReconciliationInput {
  const donor = JSON.parse(input.generationTwoLedgerRaw);
  change(donor);
  return { ...input, generationTwoLedgerRaw: JSON.stringify(donor) };
}

describe("offline ledger reconciliation assessment", () => {
  it("reports redacted feasibility and blocks migration until history and writer compatibility are resolved", () => {
    const { input } = fixture();
    const assessment = assessOfflineLedgerReconciliation(input);

    expect(assessment.migrationBlocked).toBe(true);
    expect(assessment.blockingReasons).toEqual([
      expect.stringContaining("decrypt the generation-2 envelope"),
      expect.stringContaining("generation-2 writer omits current HTTP fields and SSH transfer paths"),
      expect.stringContaining("plaintext app ledger, journal, and retained backups")
    ]);
    expect(Object.keys(assessment)).toEqual(["migrationBlocked", "blockingReasons", "summary"]);
    expect(assessment.summary).toMatchObject({
      secrets: 1, grants: 1, rules: 1, routes: 1, requests: 1, audit: 1,
      donorIdentityRecords: 1, ruleFieldsOnlyInSeal: 2,
      plaintextRequestRows: 1, plaintextAuditRows: 1,
      donorPlaintextRequestRows: 0, donorPlaintextAuditRows: 0
    });
    expect(JSON.stringify(assessment)).not.toMatch(
      /synthetic current reason|synthetic argument|synthetic audit|Synthetic Claude|synthetic-ciphertext|example.test/
    );
  });

  it("rejects a mismatched seal, recovery namespace, head, or pending transaction", () => {
    const { input } = fixture();
    const wrongManifest = JSON.parse(input.controlManifestRaw);
    wrongManifest.fingerprint = "0".repeat(64);
    expect(() => assessOfflineLedgerReconciliation({ ...input, controlManifestRaw: JSON.stringify(wrongManifest) }))
      .toThrow("sealed app control plane");
    expect(() => assessOfflineLedgerReconciliation({ ...input, originalRecoveryHome: "/synthetic/other" }))
      .toThrow("different home or recovery vault");
    expect(() => assessOfflineLedgerReconciliation({ ...input, recoveryHeadRaw: JSON.stringify({ version: 1 }) }))
      .toThrow("sealed app control plane");
    expect(() => assessOfflineLedgerReconciliation({ ...input, pendingControlRaw: "{}" }))
      .toThrow("pending control-plane write");
    const futureManifest = JSON.parse(input.controlManifestRaw);
    futureManifest.writerVersion = "0.1.23";
    expect(() => assessOfflineLedgerReconciliation({ ...input, controlManifestRaw: JSON.stringify(futureManifest) }))
      .toThrow("sealed app control plane");
    const checkpoint = JSON.parse(input.checkpointRaw);
    checkpoint.approvalPolicyRules[0].decision = "deny";
    expect(() => assessOfflineLedgerReconciliation({ ...input, checkpointRaw: JSON.stringify(checkpoint) }))
      .toThrow("sealed app control plane");
  });

  it("rejects generation-2 secret, grant, setting, rule, and shared-condition drift", () => {
    const { input } = fixture();
    for (const change of [
      (d: any) => { d.secrets[0].policy.allowedCommands = ["/usr/bin/false"]; },
      (d: any) => { d.approvalGrants[0].mode = "always"; },
      (d: any) => { d.approvalSettings.mode = "always"; },
      (d: any) => { d.approvalPolicyRules[0].decision = "deny"; },
      (d: any) => { d.approvalPolicyRules[0].conditions.commands = ["/usr/bin/false"]; }
    ]) {
      expect(() => assessOfflineLedgerReconciliation(editDonor(input, change))).toThrow();
    }
  });

  it("rejects unexpected rule loss and duplicate or missing history IDs", () => {
    const { input } = fixture();
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      delete d.approvalPolicyRules[0].conditions.commands;
    }))).toThrow("unexpected rule condition");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.requests.push({ ...d.requests[0], id: "req_donor_only" });
    }))).toThrow("history contains an ID missing");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.audit.push({ ...d.audit[0] });
    }))).toThrow("duplicate ledger record ID");
  });

  it("refuses open requests rather than treating them as migration-ready history", () => {
    const { input, app, donor } = fixture();
    app.requests[0].state = "approved";
    const resealed = seal(app, donor);
    expect(() => assessOfflineLedgerReconciliation(resealed)).toThrow("open request");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      delete d.sensitiveMetadata;
    }))).toThrow("expected sealed-app and generation-2 pair");
  });

  it("rejects duplicate identity records before producing an assessment", () => {
    const { input } = fixture();
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.agentIdentities.push({ ...d.agentIdentities[0] });
    }))).toThrow("duplicate ledger record ID");
  });

  it("counts plaintext HTTP and SSH details left outside the older encrypted envelope", () => {
    const { input } = fixture();
    const withUncoveredFields = editDonor(input, (d) => {
      d.requests[0].action.http = {
        url: "https://example.test/private", headers: { Authorization: "synthetic header" },
        body: "synthetic body"
      };
      d.requests[0].action.ssh = {
        target: "", transfer: { sourcePath: "/synthetic/source", destinationPath: "/synthetic/destination" }
      };
    });
    const assessment = assessOfflineLedgerReconciliation(withUncoveredFields);
    expect(assessment.summary.donorPlaintextRequestRows).toBe(1);
    expect(JSON.stringify(assessment)).not.toMatch(/synthetic header|synthetic body|synthetic\/source/);
  });

  it("does not echo malformed input into errors", () => {
    const { input } = fixture();
    expect(() => assessOfflineLedgerReconciliation({ ...input, controlManifestRaw: "private malformed manifest" }))
      .toThrow("Invalid control manifest JSON.");
    expect(() => assessOfflineLedgerReconciliation({ ...input, generationTwoLedgerRaw: "private malformed ledger" }))
      .toThrow("Invalid ledger JSON.");
  });
});
