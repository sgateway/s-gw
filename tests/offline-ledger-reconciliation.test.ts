import { createHash } from "node:crypto";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assessOfflineLedgerReconciliation,
  verifyOfflineReconciliationCandidateDetails,
  verifyOfflineReconciliationCandidateStructure,
  type OfflineReconciliationInput, type OfflineDecryptedDonorEvidence
} from "../src/offline-ledger-reconciliation.js";

const syntheticRoot = path.join(path.parse(process.cwd()).root, "synthetic");
const home = path.resolve(syntheticRoot, "operator", ".s-gw");
const recoveryHome = path.resolve(syntheticRoot, "operator", ".s-gw-recovery");
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
  consoleAccess?: "protected";
  credentialOps?: Record<string, unknown>[];
}, donor: object, writerVersion = "0.1.22"): OfflineReconciliationInput {
  const secrets = app.secrets.map(({ updatedAt: _updatedAt, cache: _cache, ...secret }) => secret);
  const grants = app.approvalGrants.map(({ lastRequestId: _lastRequestId, updatedAt: _updatedAt, ...grant }) => grant);
  const controls = {
    version: 1, secrets, approvalSettings: app.approvalSettings,
    ...(app.consoleAccess === "protected" ? { consoleAccess: app.consoleAccess } : {}),
    approvalGrants: grants, approvalPolicyRules: app.approvalPolicyRules,
    managedSshRoutes: app.managedSshRoutes,
    ...(app.credentialOps?.length ? { credentialOps: app.credentialOps } : {})
  };
  const fingerprint = sha(JSON.stringify(canonical(controls)));
  const checkpointName = `checkpoint-1700000000000-cp_synthetic-${fingerprint}.json`;
  return {
    sealedLedgerRaw: JSON.stringify(app),
    controlManifestRaw: JSON.stringify({
      version: 1, fingerprint, updatedAt: timestamp, secrets: app.secrets.length,
      approvalPolicyRules: app.approvalPolicyRules.length, recoverySealed: true,
      recoveryCheckpoint: checkpointName, recoveryNamespace: sha(path.resolve(home)).slice(0, 24),
      recoveryVaultId: sha(path.resolve(recoveryHome)), writerVersion
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

function syntheticCandidate() {
  const { app, donor, input } = fixture();
  const candidate = {
    ...structuredClone(app), writerGeneration: 2,
    agentIdentities: structuredClone(donor.agentIdentities),
    sensitiveMetadata: structuredClone(donor.sensitiveMetadata)
  };
  return { input, candidate };
}

function detailEvidence(input: OfflineReconciliationInput): OfflineDecryptedDonorEvidence {
  const app = JSON.parse(input.sealedLedgerRaw);
  const donor = JSON.parse(input.generationTwoLedgerRaw);
  return {
    decryptedDonorMetadataRaw: JSON.stringify({
      requests: { req_one: { reason: "synthetic current reason", args: ["synthetic argument"] } },
      audit: { audit_one: "synthetic audit" }
    }),
    generationTwoLedgerSha256: sha(input.generationTwoLedgerRaw),
    donorMetadataBoxSha256: sha(JSON.stringify(canonical(donor.sensitiveMetadata))),
    sealedAppLedgerSha256: sha(input.sealedLedgerRaw),
    sealedAppHistorySha256: sha(JSON.stringify(canonical({ requests: app.requests, audit: app.audit })))
  };
}

describe("offline ledger reconciliation assessment", () => {
  it("reports redacted feasibility and blocks migration until history and writer compatibility are resolved", () => {
    const { input } = fixture();
    const assessment = assessOfflineLedgerReconciliation(input);

    expect(assessment.migrationBlocked).toBe(true);
    expect(assessment.blockingReasons).toEqual([
      expect.stringContaining("decrypt the generation-2 envelope"),
      expect.stringContaining("generation-2 writer omits current HTTP fields and SSH transfer paths"),
      expect.stringContaining("Locked Usage Flow detail visibility also needs an operator decision")
    ]);
    expect(Object.keys(assessment)).toEqual(["migrationBlocked", "blockingReasons", "summary"]);
    expect(assessment.summary).toMatchObject({
      secrets: 1, grants: 1, rules: 1, routes: 1, requests: 1, audit: 1,
      donorIdentityRecords: 1, ruleFieldsOnlyInSeal: 2,
      appOnlyRequests: 0, appOnlyAudit: 0, donorOpenRequests: 0,
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
    expect(() => assessOfflineLedgerReconciliation({ ...input,
      originalRecoveryHome: path.join(syntheticRoot, "other") }))
      .toThrow("different home or recovery vault");
    expect(() => assessOfflineLedgerReconciliation({ ...input, recoveryHeadRaw: JSON.stringify({ version: 1 }) }))
      .toThrow("sealed app control plane");
    expect(() => assessOfflineLedgerReconciliation({ ...input, pendingControlRaw: "{}" }))
      .toThrow("pending control-plane write");
    const futureManifest = JSON.parse(input.controlManifestRaw);
    futureManifest.writerVersion = "0.1.24";
    expect(() => assessOfflineLedgerReconciliation({ ...input, controlManifestRaw: JSON.stringify(futureManifest) }))
      .toThrow("sealed app control plane");
    const checkpoint = JSON.parse(input.checkpointRaw);
    checkpoint.approvalPolicyRules[0].decision = "deny";
    expect(() => assessOfflineLedgerReconciliation({ ...input, checkpointRaw: JSON.stringify(checkpoint) }))
      .toThrow("sealed app control plane");
    expect(() => assessOfflineLedgerReconciliation({ ...input,
      originalHome: path.join(home, "..", ".s-gw"),
      originalRecoveryHome: path.join(recoveryHome, "..", ".s-gw-recovery") })).not.toThrow();
  });

  it("validates a protected 0.1.23 app seal and rejects console policy drift", () => {
    const { app, donor } = fixture();
    const protectedApp = { ...app, consoleAccess: "protected" as const };
    const input = seal(protectedApp, donor, "0.1.23");
    const assessment = assessOfflineLedgerReconciliation(input);
    expect(assessment.migrationBlocked).toBe(true);
    expect(assessment.summary.controlFingerprint).toBe(JSON.parse(input.controlManifestRaw).fingerprint);

    const checkpoint = JSON.parse(input.checkpointRaw);
    delete checkpoint.consoleAccess;
    expect(() => assessOfflineLedgerReconciliation({ ...input, checkpointRaw: JSON.stringify(checkpoint) }))
      .toThrow("sealed app control plane");

    const changedApp = JSON.parse(input.sealedLedgerRaw);
    delete changedApp.consoleAccess;
    expect(() => assessOfflineLedgerReconciliation({ ...input, sealedLedgerRaw: JSON.stringify(changedApp) }))
      .toThrow("sealed app control plane");

    const invalidApp = { ...changedApp, consoleAccess: "ordinary" };
    expect(() => assessOfflineLedgerReconciliation({ ...input, sealedLedgerRaw: JSON.stringify(invalidApp) }))
      .toThrow("Invalid console access policy");

    expect(() => assessOfflineLedgerReconciliation(seal(protectedApp, donor, "0.1.22")))
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

  it("rejects a shared history ID when its immutable origin differs", () => {
    const { input } = fixture();
    for (const change of [
      (d: any) => { d.requests[0].handle = "s-gw:synthetic:other"; },
      (d: any) => { d.requests[0].createdAt = "2026-10-20T00:00:00.000Z"; },
      (d: any) => { d.requests[0].action.kind = "ssh"; },
      (d: any) => { d.requests[0].action.command = "/usr/bin/false"; },
      (d: any) => { d.audit[0].ts = "2026-10-20T00:00:00.000Z"; },
      (d: any) => { d.audit[0].type = "request.executed"; },
      (d: any) => { d.audit[0].requestId = "req_other"; }
    ]) {
      expect(() => assessOfflineLedgerReconciliation(editDonor(input, change)))
        .toThrow("history provenance conflicts");
    }
  });

  it("refuses unknown ledger fields, malformed origins, and invalid donor states", () => {
    const { input } = fixture();
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.futureAuthority = { synthetic: true };
    }))).toThrow("unrecognized ledger field");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      delete d.requests[0].createdAt;
    }))).toThrow("Invalid shared history provenance");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.requests[0].state = "unknown";
    }))).toThrow("Invalid generation-2 request state");
    const checkpoint = JSON.parse(input.checkpointRaw);
    checkpoint.futureAuthority = { synthetic: true };
    expect(() => assessOfflineLedgerReconciliation({ ...input, checkpointRaw: JSON.stringify(checkpoint) }))
      .toThrow("unrecognized ledger field");
    const manifest = JSON.parse(input.controlManifestRaw);
    manifest.futureAuthority = { synthetic: true };
    expect(() => assessOfflineLedgerReconciliation({ ...input, controlManifestRaw: JSON.stringify(manifest) }))
      .toThrow("unrecognized control manifest field");
    const head = JSON.parse(input.recoveryHeadRaw);
    head.futureAuthority = { synthetic: true };
    expect(() => assessOfflineLedgerReconciliation({ ...input, recoveryHeadRaw: JSON.stringify(head) }))
      .toThrow("unrecognized recovery head field");
  });

  it("counts newer app history and open donor states without granting them authority", () => {
    const { input, app } = fixture();
    app.requests.push({ ...app.requests[0], id: "req_new" });
    app.audit.push({ ...app.audit[0], id: "audit_new" });
    const donor = JSON.parse(input.generationTwoLedgerRaw);
    donor.requests[0].state = "executing";
    const assessment = assessOfflineLedgerReconciliation(seal(app, donor));
    expect(assessment.summary).toMatchObject({
      requests: 2, audit: 2, appOnlyRequests: 1, appOnlyAudit: 1, donorOpenRequests: 1
    });
  });

  it("blocks a sealed pending credential operation and unexpected donor authority", () => {
    const { input, app } = fixture();
    const donor = JSON.parse(input.generationTwoLedgerRaw);
    const staged = { id: "op_synthetic", kind: "keychain-add", phase: "prepared" };
    const withStaged = seal({ ...app, credentialOps: [staged] }, donor);
    expect(() => assessOfflineLedgerReconciliation(withStaged)).toThrow("staged credential transaction");
    expect(() => assessOfflineLedgerReconciliation(editDonor(input, (d) => {
      d.credentialOps = [staged];
    }))).toThrow("unrecognized ledger field");
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

describe("offline reconciliation candidate structure", () => {
  it("accepts a mixed synthetic candidate while keeping migration blocked", () => {
    const { input, candidate } = syntheticCandidate();
    const assessment = verifyOfflineReconciliationCandidateStructure(input, JSON.stringify(candidate));

    expect(assessment.migrationBlocked).toBe(true);
    expect(assessment.summary).toMatchObject({
      donorIdentityRecords: 1, routes: 1, ruleFieldsOnlyInSeal: 2, requests: 1, audit: 1
    });
    expect(JSON.stringify(assessment)).not.toMatch(/Synthetic Claude|synthetic-ciphertext|example.test/);
  });

  it("rejects a candidate that drops or changes donor identities and encrypted metadata", () => {
    const { input, candidate } = syntheticCandidate();
    for (const change of [
      (c: any) => { c.agentIdentities = []; },
      (c: any) => { c.agentIdentities[0].customName = "Changed"; },
      (c: any) => { c.agentIdentities.push({ ...c.agentIdentities[0] }); },
      (c: any) => { delete c.sensitiveMetadata; },
      (c: any) => { c.sensitiveMetadata.ciphertext = "changed"; },
      (c: any) => { c.writerGeneration = 1; }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateStructure(input, JSON.stringify(changed))).toThrow();
    }
  });

  it("rejects missing or changed sealed routes and policy conditions", () => {
    const { input, candidate } = syntheticCandidate();
    for (const change of [
      (c: any) => { delete c.managedSshRoutes; },
      (c: any) => { c.managedSshRoutes[0].route.port = 23; },
      (c: any) => { delete c.approvalPolicyRules[0].conditions.envBindings; },
      (c: any) => { c.approvalPolicyRules[0].conditions.commands = ["/usr/bin/false"]; }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateStructure(input, JSON.stringify(changed))).toThrow();
    }
  });

  it("rejects missing, replaced, added, and duplicate request or audit IDs", () => {
    const { input, candidate } = syntheticCandidate();
    for (const change of [
      (c: any) => { c.requests = []; },
      (c: any) => { c.requests[0].id = "req_replaced"; },
      (c: any) => { c.requests.push({ ...c.requests[0], id: "req_extra" }); },
      (c: any) => { c.audit = []; },
      (c: any) => { c.audit[0].id = "audit_replaced"; },
      (c: any) => { c.audit.push({ ...c.audit[0] }); }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateStructure(input, JSON.stringify(changed))).toThrow();
    }
  });
});

describe("offline reconciliation candidate details", () => {
  it("compares decrypted donor detail and keeps migration blocked", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    const assessment = verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), evidence);

    expect(assessment.migrationBlocked).toBe(true);
    expect(JSON.stringify(assessment)).not.toMatch(/synthetic current reason|synthetic argument|synthetic audit/);
  });

  it("preserves every app-only history row and all its details", () => {
    const { app, donor } = fixture();
    app.requests.push({ ...app.requests[0], id: "req_new", reason: "new private reason" });
    app.audit.push({ ...app.audit[0], id: "audit_new", message: "new private audit" });
    const input = seal(app, donor);
    const candidate = { ...structuredClone(app), writerGeneration: 2,
      agentIdentities: structuredClone(donor.agentIdentities),
      sensitiveMetadata: structuredClone(donor.sensitiveMetadata) };
    const evidence = detailEvidence(input);
    expect(verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), evidence)
      .summary.appOnlyRequests).toBe(1);

    for (const change of [
      (c: any) => { c.requests[1].reason = "changed"; },
      (c: any) => { c.requests[1].action.args = []; },
      (c: any) => { c.audit[1].message = "changed"; },
      (c: any) => { c.requests.reverse(); },
      (c: any) => { c.audit.reverse(); }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(changed), evidence))
        .toThrow("Candidate request or audit detail");
    }
  });

  it("rejects same-ID candidate content changes hidden by the structural check", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    for (const change of [
      (c: any) => { c.requests[0].reason = "changed"; },
      (c: any) => { c.requests[0].action.args = ["changed"]; },
      (c: any) => { c.requests[0].action.http = { url: "https://other.test" }; },
      (c: any) => { c.requests[0].state = "executed"; },
      (c: any) => { c.requests[0].resultSummary = { stdout: "changed" }; },
      (c: any) => { c.audit[0].message = "changed"; },
      (c: any) => { c.audit[0].requestId = "req_other"; }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(changed), evidence))
        .toThrow("Candidate request or audit detail");
    }
  });

  it("keeps exact app-owned cache, grant, and optional fields", () => {
    const { app, donor } = fixture();
    (app.secrets[0] as any).cache = { backend: "onepassword", fingerprint: "synthetic-cache" };
    const grantFields = {
      actionKey: "env_command:synthetic", agentScope: "same-agent", agentName: "Synthetic Claude",
      principalId: "principal_one", agentSessionId: "session_one", loginSessionId: "login_one",
      createdAt: timestamp, updatedAt: timestamp, expiresAt: "2027-01-01T00:00:00.000Z",
      lastRequestId: "req_one"
    };
    Object.assign(app.approvalGrants[0], grantFields);
    Object.assign(donor.approvalGrants[0], grantFields);
    const input = seal(app, donor);
    const candidate = { ...structuredClone(app), writerGeneration: 2,
      agentIdentities: structuredClone(donor.agentIdentities),
      sensitiveMetadata: structuredClone(donor.sensitiveMetadata) };
    const evidence = detailEvidence(input);
    const candidateRaw = JSON.stringify(candidate);
    expect(() => verifyOfflineReconciliationCandidateDetails(input, candidateRaw, evidence)).not.toThrow();

    for (const change of [
      (c: any) => { c.secrets[0].cache.fingerprint = "changed"; },
      (c: any) => { delete c.secrets[0].cache; },
      (c: any) => { c.secrets[0].updatedAt = "2026-10-22T00:00:00.000Z"; },
      (c: any) => { c.approvalGrants[0].lastRequestId = "req_other"; },
      (c: any) => { c.approvalGrants[0].updatedAt = "2026-10-22T00:00:00.000Z"; },
      (c: any) => { c.credentialOps = []; }
    ]) {
      const changed = structuredClone(candidate);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateStructure(input, JSON.stringify(changed))).not.toThrow();
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(changed), evidence))
        .toThrow("Candidate app-owned fields differ");
    }

    for (const field of Object.keys(app.approvalGrants[0])) {
      const changed = structuredClone(candidate) as any;
      changed.approvalGrants[0][field] = "changed";
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(changed), evidence))
        .toThrow();
    }
  });

  it("rejects decrypted request and audit conflicts or missing envelope rows", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    for (const change of [
      (d: any) => { d.requests.req_one.reason = "different private reason"; },
      (d: any) => { d.requests.req_one.args = ["different private arg"]; },
      (d: any) => { d.audit.audit_one = "different private audit"; },
      (d: any) => { delete d.requests.req_one; },
      (d: any) => { d.requests.req_extra = { reason: "extra", args: [] }; },
      (d: any) => { delete d.audit.audit_one; },
      (d: any) => { d.audit.audit_extra = "extra"; },
      (d: any) => { d.requests.req_one.futureDetail = "unknown"; }
    ]) {
      const details = JSON.parse(evidence.decryptedDonorMetadataRaw);
      change(details);
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
        ...evidence, decryptedDonorMetadataRaw: JSON.stringify(details)
      })).toThrow();
    }
  });

  it("checks legacy sealed fields and newer fields left outside that envelope", () => {
    const { app, donor } = fixture();
    app.requests[0].action = {
      kind: "ssh_session", command: "ssh", args: ["private argument"],
      workingDir: "/private/work", ssh: {
        target: "synthetic@example.test", port: 22,
        transfer: { direction: "upload", sourcePath: "/private/source", destinationPath: "/private/dest" }
      }
    };
    (app.requests[0] as any).error = "private failure";
    (app.requests[0] as any).resultSummary = { stdout: "private stdout", stderr: "private stderr" };
    donor.requests[0] = structuredClone(app.requests[0]);
    donor.requests[0].reason = "";
    delete (donor.requests[0] as any).error;
    donor.requests[0].action.args = [];
    delete (donor.requests[0].action as any).workingDir;
    (donor.requests[0].action as any).ssh.target = "";
    (donor.requests[0] as any).resultSummary.stdout = "";
    (donor.requests[0] as any).resultSummary.stderr = "";
    const input = seal(app, donor);
    const candidate = { ...structuredClone(app), writerGeneration: 2,
      agentIdentities: structuredClone(donor.agentIdentities),
      sensitiveMetadata: structuredClone(donor.sensitiveMetadata) };
    const details = {
      requests: { req_one: { reason: app.requests[0].reason, args: app.requests[0].action.args,
        error: "private failure", workingDir: "/private/work", sshTarget: "synthetic@example.test",
        stdout: "private stdout", stderr: "private stderr" } },
      audit: { audit_one: app.audit[0].message }
    };
    const evidence = { ...detailEvidence(input), decryptedDonorMetadataRaw: JSON.stringify(details) };
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), evidence))
      .not.toThrow();

    for (const change of [
      (d: any) => { d.requests.req_one.workingDir = "/other"; },
      (d: any) => { d.requests.req_one.sshTarget = "other@example.test"; },
      (d: any) => { d.requests.req_one.stdout = "other output"; },
      (d: any) => { delete d.requests.req_one.stderr; },
      (d: any) => { d.requests.req_one.error = "other failure"; }
    ]) {
      const changed = structuredClone(details);
      change(changed);
      expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
        ...evidence, decryptedDonorMetadataRaw: JSON.stringify(changed)
      })).toThrow();
    }
    const changedDonor = structuredClone(donor);
    (changedDonor.requests[0].action as any).ssh.transfer.sourcePath = "/other/source";
    const changedInput = seal(app, changedDonor);
    expect(() => verifyOfflineReconciliationCandidateDetails(changedInput, JSON.stringify(candidate), {
      ...evidence, generationTwoLedgerSha256: sha(changedInput.generationTwoLedgerRaw)
    })).toThrow("request detail conflicts");
  });

  it("accepts a later closed app request but rejects conflicting lifecycle and origin", () => {
    const { input, candidate } = syntheticCandidate();
    const donor = JSON.parse(input.generationTwoLedgerRaw);
    donor.requests[0].state = "executing";
    donor.requests[0].updatedAt = "2026-10-20T00:00:00.000Z";
    const older = { ...input, generationTwoLedgerRaw: JSON.stringify(donor) };
    const evidence = detailEvidence(older);
    expect(() => verifyOfflineReconciliationCandidateDetails(older, JSON.stringify(candidate), evidence))
      .not.toThrow();

    for (const change of [
      (d: any) => { d.requests[0].updatedAt = "2026-10-22T00:00:00.000Z"; },
      (d: any) => { d.requests[0].action.injectEnv = "OTHER_TOKEN"; },
      (d: any) => { d.requests[0].approvalSource = "policy"; },
      (d: any) => { d.requests[0].state = "executed"; }
    ]) {
      const changed = structuredClone(donor);
      change(changed);
      const changedInput = { ...input, generationTwoLedgerRaw: JSON.stringify(changed) };
      expect(() => verifyOfflineReconciliationCandidateDetails(changedInput, JSON.stringify(candidate),
        detailEvidence(changedInput))).toThrow();
    }
  });

  it("rejects donor rows that were not redacted as the envelope format requires", () => {
    const { input, candidate } = syntheticCandidate();
    for (const change of [
      (d: any) => { d.requests[0].reason = "private reason outside the box"; },
      (d: any) => { d.requests[0].action.args = ["private arg outside the box"]; },
      (d: any) => { d.audit[0].message = "private audit outside the box"; }
    ]) {
      const donor = JSON.parse(input.generationTwoLedgerRaw);
      change(donor);
      const changedInput = { ...input, generationTwoLedgerRaw: JSON.stringify(donor) };
      expect(() => verifyOfflineReconciliationCandidateDetails(changedInput, JSON.stringify(candidate),
        detailEvidence(changedInput))).toThrow();
    }
  });

  it("requires independent anchors and rejects ambiguous JSON without echoing details", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
      ...evidence, generationTwoLedgerSha256: "0".repeat(64)
    })).toThrow("generation-2 ledger anchor");
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
      ...evidence, donorMetadataBoxSha256: "0".repeat(64)
    })).toThrow("metadata box anchor");
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
      ...evidence, sealedAppLedgerSha256: "0".repeat(64)
    })).toThrow("sealed-app ledger anchor");
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
      ...evidence, sealedAppHistorySha256: "0".repeat(64)
    })).toThrow("history anchor");
    const duplicateEnvelope = evidence.decryptedDonorMetadataRaw.replace(
      '"req_one":', '"req_one":{"reason":"hidden private reason","args":[]},"req_one":');
    expect(() => verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
      ...evidence, decryptedDonorMetadataRaw: duplicateEnvelope
    })).toThrow("duplicate key");
    const duplicateApp = input.sealedLedgerRaw.replace('"requests":', '"requests":[],"requests":');
    expect(() => verifyOfflineReconciliationCandidateDetails({ ...input, sealedLedgerRaw: duplicateApp },
      JSON.stringify(candidate), evidence)).toThrow("duplicate key");
    const nonFiniteNumber = input.sealedLedgerRaw.replace('"durationMs":900000', '"durationMs":1e309');
    expect(() => verifyOfflineReconciliationCandidateDetails({ ...input, sealedLedgerRaw: nonFiniteNumber },
      JSON.stringify(candidate), evidence)).toThrow("invalid number");
    let error: Error | undefined;
    try {
      verifyOfflineReconciliationCandidateDetails(input, JSON.stringify(candidate), {
        ...evidence, decryptedDonorMetadataRaw: "private malformed metadata"
      });
    } catch (caught) {
      error = caught as Error;
    }
    expect(error?.message).toMatch(/Invalid offline reconciliation JSON/);
    expect(error?.message).not.toContain("private malformed metadata");
  });

  it("rejects donor identity tampering even when box and app-history hashes still match", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    const donor = JSON.parse(input.generationTwoLedgerRaw);
    donor.agentIdentities[0].customName = "changed identity";
    const changedInput = { ...input, generationTwoLedgerRaw: JSON.stringify(donor) };
    const changedCandidate = structuredClone(candidate);
    changedCandidate.agentIdentities[0].customName = "changed identity";
    const changedEvidence = detailEvidence(changedInput);
    expect(changedEvidence.donorMetadataBoxSha256).toBe(evidence.donorMetadataBoxSha256);
    expect(changedEvidence.sealedAppHistorySha256).toBe(evidence.sealedAppHistorySha256);
    expect(() => verifyOfflineReconciliationCandidateStructure(changedInput, JSON.stringify(changedCandidate)))
      .not.toThrow();
    expect(() => verifyOfflineReconciliationCandidateDetails(changedInput,
      JSON.stringify(changedCandidate), evidence)).toThrow("generation-2 ledger anchor");
  });

  it("rejects coordinated app and candidate bookkeeping changes outside the control fingerprint", () => {
    const { input, candidate } = syntheticCandidate();
    const evidence = detailEvidence(input);
    const app = JSON.parse(input.sealedLedgerRaw);
    app.secrets[0].cache = { backend: "onepassword", fingerprint: "changed cache" };
    app.approvalGrants[0].lastRequestId = "req_other";
    const changedInput = { ...input, sealedLedgerRaw: JSON.stringify(app) };
    const changedCandidate = structuredClone(candidate) as any;
    changedCandidate.secrets = app.secrets;
    changedCandidate.approvalGrants = app.approvalGrants;
    const changedEvidence = detailEvidence(changedInput);
    expect(changedEvidence.sealedAppHistorySha256).toBe(evidence.sealedAppHistorySha256);
    expect(() => verifyOfflineReconciliationCandidateStructure(changedInput, JSON.stringify(changedCandidate)))
      .not.toThrow();
    expect(() => verifyOfflineReconciliationCandidateDetails(changedInput,
      JSON.stringify(changedCandidate), evidence)).toThrow("sealed-app ledger anchor");
  });
});
