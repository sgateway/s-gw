import { createHash } from "node:crypto";
import path from "node:path";
import { inspectLedgerFormat } from "./ledger-format-inspection.js";

interface Ledger extends Record<string, unknown> {
  version: 1;
  secrets: Record<string, unknown>[];
  requests: Record<string, unknown>[];
  audit: Record<string, unknown>[];
  approvalSettings: Record<string, unknown>;
  approvalGrants: Record<string, unknown>[];
  approvalPolicyRules: Record<string, unknown>[];
}

export interface OfflineReconciliationInput {
  sealedLedgerRaw: string;
  controlManifestRaw: string;
  checkpointName: string;
  checkpointRaw: string;
  recoveryHeadRaw: string;
  generationTwoLedgerRaw: string;
  originalHome: string;
  originalRecoveryHome: string;
  pendingControlRaw: string | null;
}

export interface OfflineReconciliationSummary {
  secrets: number;
  grants: number;
  rules: number;
  routes: number;
  requests: number;
  audit: number;
  donorIdentityRecords: number;
  ruleFieldsOnlyInSeal: number;
  appOnlyRequests: number;
  appOnlyAudit: number;
  donorOpenRequests: number;
  plaintextRequestRows: number;
  plaintextAuditRows: number;
  donorPlaintextRequestRows: number;
  donorPlaintextAuditRows: number;
  controlFingerprint: string;
}

export interface OfflineReconciliationAssessment {
  migrationBlocked: true;
  blockingReasons: string[];
  summary: OfflineReconciliationSummary;
}

const appOnlyRuleFields = new Set(["envBindings", "resolvedCommands", "principalIds", "actionKeys"]);
const terminalStates = new Set(["denied", "executed", "failed"]);
const requestStates = new Set([...terminalStates, "pending", "approved", "executing"]);
const appLedgerFields = new Set([
  "version", "secrets", "requests", "audit", "approvalSettings", "approvalGrants",
  "approvalPolicyRules", "managedSshRoutes", "credentialOps"
]);
const donorLedgerFields = new Set([
  "version", "writerGeneration", "secrets", "requests", "agentIdentities", "audit",
  "approvalSettings", "approvalGrants", "approvalPolicyRules", "sensitiveMetadata"
]);
const controlManifestFields = new Set([
  "version", "fingerprint", "updatedAt", "secrets", "approvalPolicyRules",
  "recoverySealed", "recoveryCheckpoint", "recoveryVaultId", "recoveryNamespace", "writerVersion"
]);
const recoveryHeadFields = new Set(["version", "checkpoint", "fingerprint"]);

/** Pure assessment for a quiesced, paired home/recovery snapshot. It never reads or writes files. */
export function assessOfflineLedgerReconciliation(input: OfflineReconciliationInput): OfflineReconciliationAssessment {
  const app = parseLedger(input.sealedLedgerRaw);
  const donor = parseLedger(input.generationTwoLedgerRaw);
  const checkpoint = parseLedger(input.checkpointRaw);
  assertKnownFields(app, appLedgerFields, "ledger");
  assertKnownFields(donor, donorLedgerFields, "ledger");
  assertKnownFields(checkpoint, appLedgerFields, "ledger");
  const appFormat = inspectLedgerFormat(input.sealedLedgerRaw);
  const donorFormat = inspectLedgerFormat(input.generationTwoLedgerRaw);
  assertExpectedFormats(input, appFormat);

  assertSealedControl(input, app, checkpoint);
  assertNoStagedCredentialOps(app);
  const restoredFields = assertDonorAuthority(app, donor);
  const appRequests = recordsByKey(app.requests, "id");
  const appAudit = recordsByKey(app.audit, "id");
  const donorRequests = recordsByKey(donor.requests, "id");
  const donorAudit = recordsByKey(donor.audit, "id");
  assertSharedHistoryProvenance(appRequests, donorRequests, "request");
  assertSharedHistoryProvenance(appAudit, donorAudit, "audit");
  for (const request of donor.requests) {
    if (!requestStates.has(request.state as string)) {
      throw new Error("Invalid generation-2 request state.");
    }
  }

  assertClosedHistory(app);

  const identities = requiredArray(donor.agentIdentities, "agent identities");
  recordsByKey(identities, "id");
  return {
    migrationBlocked: true,
    blockingReasons: [
      "A trusted offline process must decrypt the generation-2 envelope, reconcile each history ID against the sealed app ledger, and re-encrypt the chosen details. Opaque envelope grafting can overwrite newer history.",
      "One compatible writer must round-trip agent identities, managed SSH routes, every policy condition, and format-aware encrypted history. The generation-2 writer omits current HTTP fields and SSH transfer paths.",
      "The plaintext app ledger, journal, and retained backups need an approved encryption or retention migration before installation. Locked Usage Flow detail visibility also needs an operator decision."
    ],
    summary: {
      secrets: app.secrets.length,
      grants: app.approvalGrants.length,
      rules: app.approvalPolicyRules.length,
      routes: optionalArray(app.managedSshRoutes, "managed routes").length,
      requests: app.requests.length,
      audit: app.audit.length,
      donorIdentityRecords: identities.length,
      ruleFieldsOnlyInSeal: restoredFields,
      appOnlyRequests: appRequests.size - donorRequests.size,
      appOnlyAudit: appAudit.size - donorAudit.size,
      donorOpenRequests: donor.requests.filter((request) => !terminalStates.has(request.state as string)).length,
      plaintextRequestRows: appFormat.plaintextRequestRows,
      plaintextAuditRows: appFormat.plaintextAuditRows,
      donorPlaintextRequestRows: donorFormat.plaintextRequestRows,
      donorPlaintextAuditRows: donorFormat.plaintextAuditRows,
      controlFingerprint: controlFingerprint(app)
    }
  };
}

function assertKnownFields(record: Record<string, unknown>, fields: Set<string>, name: string): void {
  for (const field of Object.keys(record)) {
    if (!fields.has(field)) {
      throw new Error(`An unrecognized ${name} field requires a separate migration review.`);
    }
  }
}

function assertExpectedFormats(input: OfflineReconciliationInput,
    appFormat: ReturnType<typeof inspectLedgerFormat>): void {
  const donorFormat = inspectLedgerFormat(input.generationTwoLedgerRaw);
  if (appFormat.shape !== "app" || donorFormat.shape !== "generation-2"
      || donorFormat.writerGeneration !== 2 || !donorFormat.hasEncryptedSensitiveMetadata) {
    throw new Error("The ledger formats are not the expected sealed-app and generation-2 pair.");
  }
  if (appFormat.unknownConditionFields || donorFormat.unknownConditionFields) {
    throw new Error("An unrecognized rule condition requires a separate migration review.");
  }
  if (input.pendingControlRaw !== null) {
    throw new Error("A pending control-plane write requires a separate recovery decision.");
  }
}

function assertClosedHistory(app: Ledger): void {
  for (const request of app.requests) {
    if (!terminalStates.has(request.state as string)) {
      throw new Error("The sealed ledger still has an open request; authority must be closed before assessment.");
    }
  }
}

function assertSealedControl(input: OfflineReconciliationInput, app: Ledger, checkpoint: Ledger): void {
  const manifest = parseObject(input.controlManifestRaw, "control manifest");
  const head = parseObject(input.recoveryHeadRaw, "recovery head");
  assertKnownFields(manifest, controlManifestFields, "control manifest");
  assertKnownFields(head, recoveryHeadFields, "recovery head");
  const fingerprint = controlFingerprint(app);
  const checkpointHash = controlFingerprint(checkpoint);
  const checkpointName = /^checkpoint-\d{13}-[A-Za-z0-9_-]+-([a-f0-9]{64})\.json$/
    .exec(input.checkpointName);
  // A later writer may change the fingerprint or checkpoint format.
  if (!checkpointName || manifest.version !== 1 || manifest.recoverySealed !== true
      || typeof manifest.updatedAt !== "string"
      || manifest.writerVersion !== "0.1.22"
      || manifest.fingerprint !== fingerprint || checkpointHash !== fingerprint
      || checkpointName[1] !== fingerprint || manifest.recoveryCheckpoint !== input.checkpointName
      || manifest.secrets !== app.secrets.length
      || manifest.approvalPolicyRules !== app.approvalPolicyRules.length
      || head.version !== 1 || head.checkpoint !== input.checkpointName
      || head.fingerprint !== fingerprint) {
    throw new Error("The sealed app control plane does not match its manifest and recovery checkpoint.");
  }
  if (!path.isAbsolute(input.originalHome) || !path.isAbsolute(input.originalRecoveryHome)) {
    throw new Error("Original home and recovery paths must be absolute.");
  }
  const namespace = digest(path.resolve(input.originalHome)).slice(0, 24);
  const vaultId = digest(path.resolve(input.originalRecoveryHome));
  if (manifest.recoveryNamespace !== namespace || manifest.recoveryVaultId !== vaultId) {
    throw new Error("The sealed control manifest belongs to a different home or recovery vault.");
  }
  if (checkpoint.requests.length || checkpoint.audit.length) {
    throw new Error("The sealed control checkpoint unexpectedly contains history.");
  }
  if (Object.hasOwn(checkpoint, "writerGeneration") || Object.hasOwn(checkpoint, "sensitiveMetadata")) {
    throw new Error("The sealed control checkpoint has unsupported generation-2 fields.");
  }
  if (Object.hasOwn(checkpoint, "agentIdentities")) {
    throw new Error("The sealed control checkpoint has unsupported generation-2 fields.");
  }
}

function assertNoStagedCredentialOps(app: Ledger): void {
  if (optionalArray(app.credentialOps, "staged credential operations").length) {
    throw new Error("A staged credential transaction requires a separate recovery decision.");
  }
}

function assertDonorAuthority(app: Ledger, donor: Ledger): number {
  compareRecords(app.secrets, donor.secrets, "handle", ["cache", "updatedAt"]);
  compareRecords(app.approvalGrants, donor.approvalGrants, "id", ["lastRequestId", "updatedAt"]);
  if (canonical(app.approvalSettings) !== canonical(donor.approvalSettings)) {
    throw new Error("Generation-2 approval settings differ from sealed authority.");
  }

  const appRules = recordsByKey(app.approvalPolicyRules, "id");
  const donorRules = recordsByKey(donor.approvalPolicyRules, "id");
  if (appRules.size !== donorRules.size) {
    throw new Error("Generation-2 rule IDs differ from sealed authority.");
  }
  let restoredFields = 0;
  for (const [id, rule] of appRules) {
    const other = donorRules.get(id);
    if (!other) throw new Error("Generation-2 rule IDs differ from sealed authority.");
    const { conditions, ...appRule } = rule;
    const { conditions: donorConditions, ...donorRule } = other;
    if (canonical(appRule) !== canonical(donorRule)) {
      throw new Error("Generation-2 rule metadata differs from sealed authority.");
    }
    const appFields = asObject(conditions);
    const donorFields = asObject(donorConditions);
    if (!appFields || !donorFields) throw new Error("Invalid rule conditions.");
    for (const [field, value] of Object.entries(donorFields)) {
      if (!Object.hasOwn(appFields, field) || canonical(value) !== canonical(appFields[field])) {
        throw new Error("Generation-2 rule condition conflicts with sealed authority.");
      }
    }
    for (const field of Object.keys(appFields)) {
      if (Object.hasOwn(donorFields, field)) continue;
      if (!appOnlyRuleFields.has(field)) {
        throw new Error("An unexpected rule condition is absent from the generation-2 donor.");
      }
      restoredFields += 1;
    }
  }
  return restoredFields;
}

function assertSharedHistoryProvenance(app: Map<string, Record<string, unknown>>,
    donor: Map<string, Record<string, unknown>>, kind: "request" | "audit"): void {
  for (const [id, donorRow] of donor) {
    const appRow = app.get(id);
    if (!appRow) {
      throw new Error("Generation-2 history contains an ID missing from the sealed ledger.");
    }
    const appOrigin = kind === "request"
      ? [appRow.handle, appRow.createdAt, asObject(appRow.action)?.kind, asObject(appRow.action)?.command]
      : [appRow.ts, appRow.type, appRow.handle, appRow.requestId];
    const donorOrigin = kind === "request"
      ? [donorRow.handle, donorRow.createdAt, asObject(donorRow.action)?.kind, asObject(donorRow.action)?.command]
      : [donorRow.ts, donorRow.type, donorRow.handle, donorRow.requestId];
    const requiredFields = kind === "request" ? 4 : 2;
    for (let index = 0; index < requiredFields; index += 1) {
      if (typeof appOrigin[index] !== "string" || !appOrigin[index]
          || typeof donorOrigin[index] !== "string" || !donorOrigin[index]) {
        throw new Error("Invalid shared history provenance.");
      }
    }
    if (appOrigin.some((field, index) => field !== donorOrigin[index])) {
      throw new Error("Generation-2 history provenance conflicts with the sealed ledger.");
    }
  }
}

function compareRecords(first: Record<string, unknown>[], second: Record<string, unknown>[],
    key: "id" | "handle", ignored: string[]): void {
  const app = recordsByKey(first, key);
  const donor = recordsByKey(second, key);
  if (app.size !== donor.size) throw new Error("Generation-2 control IDs differ from sealed authority.");
  for (const [id, record] of app) {
    const other = donor.get(id);
    if (!other || canonical(without(record, ignored)) !== canonical(without(other, ignored))) {
      throw new Error("Generation-2 control authority differs from the sealed ledger.");
    }
  }
}

function controlFingerprint(ledger: Ledger): string {
  const secrets = ledger.secrets.map((record) => without(record, ["cache", "updatedAt"]))
    .sort((a, b) => String(a.handle).localeCompare(String(b.handle)));
  const grants = ledger.approvalGrants.map((record) => without(record, ["lastRequestId", "updatedAt"]))
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const rules = [...ledger.approvalPolicyRules]
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  const routes = optionalArray(ledger.managedSshRoutes, "managed routes")
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  recordsByKey(routes, "id");
  const credentialOps = optionalArray(ledger.credentialOps, "staged credential operations")
    .sort((a, b) => String(a.id).localeCompare(String(b.id)));
  recordsByKey(credentialOps, "id");
  const control = {
    version: ledger.version,
    secrets,
    approvalSettings: ledger.approvalSettings,
    approvalGrants: grants,
    approvalPolicyRules: rules,
    ...(routes.length ? { managedSshRoutes: routes } : {}),
    ...(credentialOps.length ? { credentialOps } : {})
  };
  return digest(canonical(control));
}

function without(record: Record<string, unknown>, ignored: string[]): Record<string, unknown> {
  const copy = { ...record };
  for (const field of ignored) delete copy[field];
  return copy;
}

function recordsByKey(values: Record<string, unknown>[], key: "id" | "handle"): Map<string, Record<string, unknown>> {
  const records = new Map<string, Record<string, unknown>>();
  for (const value of values) {
    const id = value[key];
    if (typeof id !== "string" || !id || records.has(id)) {
      throw new Error("Invalid or duplicate ledger record ID.");
    }
    records.set(id, value);
  }
  return records;
}

function parseLedger(raw: string): Ledger {
  const value = parseObject(raw, "ledger");
  if (value.version !== 1 || !asObject(value.approvalSettings)) {
    throw new Error("Unsupported ledger structure.");
  }
  for (const key of ["secrets", "requests", "audit", "approvalGrants", "approvalPolicyRules"] as const) {
    value[key] = requiredArray(value[key], key);
  }
  return value as Ledger;
}

function requiredArray(value: unknown, name: string): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.some((entry) => !asObject(entry))) {
    throw new Error(`Invalid ${name} collection.`);
  }
  return value as Record<string, unknown>[];
}

function optionalArray(value: unknown, name: string): Record<string, unknown>[] {
  return value === undefined ? [] : requiredArray(value, name);
}

function parseObject(raw: string, name: string): Record<string, unknown> {
  try {
    const value = asObject(JSON.parse(raw));
    if (value) return value;
  } catch { /* malformed input is reported without echoing it */ }
  throw new Error(`Invalid ${name} JSON.`);
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = asObject(value);
  if (object) {
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
