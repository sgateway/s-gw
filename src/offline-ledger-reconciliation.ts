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

/** Pure assessment for a quiesced, paired home/recovery snapshot. It never reads or writes files. */
export function assessOfflineLedgerReconciliation(input: OfflineReconciliationInput): OfflineReconciliationAssessment {
  const app = parseLedger(input.sealedLedgerRaw);
  const donor = parseLedger(input.generationTwoLedgerRaw);
  const checkpoint = parseLedger(input.checkpointRaw);
  const appFormat = inspectLedgerFormat(input.sealedLedgerRaw);
  const donorFormat = inspectLedgerFormat(input.generationTwoLedgerRaw);
  assertExpectedFormats(input, appFormat);

  assertSealedControl(input, app, checkpoint);
  const restoredFields = assertDonorAuthority(app, donor);
  const appRequests = recordsByKey(app.requests, "id");
  const appAudit = recordsByKey(app.audit, "id");
  assertDonorHistoryIsPresent(appRequests, recordsByKey(donor.requests, "id"));
  assertDonorHistoryIsPresent(appAudit, recordsByKey(donor.audit, "id"));

  assertClosedHistory(app);

  const identities = requiredArray(donor.agentIdentities, "agent identities");
  recordsByKey(identities, "id");
  return {
    migrationBlocked: true,
    blockingReasons: [
      "A trusted offline process must decrypt the generation-2 envelope, reconcile each history ID against the sealed app ledger, and re-encrypt the chosen details. Opaque envelope grafting can overwrite newer history.",
      "One compatible writer must round-trip agent identities, managed SSH routes, every policy condition, and format-aware encrypted history. The generation-2 writer omits current HTTP fields and SSH transfer paths.",
      "The plaintext app ledger, journal, and retained backups need an approved encryption or retention migration before installation."
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
      plaintextRequestRows: appFormat.plaintextRequestRows,
      plaintextAuditRows: appFormat.plaintextAuditRows,
      donorPlaintextRequestRows: donorFormat.plaintextRequestRows,
      donorPlaintextAuditRows: donorFormat.plaintextAuditRows,
      controlFingerprint: controlFingerprint(app)
    }
  };
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
  const fingerprint = controlFingerprint(app);
  const checkpointHash = controlFingerprint(checkpoint);
  const checkpointName = /^checkpoint-\d{13}-[A-Za-z0-9_-]+-([a-f0-9]{64})\.json$/
    .exec(input.checkpointName);
  // A later writer may change the fingerprint or checkpoint format.
  if (!checkpointName || manifest.version !== 1 || manifest.recoverySealed !== true
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

function assertDonorHistoryIsPresent(app: Map<string, Record<string, unknown>>, donor: Map<string, Record<string, unknown>>): void {
  for (const id of donor.keys()) {
    if (!app.has(id)) {
      throw new Error("Generation-2 history contains an ID missing from the sealed ledger.");
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
  const control = {
    version: ledger.version,
    secrets,
    approvalSettings: ledger.approvalSettings,
    approvalGrants: grants,
    approvalPolicyRules: rules,
    ...(routes.length ? { managedSshRoutes: routes } : {})
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
