import { createHash } from "node:crypto";
import path from "node:path";
import { parseTree, type Node as JsonNode, type ParseError } from "jsonc-parser";
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

export interface OfflineDecryptedDonorEvidence {
  /** Authenticated decryption of the exact generation-2 sensitiveMetadata box, supplied by the caller. */
  decryptedDonorMetadataRaw: string;
  /** SHA-256 of the exact generation-2 ledger bytes from the trusted paired snapshot. */
  generationTwoLedgerSha256: string;
  /** SHA-256 of the canonical encrypted box passed to the trusted decryptor. */
  donorMetadataBoxSha256: string;
  /** SHA-256 of the exact sealed-app ledger bytes from the trusted paired snapshot. */
  sealedAppLedgerSha256: string;
  /** Independently captured SHA-256 of canonical { requests, audit } from the sealed app snapshot. */
  sealedAppHistorySha256: string;
}

const appOnlyRuleFields = new Set(["envBindings", "resolvedCommands", "principalIds", "actionKeys"]);
const terminalStates = new Set(["denied", "executed", "failed"]);
const requestStates = new Set([...terminalStates, "pending", "approved", "executing"]);
const appLedgerFields = new Set([
  "version", "secrets", "requests", "audit", "approvalSettings", "approvalGrants",
  "approvalPolicyRules", "managedSshRoutes", "credentialOps", "consoleAccess"
]);
const donorLedgerFields = new Set([
  "version", "writerGeneration", "secrets", "requests", "agentIdentities", "audit",
  "approvalSettings", "approvalGrants", "approvalPolicyRules", "sensitiveMetadata"
]);
const candidateLedgerFields = new Set([...appLedgerFields, ...donorLedgerFields]);
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

// Keep this preflight separate from the encrypted-history migration.
export function verifyOfflineReconciliationCandidateStructure(
    input: OfflineReconciliationInput, candidateRaw: string): OfflineReconciliationAssessment {
  const assessment = assessOfflineLedgerReconciliation(input);
  const app = parseLedger(input.sealedLedgerRaw);
  const donor = parseLedger(input.generationTwoLedgerRaw);
  const candidate = parseLedger(candidateRaw);
  assertKnownFields(candidate, candidateLedgerFields, "candidate ledger");
  const format = inspectLedgerFormat(candidateRaw);
  if (format.shape !== "mixed" || format.writerGeneration !== 2
      || !format.hasEncryptedSensitiveMetadata || format.unknownConditionFields) {
    throw new Error("The candidate is not the expected mixed ledger structure.");
  }
  if (controlFingerprint(candidate) !== assessment.summary.controlFingerprint) {
    throw new Error("Candidate control authority differs from the sealed ledger.");
  }
  compareRecords(requiredArray(donor.agentIdentities, "agent identities"),
    requiredArray(candidate.agentIdentities, "agent identities"), "id", []);
  if (canonical(candidate.sensitiveMetadata) !== canonical(donor.sensitiveMetadata)) {
    throw new Error("Candidate encrypted metadata differs from the generation-2 donor.");
  }
  assertSameIds(app.requests, candidate.requests);
  assertSameIds(app.audit, candidate.audit);
  return assessment;
}

/** Checks supplied history. The caller authenticates box decryption and full-donor/app snapshot anchors. */
export function verifyOfflineReconciliationCandidateDetails(input: OfflineReconciliationInput,
    candidateRaw: string, evidence: OfflineDecryptedDonorEvidence): OfflineReconciliationAssessment {
  for (const raw of [input.sealedLedgerRaw, input.controlManifestRaw, input.checkpointRaw,
    input.recoveryHeadRaw, input.generationTwoLedgerRaw, candidateRaw, evidence.decryptedDonorMetadataRaw]) {
    assertNoDuplicateJsonKeys(raw);
  }
  const assessment = verifyOfflineReconciliationCandidateStructure(input, candidateRaw);
  const app = parseLedger(input.sealedLedgerRaw);
  const donor = parseLedger(input.generationTwoLedgerRaw);
  const candidate = parseLedger(candidateRaw);
  if (evidence.generationTwoLedgerSha256 !== digest(input.generationTwoLedgerRaw)) {
    throw new Error("Trusted generation-2 ledger anchor differs from the donor snapshot.");
  }
  if (evidence.donorMetadataBoxSha256 !== digest(canonical(donor.sensitiveMetadata))) {
    throw new Error("Trusted generation-2 metadata box anchor differs from the donor.");
  }
  if (evidence.sealedAppLedgerSha256 !== digest(input.sealedLedgerRaw)) {
    throw new Error("Trusted sealed-app ledger anchor differs from the snapshot.");
  }
  if (evidence.sealedAppHistorySha256 !== digest(canonical({ requests: app.requests, audit: app.audit }))) {
    throw new Error("Trusted sealed-app history anchor differs from the snapshot.");
  }

  const details = parseDonorDetails(evidence.decryptedDonorMetadataRaw);
  const appRequests = recordsByKey(app.requests, "id");
  const appAudit = recordsByKey(app.audit, "id");
  const donorRequests = recordsByKey(donor.requests, "id");
  const donorAudit = recordsByKey(donor.audit, "id");
  assertSameIds(donor.requests, [...details.requests.keys()].map((id) => ({ id })),
    "Generation-2 request envelope IDs differ from donor history.");
  assertSameIds(donor.audit, [...details.audit.keys()].map((id) => ({ id })),
    "Generation-2 audit envelope IDs differ from donor history.");

  for (const [id, donorRow] of donorRequests) {
    const appRow = appRequests.get(id);
    const detail = details.requests.get(id);
    if (!appRow || !detail) throw new Error("Generation-2 request detail IDs differ from history.");
    assertSharedRequestDetail(appRow, donorRow, detail);
  }
  for (const [id, donorRow] of donorAudit) {
    const appRow = appAudit.get(id);
    const message = details.audit.get(id);
    if (!appRow || message === undefined || donorRow.message !== ""
        || canonical({ ...donorRow, message }) !== canonical(appRow)) {
      throw new Error("Generation-2 audit detail conflicts with sealed app history.");
    }
  }
  if (canonical(candidate.requests) !== canonical(app.requests)
      || canonical(candidate.audit) !== canonical(app.audit)) {
    throw new Error("Candidate request or audit detail differs from the sealed app history.");
  }
  if (canonical(without(candidate, ["writerGeneration", "agentIdentities", "sensitiveMetadata"]))
      !== canonical(app)) {
    throw new Error("Candidate app-owned fields differ from the sealed app ledger.");
  }
  return assessment;
}

interface DonorRequestDetail extends Record<string, unknown> {
  reason: string;
  args: string[];
  error?: string;
  workingDir?: string;
  sshTarget?: string;
  stdout?: string;
  stderr?: string;
}

function parseDonorDetails(raw: string): {
    requests: Map<string, DonorRequestDetail>; audit: Map<string, string> } {
  const envelope = parseObject(raw, "generation-2 decrypted metadata");
  if (Object.keys(envelope).length !== 2 || !Object.hasOwn(envelope, "requests")
      || !Object.hasOwn(envelope, "audit")) {
    throw new Error("Invalid generation-2 decrypted metadata.");
  }
  const requestValues = asObject(envelope.requests);
  const auditValues = asObject(envelope.audit);
  if (!requestValues || !auditValues) throw new Error("Invalid generation-2 decrypted metadata.");

  const requests = new Map<string, DonorRequestDetail>();
  for (const [id, value] of Object.entries(requestValues)) {
    const detail = asObject(value);
    if (!id || !detail || typeof detail.reason !== "string" || !Array.isArray(detail.args)
        || detail.args.some((arg) => typeof arg !== "string")
        || Object.keys(detail).some((field) => ![
          "reason", "args", "error", "workingDir", "sshTarget", "stdout", "stderr"
        ].includes(field))) {
      throw new Error("Invalid generation-2 request detail.");
    }
    for (const field of ["error", "workingDir", "sshTarget", "stdout", "stderr"]) {
      if (detail[field] !== undefined && typeof detail[field] !== "string") {
        throw new Error("Invalid generation-2 request detail.");
      }
    }
    requests.set(id, detail as DonorRequestDetail);
  }
  const audit = new Map<string, string>();
  for (const [id, message] of Object.entries(auditValues)) {
    if (!id || typeof message !== "string") throw new Error("Invalid generation-2 audit detail.");
    audit.set(id, message);
  }
  return { requests, audit };
}

function assertSharedRequestDetail(appRow: Record<string, unknown>, donorRow: Record<string, unknown>,
    detail: DonorRequestDetail): void {
  const action = asObject(donorRow.action);
  const ssh = asObject(action?.ssh);
  const result = asObject(donorRow.resultSummary);
  if (!action || !Array.isArray(action.args) || action.args.length
      || (action.ssh !== undefined && !ssh)
      || (donorRow.resultSummary !== undefined && !result)) {
    throw new Error("Invalid generation-2 redacted request row or detail.");
  }
  if (donorRow.reason !== "" || Object.hasOwn(donorRow, "error")
      || Object.hasOwn(action, "workingDir") || (ssh && ssh.target !== "")
      || (result && (result.stdout !== "" || result.stderr !== ""))) {
    throw new Error("Invalid generation-2 redacted request row or detail.");
  }
  if ((ssh && detail.sshTarget === undefined) || (!ssh && detail.sshTarget !== undefined)
      || (result && (detail.stdout === undefined || detail.stderr === undefined))
      || (!result && (detail.stdout !== undefined || detail.stderr !== undefined))) {
    throw new Error("Invalid generation-2 redacted request row or detail.");
  }

  const restored = structuredClone(donorRow);
  const restoredAction = restored.action as Record<string, unknown>;
  restored.reason = detail.reason;
  restoredAction.args = detail.args;
  if (detail.error !== undefined) restored.error = detail.error;
  if (detail.workingDir !== undefined) restoredAction.workingDir = detail.workingDir;
  if (ssh) (restoredAction.ssh as Record<string, unknown>).target = detail.sshTarget;
  if (result) {
    const output = restored.resultSummary as Record<string, unknown>;
    output.stdout = detail.stdout;
    output.stderr = detail.stderr;
  }

  if (terminalStates.has(donorRow.state as string)) {
    if (canonical(restored) !== canonical(appRow)) {
      throw new Error("Generation-2 request detail conflicts with sealed app history.");
    }
    return;
  }
  const allowedEndStates = donorRow.state === "executing"
    ? new Set(["executed", "failed"]) : terminalStates;
  const donorTime = typeof donorRow.updatedAt === "string" ? Date.parse(donorRow.updatedAt) : NaN;
  const appTime = typeof appRow.updatedAt === "string" ? Date.parse(appRow.updatedAt) : NaN;
  const changingFields = ["state", "updatedAt", "approvedAt", "approvalSource", "approvalGrantId",
    "approvalPolicyRuleId", "deniedAt", "executedAt", "resultSummary", "error"];
  if (!allowedEndStates.has(appRow.state as string) || !Number.isFinite(donorTime)
      || !Number.isFinite(appTime) || appTime < donorTime
      || canonical(without(restored, changingFields)) !== canonical(without(appRow, changingFields))) {
    throw new Error("Generation-2 request provenance conflicts with sealed app history.");
  }
  for (const field of changingFields.slice(2)) {
    if (Object.hasOwn(restored, field) && canonical(restored[field]) !== canonical(appRow[field])) {
      throw new Error("Generation-2 request lifecycle conflicts with sealed app history.");
    }
  }
}

function assertNoDuplicateJsonKeys(raw: string): void {
  const errors: ParseError[] = [];
  const tree = parseTree(raw, errors, { disallowComments: true });
  if (!tree || errors.length) throw new Error("Invalid offline reconciliation JSON.");
  function check(node: JsonNode): void {
    if (node.type === "number" && !Number.isFinite(node.value)) {
      throw new Error("Offline reconciliation JSON has an invalid number.");
    }
    if (node.type === "object") {
      const keys = new Set<string>();
      for (const property of node.children || []) {
        const key = property.children?.[0]?.value;
        if (typeof key !== "string" || keys.has(key)) {
          throw new Error("Offline reconciliation JSON has a duplicate key.");
        }
        keys.add(key);
      }
    }
    for (const child of node.children || []) check(child);
  }
  check(tree);
}

function assertSameIds(expected: Record<string, unknown>[], actual: Record<string, unknown>[],
    error = "Candidate history IDs differ from the sealed ledger."): void {
  const original = recordsByKey(expected, "id");
  const candidate = recordsByKey(actual, "id");
  if (original.size !== candidate.size || [...original.keys()].some((id) => !candidate.has(id))) {
    throw new Error(error);
  }
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
  if ((app.consoleAccess !== undefined && app.consoleAccess !== "protected")
      || (checkpoint.consoleAccess !== undefined && checkpoint.consoleAccess !== "protected")) {
    throw new Error("Invalid console access policy in sealed app ledger.");
  }
  const fingerprint = controlFingerprint(app);
  const checkpointHash = controlFingerprint(checkpoint);
  const checkpointName = /^checkpoint-\d{13}-[A-Za-z0-9_-]+-([a-f0-9]{64})\.json$/
    .exec(input.checkpointName);
  // A later writer may change the fingerprint or checkpoint format.
  if (!checkpointName || manifest.version !== 1 || manifest.recoverySealed !== true
      || typeof manifest.updatedAt !== "string"
      || (manifest.writerVersion !== "0.1.22" && manifest.writerVersion !== "0.1.23")
      || (manifest.writerVersion === "0.1.22" && app.consoleAccess === "protected")
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
    ...(ledger.consoleAccess === "protected" ? { consoleAccess: ledger.consoleAccess } : {}),
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
