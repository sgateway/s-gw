import { isDeepStrictEqual } from "node:util";
import { parseTree, type Node as JsonNode, type ParseError } from "jsonc-parser";
import { assessOfflineLedgerReconciliation, type OfflineReconciliationInput } from "./offline-ledger-reconciliation.js";
import { sealHistory, type HistoryRows } from "./sealed-history-codec.js";
import { verifySealedHistoryClone, type SealedHistoryCloneCheck } from "./sealed-history-clone-verifier.js";
import type { AuditEvent, RequestRecord } from "./types.js";

interface LegacyBox {
  alg: "aes-256-gcm";
  kdf: "scrypt";
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

interface LegacyRequestDetail extends Record<string, unknown> {
  reason: string;
  args: string[];
  error?: string;
  workingDir?: string;
  sshTarget?: string;
  stdout?: string;
  stderr?: string;
}

export interface SyntheticHistoryMigrationInput {
  reconciliation: OfflineReconciliationInput;
  unwrapLegacyMetadata: (box: LegacyBox) => string;
  key: Uint8Array;
  expectedRevisions: ReadonlyMap<string, number>;
  leakMarkers: readonly string[];
  /** SHA-256 of JSON.stringify(the independently snapshotted history rows and revisions). */
  trustedBaselineSha256: string;
}

export interface SyntheticHistoryMigrationResult {
  primaryRaw: string;
  fullBackupRaws: string[];
  recoveryCopyRaws: string[];
  journalSegmentRaws: string[];
  check: SealedHistoryCloneCheck;
}

// This never opens a store. The caller supplies a trusted synthetic unwrapping step and anchor.
export function buildSyntheticHistoryMigration(input: SyntheticHistoryMigrationInput): SyntheticHistoryMigrationResult {
  assertNoDuplicateJsonKeys(input.reconciliation.sealedLedgerRaw);
  assertNoDuplicateJsonKeys(input.reconciliation.generationTwoLedgerRaw);
  assessOfflineLedgerReconciliation(input.reconciliation);
  const app = parseHistoryLedger(input.reconciliation.sealedLedgerRaw);
  const donor = parseHistoryLedger(input.reconciliation.generationTwoLedgerRaw);
  const box = donor.sensitiveMetadata as LegacyBox;
  const envelope = parseLegacyEnvelope(input.unwrapLegacyMetadata(box));
  compareDonorHistory(app, donor, envelope);

  const baseline: HistoryRows = {
    requests: app.requests.map(record => ({ revision: revisionFor(input.expectedRevisions, record.id), record })),
    audit: app.audit.map(record => ({ revision: revisionFor(input.expectedRevisions, record.id), record }))
  };
  const primaryRaw = JSON.stringify(sealHistory(baseline, input.key));
  const fullBackupRaws = [JSON.stringify(sealHistory(baseline, input.key))];
  const recoveryCopyRaws = [JSON.stringify(sealHistory(baseline, input.key))];
  const journal = sealHistory(baseline, input.key);
  const lines = [
    ...journal.requests.map(row => JSON.stringify({ kind: "request", row })),
    ...journal.audit.map(row => JSON.stringify({ kind: "audit", row }))
  ];
  const midpoint = Math.max(1, Math.floor(lines.length / 2));
  const journalSegmentRaws = [lines.slice(0, midpoint).join("\n") + "\n"];
  if (midpoint < lines.length) journalSegmentRaws.push(lines.slice(midpoint).join("\n") + "\n");

  const check = verifySealedHistoryClone({
    baseline, expectedRevisions: input.expectedRevisions, key: input.key,
    primaryRaw, fullBackupRaws, recoveryCopyRaws, journalSegmentRaws,
    leakMarkers: input.leakMarkers, trustedBaselineSha256: input.trustedBaselineSha256
  });
  return { primaryRaw, fullBackupRaws, recoveryCopyRaws, journalSegmentRaws, check };
}

function parseHistoryLedger(raw: string): {
    requests: RequestRecord[]; audit: AuditEvent[]; sensitiveMetadata?: unknown } {
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { throw new Error("Invalid synthetic history ledger."); }
  const ledger = objectValue(value);
  if (!ledger || !Array.isArray(ledger.requests) || !Array.isArray(ledger.audit)) {
    throw new Error("Invalid synthetic history ledger.");
  }
  return ledger as { requests: RequestRecord[]; audit: AuditEvent[]; sensitiveMetadata?: unknown };
}

function parseLegacyEnvelope(raw: string): {
    requests: Map<string, LegacyRequestDetail>; audit: Map<string, string> } {
  assertNoDuplicateJsonKeys(raw);
  let value: unknown;
  try { value = JSON.parse(raw); }
  catch { throw new Error("Invalid generation-2 sensitive metadata."); }
  const envelope = objectValue(value);
  if (!envelope || !exactFields(envelope, ["requests", "audit"])) {
    throw new Error("Invalid generation-2 sensitive metadata.");
  }
  const rawRequests = objectValue(envelope.requests);
  const rawAudit = objectValue(envelope.audit);
  if (!rawRequests || !rawAudit) throw new Error("Invalid generation-2 sensitive metadata.");

  const requests = new Map<string, LegacyRequestDetail>();
  for (const [id, value] of Object.entries(rawRequests)) {
    const detail = objectValue(value);
    if (!detail || typeof detail.reason !== "string" || !Array.isArray(detail.args)
        || detail.args.some(arg => typeof arg !== "string")
        || Object.keys(detail).some(field => ![
          "reason", "args", "error", "workingDir", "sshTarget", "stdout", "stderr"
        ].includes(field))) {
      throw new Error("Invalid generation-2 request detail.");
    }
    for (const field of ["error", "workingDir", "sshTarget", "stdout", "stderr"]) {
      if (detail[field] !== undefined && typeof detail[field] !== "string") {
        throw new Error("Invalid generation-2 request detail.");
      }
    }
    requests.set(id, detail as LegacyRequestDetail);
  }
  const audit = new Map<string, string>();
  for (const [id, message] of Object.entries(rawAudit)) {
    if (typeof message !== "string") throw new Error("Invalid generation-2 audit detail.");
    audit.set(id, message);
  }
  return { requests, audit };
}

function assertNoDuplicateJsonKeys(raw: string): void {
  const errors: ParseError[] = [];
  const tree = parseTree(raw, errors, { disallowComments: true });
  if (!tree || errors.length) return;

  function check(node: JsonNode): void {
    if (node.type === "object") {
      const keys = new Set<string>();
      for (const property of node.children || []) {
        const key = property.children?.[0]?.value;
        if (typeof key !== "string" || keys.has(key)) {
          throw new Error("History input has a duplicate key.");
        }
        keys.add(key);
      }
    }
    for (const child of node.children || []) check(child);
  }
  check(tree);
}

function compareDonorHistory(app: { requests: RequestRecord[]; audit: AuditEvent[] },
    donor: { requests: RequestRecord[]; audit: AuditEvent[] },
    envelope: { requests: Map<string, LegacyRequestDetail>; audit: Map<string, string> }): void {
  if (donor.requests.length !== envelope.requests.size || donor.audit.length !== envelope.audit.size) {
    throw new Error("Generation-2 envelope and row IDs differ.");
  }
  const appRequests = new Map(app.requests.map(row => [row.id, row]));
  const appAudit = new Map(app.audit.map(row => [row.id, row]));
  for (const row of donor.requests) {
    const detail = envelope.requests.get(row.id);
    const current = appRequests.get(row.id);
    if (!detail || !current) throw new Error("Generation-2 envelope and row IDs differ.");
    const restored = restoreRequest(row, detail);
    if (!isDeepStrictEqual(restored, current)) {
      throw new Error("Generation-2 decrypted request differs from sealed app history.");
    }
  }
  for (const row of donor.audit) {
    const message = envelope.audit.get(row.id);
    const current = appAudit.get(row.id);
    if (message === undefined || !current || row.message !== "") {
      throw new Error("Generation-2 envelope and row IDs differ.");
    }
    if (!isDeepStrictEqual({ ...row, message }, current)) {
      throw new Error("Generation-2 decrypted audit differs from sealed app history.");
    }
  }
}

function restoreRequest(row: RequestRecord, detail: LegacyRequestDetail): RequestRecord {
  if (row.reason !== "" || row.error !== undefined || row.action.args.length
      || row.action.workingDir !== undefined
      || (row.action.ssh && row.action.ssh.target !== "")
      || (row.resultSummary && (row.resultSummary.stdout !== "" || row.resultSummary.stderr !== ""))) {
    throw new Error("Generation-2 request has unmasked sensitive detail.");
  }
  const restored = structuredClone(row);
  restored.reason = detail.reason;
  restored.action.args = detail.args;
  if (detail.error !== undefined) restored.error = detail.error;
  if (detail.workingDir !== undefined) restored.action.workingDir = detail.workingDir;
  if (detail.sshTarget !== undefined) {
    if (!restored.action.ssh) throw new Error("Generation-2 SSH detail has no target row.");
    restored.action.ssh.target = detail.sshTarget;
  }
  if (detail.stdout !== undefined || detail.stderr !== undefined) {
    if (!restored.resultSummary) throw new Error("Generation-2 output detail has no result row.");
    if (detail.stdout !== undefined) restored.resultSummary.stdout = detail.stdout;
    if (detail.stderr !== undefined) restored.resultSummary.stderr = detail.stderr;
  }
  return restored;
}

function revisionFor(anchor: ReadonlyMap<string, number>, id: string): number {
  const revision = anchor.get(id);
  if (!Number.isSafeInteger(revision) || (revision as number) < 1) {
    throw new Error("Trusted history anchor is missing a revision.");
  }
  return revision as number;
}

function exactFields(value: Record<string, unknown>, fields: string[]): boolean {
  return Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}
