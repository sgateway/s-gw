import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { AuditEvent, RequestRecord, RequestState } from "./types.js";

type HistoryKind = "request" | "audit";

export interface RevisedHistoryRow<T> {
  revision: number;
  record: T;
}

export interface HistoryRows {
  requests: RevisedHistoryRow<RequestRecord>[];
  audit: RevisedHistoryRow<AuditEvent>[];
}

interface HistoryBox {
  alg: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface SealedRequestRow {
  id: string;
  updatedAt: string;
  state: RequestState;
  revision: number;
  box: HistoryBox;
}

export interface SealedAuditRow {
  id: string;
  ts: string;
  revision: number;
  box: HistoryBox;
}

export interface SealedHistoryV3 {
  version: 3;
  requests: SealedRequestRow[];
  audit: SealedAuditRow[];
}

const requestStates = new Set(["pending", "approved", "executing", "denied", "executed", "failed"]);
const requestFields = new Set([
  "id", "handle", "reason", "agentName", "agentSource", "principalId", "agentSessionId",
  "loginSessionId", "action", "state", "createdAt", "updatedAt", "approvedAt",
  "approvalSource", "approvalGrantId", "approvalPolicyRuleId", "deniedAt", "executedAt",
  "resultSummary", "error"
]);
const auditFields = new Set([
  "id", "ts", "type", "handle", "requestId", "uploadApprovalScope", "message"
]);

export function sealHistory(rows: HistoryRows, key: Uint8Array): SealedHistoryV3 {
  const aesKey = checkedKey(key);
  const seen = new Set<string>();
  const requests: SealedRequestRow[] = [];
  const audit: SealedAuditRow[] = [];

  const input = objectWithFields(rows, ["requests", "audit"]);
  if (!Array.isArray(input.requests) || !Array.isArray(input.audit)) {
    throw new Error("Invalid history rows.");
  }
  for (const value of input.requests) {
    const item = objectWithFields(value, ["revision", "record"]);
    checkRevision(item.revision);
    const record = checkRequest(item.record);
    checkId(seen, record.id);
    const meta = { id: record.id, updatedAt: record.updatedAt, state: record.state,
      revision: item.revision };
    requests.push({ ...meta, box: encryptRow("request", meta, record, aesKey) });
  }
  for (const value of input.audit) {
    const item = objectWithFields(value, ["revision", "record"]);
    checkRevision(item.revision);
    const record = checkAudit(item.record);
    checkId(seen, record.id);
    const meta = { id: record.id, ts: record.ts, revision: item.revision };
    audit.push({ ...meta, box: encryptRow("audit", meta, record, aesKey) });
  }
  return { version: 3, requests, audit };
}

export function openSealedHistory(raw: unknown, key: Uint8Array,
    expectedRevisions: ReadonlyMap<string, number>): HistoryRows {
  if (!expectedRevisions) throw new Error("A trusted history revision anchor is required.");
  const aesKey = checkedKey(key);
  const parsed = typeof raw === "string" ? JSON.parse(raw) as unknown : raw;
  const history = objectWithFields(parsed, ["version", "requests", "audit"]);
  if (history.version !== 3 || !Array.isArray(history.requests) || !Array.isArray(history.audit)) {
    throw new Error("Unsupported sealed history format.");
  }

  const seen = new Set<string>();
  const requests: HistoryRows["requests"] = [];
  const audit: HistoryRows["audit"] = [];
  for (const value of history.requests) {
    const row = objectWithFields(value, ["id", "updatedAt", "state", "revision", "box"]);
    checkText(row.id);
    checkText(row.updatedAt);
    checkState(row.state);
    checkRevision(row.revision);
    checkId(seen, row.id);
    checkExpectedRevision(expectedRevisions, row.id, row.revision);
    const meta = { id: row.id, updatedAt: row.updatedAt, state: row.state,
      revision: row.revision };
    const record = checkRequest(decryptRow("request", meta, row.box, aesKey));
    if (record.id !== row.id || record.updatedAt !== row.updatedAt || record.state !== row.state) {
      throw new Error("Sealed request metadata mismatch.");
    }
    requests.push({ revision: row.revision, record });
  }
  for (const value of history.audit) {
    const row = objectWithFields(value, ["id", "ts", "revision", "box"]);
    checkText(row.id);
    checkText(row.ts);
    checkRevision(row.revision);
    checkId(seen, row.id);
    checkExpectedRevision(expectedRevisions, row.id, row.revision);
    const meta = { id: row.id, ts: row.ts, revision: row.revision };
    const record = checkAudit(decryptRow("audit", meta, row.box, aesKey));
    if (record.id !== row.id || record.ts !== row.ts) {
      throw new Error("Sealed audit metadata mismatch.");
    }
    audit.push({ revision: row.revision, record });
  }
  if (expectedRevisions.size !== seen.size) {
    throw new Error("Sealed history revision anchor mismatch.");
  }
  return { requests, audit };
}

function encryptRow(kind: HistoryKind, meta: object, record: object, key: Buffer): HistoryBox {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad(kind, meta));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(record), "utf8"), cipher.final()]);
  return {
    alg: "aes-256-gcm", iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64")
  };
}

function decryptRow(kind: HistoryKind, meta: object, value: unknown, key: Buffer): unknown {
  const box = objectWithFields(value, ["alg", "iv", "authTag", "ciphertext"]);
  if (box.alg !== "aes-256-gcm") throw new Error("Unsupported history cipher.");
  const iv = decodeBase64(box.iv, 12);
  const tag = decodeBase64(box.authTag, 16);
  const ciphertext = decodeBase64(box.ciphertext);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad(kind, meta));
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plain.toString("utf8")) as unknown;
}

function aad(kind: HistoryKind, meta: object): Buffer {
  return Buffer.from(JSON.stringify(["s-gw-history-v3", kind, meta]), "utf8");
}

function checkedKey(key: Uint8Array): Buffer {
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new Error("Sealed history requires a 32-byte key.");
  }
  return Buffer.from(key);
}

function objectWithFields(value: unknown, fields: string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid sealed history object.");
  }
  const record = value as Record<string, unknown>;
  for (const field of Object.keys(record)) {
    if (!fields.includes(field)) throw new Error("Unknown sealed history field.");
  }
  if (Object.keys(record).length !== fields.length) {
    throw new Error("Missing sealed history field.");
  }
  return record;
}

function checkRequest(value: unknown): RequestRecord {
  const record = detailObject(value, requestFields);
  checkText(record.id);
  checkText(record.handle);
  checkString(record.reason);
  checkText(record.createdAt);
  checkText(record.updatedAt);
  checkState(record.state);
  if (!record.action || typeof record.action !== "object" || Array.isArray(record.action)) {
    throw new Error("Invalid sealed request detail.");
  }
  // Keep nested action detail intact so newer action fields survive a history round-trip.
  return record as unknown as RequestRecord;
}

function checkAudit(value: unknown): AuditEvent {
  const record = detailObject(value, auditFields);
  checkText(record.id);
  checkText(record.ts);
  checkText(record.type);
  checkString(record.message);
  return record as unknown as AuditEvent;
}

function detailObject(value: unknown, fields: Set<string>): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid sealed history detail.");
  }
  const record = value as Record<string, unknown>;
  for (const field of Object.keys(record)) {
    if (!fields.has(field)) throw new Error("Unknown sealed history detail field.");
  }
  return record;
}

function checkText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !value) throw new Error("Invalid sealed history text.");
}

function checkString(value: unknown): asserts value is string {
  if (typeof value !== "string") throw new Error("Invalid sealed history text.");
}

function checkState(value: unknown): asserts value is RequestState {
  if (!requestStates.has(value as string)) throw new Error("Invalid sealed request state.");
}

function checkRevision(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new Error("Invalid sealed history revision.");
  }
}

function checkId(seen: Set<string>, id: string): void {
  if (seen.has(id)) throw new Error("Duplicate sealed history ID.");
  seen.add(id);
}

function checkExpectedRevision(expected: ReadonlyMap<string, number>,
    id: string, revision: number): void {
  if (expected.get(id) !== revision) {
    throw new Error("Sealed history revision anchor mismatch.");
  }
}

function decodeBase64(value: unknown, expectedLength?: number): Buffer {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Invalid sealed history encoding.");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (expectedLength !== undefined && bytes.length !== expectedLength)) {
    throw new Error("Invalid sealed history encoding.");
  }
  return bytes;
}
