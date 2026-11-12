import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { openSealedHistory, type HistoryRows, type SealedAuditRow, type SealedRequestRow } from "./sealed-history-codec.js";

export interface SealedHistoryCloneInput {
  baseline: HistoryRows;
  expectedRevisions: ReadonlyMap<string, number>;
  key: Uint8Array;
  primaryRaw: string;
  fullBackupRaws: readonly string[];
  recoveryCopyRaws: readonly string[];
  journalSegmentRaws: readonly string[];
  leakMarkers: readonly string[];
  /** SHA-256 of JSON.stringify(baseline), recorded from an independent snapshot. */
  trustedBaselineSha256: string;
}

export interface SealedHistoryCloneCheck {
  requests: number;
  audit: number;
  completeCopies: number;
  journalSegments: number;
}

// This checks synthetic v3 copies and a compacted journal. Crash recovery needs its own gate.
export function verifySealedHistoryClone(input: SealedHistoryCloneInput): SealedHistoryCloneCheck {
  if (!input.expectedRevisions || !input.leakMarkers.length
      || !input.fullBackupRaws.length || !input.recoveryCopyRaws.length
      || !input.journalSegmentRaws.length) {
    throw new Error("A trusted revision anchor, canaries, full backup, recovery copy, and journal are required.");
  }

  const baseline = input.baseline;
  if (!baseline || !Array.isArray(baseline.requests) || !Array.isArray(baseline.audit)) {
    throw new Error("Invalid baseline history.");
  }
  // The control seal does not cover history, so the baseline needs its own anchor.
  const baselineDigest = createHash("sha256").update(JSON.stringify(baseline)).digest("hex");
  if (!/^[a-f0-9]{64}$/.test(input.trustedBaselineSha256)
      || baselineDigest !== input.trustedBaselineSha256) {
    throw new Error("The trusted history baseline digest does not match.");
  }
  const ids = new Set<string>();
  const index: string[] = [];
  for (const item of baseline.requests) {
    const row = item?.record;
    if (!row || typeof row.id !== "string" || !row.id || ids.has(row.id)
        || !Number.isSafeInteger(item.revision) || item.revision < 1
        || input.expectedRevisions.get(row.id) !== item.revision) {
      throw new Error("Baseline history does not match its trusted revision anchor.");
    }
    ids.add(row.id);
    index.push(row.id, row.updatedAt, row.state);
  }
  for (const item of baseline.audit) {
    const row = item?.record;
    if (!row || typeof row.id !== "string" || !row.id || ids.has(row.id)
        || !Number.isSafeInteger(item.revision) || item.revision < 1
        || input.expectedRevisions.get(row.id) !== item.revision) {
      throw new Error("Baseline history does not match its trusted revision anchor.");
    }
    ids.add(row.id);
    index.push(row.id, row.ts);
  }
  if (ids.size !== input.expectedRevisions.size) {
    throw new Error("Baseline history does not match its trusted revision anchor.");
  }

  const baselineRaw = JSON.stringify(baseline);
  const publicIndex = JSON.stringify(index);
  for (const marker of input.leakMarkers) {
    if (typeof marker !== "string" || marker.length < 8
        || !baselineRaw.includes(marker) || publicIndex.includes(marker)) {
      throw new Error("A leak canary must occur only in private baseline detail.");
    }
  }

  const copies = [input.primaryRaw, ...input.fullBackupRaws, ...input.recoveryCopyRaws];
  for (const raw of copies) {
    if (typeof raw !== "string") throw new Error("Invalid sealed history copy.");
    assertNoCanaries(raw, input.leakMarkers);
    const opened = openSealedHistory(raw, input.key, input.expectedRevisions);
    if (!isDeepStrictEqual(opened, baseline)) {
      throw new Error("Sealed history copy differs from the trusted baseline.");
    }
  }

  const journal = parseJournal(input.journalSegmentRaws, input.leakMarkers);
  const restored = openSealedHistory(journal, input.key, input.expectedRevisions);
  if (!isDeepStrictEqual(restored, baseline)) {
    throw new Error("Sealed journal differs from the trusted baseline.");
  }

  return {
    requests: baseline.requests.length,
    audit: baseline.audit.length,
    completeCopies: copies.length,
    journalSegments: input.journalSegmentRaws.length
  };
}

function assertNoCanaries(raw: string, markers: readonly string[]): void {
  for (const marker of markers) {
    if (raw.includes(marker)) throw new Error("Sensitive history canary leaked in a sealed copy.");
  }
}

function parseJournal(rawSegments: readonly string[], markers: readonly string[]): {
    version: 3; requests: SealedRequestRow[]; audit: SealedAuditRow[] } {
  const requests: SealedRequestRow[] = [];
  const audit: SealedAuditRow[] = [];
  for (const raw of rawSegments) {
    if (typeof raw !== "string" || !raw.endsWith("\n")) {
      throw new Error("Torn or invalid sealed journal segment.");
    }
    assertNoCanaries(raw, markers);
    for (const line of raw.slice(0, -1).split("\n")) {
      let value: unknown;
      try { value = JSON.parse(line); }
      catch { throw new Error("Torn or invalid sealed journal segment."); }
      if (!value || typeof value !== "object" || Array.isArray(value)
          || Object.keys(value).length !== 2 || !Object.hasOwn(value, "kind")
          || !Object.hasOwn(value, "row")) {
        throw new Error("Invalid sealed journal row.");
      }
      const item = value as { kind: unknown; row: unknown };
      if (item.kind === "request") requests.push(item.row as SealedRequestRow);
      else if (item.kind === "audit") audit.push(item.row as SealedAuditRow);
      else throw new Error("Invalid sealed journal row.");
    }
  }
  return { version: 3, requests, audit };
}
