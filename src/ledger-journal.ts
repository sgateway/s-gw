import { appendFile, mkdir, open, readFile, readdir, rm, stat } from "node:fs/promises";
import path from "node:path";
import type { AuditEvent, RequestRecord, StoreFile } from "./types.js";

/**
 * Append-only request/audit journal.
 *
 * Retained full backups are written only when the control plane changes or after a backup
 * interval elapses, so a crash can easily land between backups and lose every request made
 * since the last one. Sealed control-plane checkpoints do not help: they omit request and
 * audit history by design. The journal closes that gap by appending each newly committed
 * request and audit row as its own line, so recovery can rebuild a complete history no matter
 * when the crash happened.
 *
 * The journal holds history only. It never carries secrets, grants, approval settings, or
 * policy rules, so it cannot be used to restore authority.
 */

const journalDirName = "journal";
const journalPrefix = "ledger-";
const journalSuffix = ".jsonl";
/** Roll to a new segment past this size so a single file cannot grow without bound. */
const maxSegmentBytes = 4 * 1024 * 1024;
/** Segments retained after rotation, newest first. */
const maxSegments = 8;

type JournalRow =
  | { kind: "request"; row: RequestRecord }
  | { kind: "audit"; row: AuditEvent };

export interface LedgerJournalHistory {
  requests: RequestRecord[];
  audit: AuditEvent[];
  /** Lines that could not be parsed, typically one torn line from a crash mid-append. */
  damagedLines: number;
}

export function ledgerJournalDir(home: string): string {
  return path.join(home, journalDirName);
}

function segmentPath(home: string, index: number): string {
  return path.join(ledgerJournalDir(home), `${journalPrefix}${String(index).padStart(6, "0")}${journalSuffix}`);
}

function segmentIndex(name: string): number | undefined {
  if (!name.startsWith(journalPrefix) || !name.endsWith(journalSuffix)) {
    return undefined;
  }
  const raw = name.slice(journalPrefix.length, name.length - journalSuffix.length);
  if (!/^\d+$/.test(raw)) {
    return undefined;
  }
  return Number(raw);
}

async function listSegments(home: string): Promise<Array<{ index: number; path: string }>> {
  const entries = await readdir(ledgerJournalDir(home)).catch(() => []);
  const segments: Array<{ index: number; path: string }> = [];
  for (const entry of entries) {
    const index = segmentIndex(entry);
    if (index !== undefined) {
      segments.push({ index, path: path.join(ledgerJournalDir(home), entry) });
    }
  }
  return segments.sort((left, right) => left.index - right.index);
}

async function activeSegment(home: string): Promise<string> {
  const segments = await listSegments(home);
  if (segments.length === 0) {
    return segmentPath(home, 0);
  }
  const newest = segments[segments.length - 1];
  const info = await stat(newest.path).catch(() => undefined);
  if (info && info.size >= maxSegmentBytes) {
    return segmentPath(home, newest.index + 1);
  }
  return newest.path;
}

async function endsWithNewline(filePath: string): Promise<boolean> {
  const info = await stat(filePath).catch(() => undefined);
  if (!info || info.size === 0) {
    return true;
  }
  const handle = await open(filePath, "r").catch(() => undefined);
  if (!handle) {
    return true;
  }
  try {
    const buffer = Buffer.alloc(1);
    await handle.read(buffer, 0, 1, info.size - 1);
    return buffer[0] === 0x0a;
  } catch {
    return true;
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function pruneSegments(home: string): Promise<void> {
  const segments = await listSegments(home);
  for (const segment of segments.slice(0, Math.max(0, segments.length - maxSegments))) {
    await rm(segment.path, { force: true }).catch(() => undefined);
  }
}

function idsOf(rows: readonly { id: string }[] | undefined): Set<string> {
  return new Set((rows || []).map((row) => row?.id).filter((id): id is string => typeof id === "string"));
}

function serializedById(rows: readonly RequestRecord[] | undefined): Map<string, string> {
  const map = new Map<string, string>();
  for (const row of rows || []) {
    if (row?.id) {
      map.set(row.id, JSON.stringify(row));
    }
  }
  return map;
}

/**
 * Append every request and audit row present in `store` but not in `previous`.
 *
 * Called after the ledger commit succeeds. A failure to append is never allowed to fail the
 * commit: the journal is a recovery aid, and losing a journal line is strictly better than
 * refusing a write the operator asked for. Callers pass `onError` to surface that case.
 */
export async function appendLedgerJournal(
  home: string,
  store: Pick<StoreFile, "requests" | "audit">,
  previous?: Pick<StoreFile, "requests" | "audit">
): Promise<number> {
  // A request is journaled whenever it is created *or changes*, because Usage Flow depends on
  // the final state of each request, not just its creation. Audit events are immutable, so a
  // new-id check is enough for them.
  const previousRequests = serializedById(previous?.requests);
  const previousAuditIds = idsOf(previous?.audit);

  const lines: string[] = [];
  for (const row of store.requests || []) {
    if (!row?.id) {
      continue;
    }
    const serialized = JSON.stringify(row);
    if (previousRequests.get(row.id) !== serialized) {
      lines.push(JSON.stringify({ kind: "request", row } satisfies JournalRow));
    }
  }
  for (const row of store.audit || []) {
    if (row?.id && !previousAuditIds.has(row.id)) {
      lines.push(JSON.stringify({ kind: "audit", row } satisfies JournalRow));
    }
  }
  if (lines.length === 0) {
    return 0;
  }

  await mkdir(ledgerJournalDir(home), { recursive: true, mode: 0o700 });
  const target = await activeSegment(home);
  // If a previous process was killed partway through an append, the segment can end without a
  // newline. Start on a fresh line so the torn line stays the only damaged one.
  const separator = (await endsWithNewline(target)) ? "" : "\n";
  await appendFile(target, `${separator}${lines.join("\n")}\n`, { mode: 0o600 });
  await pruneSegments(home);
  return lines.length;
}

/**
 * Read all retained journal history, oldest segment first.
 *
 * A crash during append can leave a partial final line. Such a line is skipped and counted,
 * never treated as corruption of the whole journal.
 */
export async function readLedgerJournal(home: string): Promise<LedgerJournalHistory> {
  const requests = new Map<string, RequestRecord>();
  const audit = new Map<string, AuditEvent>();
  let damagedLines = 0;

  for (const segment of await listSegments(home)) {
    const raw = await readFile(segment.path, "utf8").catch(() => "");
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      let parsed: JournalRow;
      try {
        parsed = JSON.parse(trimmed) as JournalRow;
      } catch {
        damagedLines += 1;
        continue;
      }
      if (!parsed || typeof parsed !== "object" || !parsed.row || typeof parsed.row.id !== "string") {
        damagedLines += 1;
        continue;
      }
      // Later entries win: a request is journaled again as it moves through its lifecycle.
      if (parsed.kind === "request") {
        requests.set(parsed.row.id, parsed.row);
      } else if (parsed.kind === "audit") {
        audit.set(parsed.row.id, parsed.row);
      } else {
        damagedLines += 1;
      }
    }
  }

  return { requests: [...requests.values()], audit: [...audit.values()], damagedLines };
}

export async function hasLedgerJournal(home: string): Promise<boolean> {
  return (await listSegments(home)).length > 0;
}
