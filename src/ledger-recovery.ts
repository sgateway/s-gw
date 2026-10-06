import type { AuditEvent, RequestRecord, RequestState, StoreFile } from "./types.js";

const terminalRequestStates: ReadonlySet<RequestState> = new Set<RequestState>([
  "denied",
  "executed",
  "failed"
]);

/**
 * States that must never come back from a recovery source.
 *
 * `approved` carries live authority: a restored approved request could be claimed and run
 * without the operator approving it on the recovered ledger. `executing` describes a child
 * process that no longer exists, so it can never complete. Both are closed out on restore.
 *
 * `pending` is deliberately not in this set. A pending request grants nothing on its own — it
 * still has to be approved — so restoring it preserves the operator's queue instead of
 * silently discarding work they were about to act on.
 */
const unrestorableRequestStates: ReadonlySet<RequestState> = new Set<RequestState>([
  "approved",
  "executing"
]);

/**
 * Explanation attached to a merged request that still carried authority when it was recorded.
 * Such a request is closed rather than resurrected, so recovery can never re-authorize work
 * that the operator has not approved on the recovered ledger.
 */
export const neutralizedRequestError =
  "This request still held an approval, or was mid-execution, when the ledger was last recorded. "
  + "Recovery restored it as history only; it was closed without authority and must be requested again to run.";

export interface LedgerHistoryStats {
  requests: number;
  audit: number;
}

export interface LedgerHistorySource {
  /** Human-readable label used in the durable recovery audit event. */
  label: string;
  store: StoreFile;
}

export interface MergeLedgerHistoryResult {
  requests: RequestRecord[];
  audit: AuditEvent[];
  addedRequests: number;
  addedAudit: number;
  neutralizedRequests: number;
  /** Labels of the sources that actually contributed at least one row, richest first. */
  sources: string[];
}

export function ledgerHistoryStats(store: Pick<StoreFile, "requests" | "audit">): LedgerHistoryStats {
  return {
    requests: Array.isArray(store.requests) ? store.requests.length : 0,
    audit: Array.isArray(store.audit) ? store.audit.length : 0
  };
}

/**
 * True when a ledger carries no request or audit history at all.
 *
 * Sealed control-plane checkpoints are built this way on purpose: they anchor secrets,
 * grants, settings, and policy rules, and deliberately omit request/audit history. Restoring
 * one as if it were a full backup is what silently erases Usage Flow, so every recovery path
 * must test for this before it accepts a candidate as a complete ledger.
 */
export function isHistoryFreeLedger(store: Pick<StoreFile, "requests" | "audit">): boolean {
  const stats = ledgerHistoryStats(store);
  return stats.requests === 0 && stats.audit === 0;
}

export function isTerminalRequestState(state: RequestState): boolean {
  return terminalRequestStates.has(state);
}

export function isRestorableRequestState(state: RequestState): boolean {
  return !unrestorableRequestStates.has(state);
}

/**
 * Strip every field that could let a restored request act. The row stays in the ledger as
 * history so Usage Flow keeps its continuity, but it is closed and carries no approval.
 */
function neutralizeRequest(request: RequestRecord, nowIso: string): RequestRecord {
  const {
    approvedAt: _approvedAt,
    approvalSource: _approvalSource,
    approvalGrantId: _approvalGrantId,
    approvalPolicyRuleId: _approvalPolicyRuleId,
    ...rest
  } = request;
  return {
    ...rest,
    state: "failed",
    updatedAt: nowIso,
    error: request.error ? `${request.error} ${neutralizedRequestError}` : neutralizedRequestError
  };
}

function requestSortKey(request: RequestRecord): string {
  return `${request.createdAt || ""}|${request.id}`;
}

function auditSortKey(event: AuditEvent): string {
  return `${event.ts || ""}|${event.id}`;
}

/**
 * Merge request and audit history from retained full backups into a base ledger.
 *
 * Rules, in order of importance:
 *  1. The base ledger is authoritative. A row already present by id is never overwritten.
 *  2. Only requests and audit events are merged. Secrets, grants, settings, and policy rules
 *     always come from the base, so a donor file can never inject credentials or authority.
 *  3. Any merged request that still held authority (approved) or was mid-execution is closed as
 *     failed and stripped of its approval fields, so recovery cannot resurrect usable
 *     authorization. Pending requests are restored as pending: they grant nothing by themselves.
 *  4. Output is deduplicated by id and ordered oldest-first for stable rendering.
 */
export function mergeLedgerHistory(
  base: Pick<StoreFile, "requests" | "audit">,
  sources: readonly LedgerHistorySource[],
  nowIso: string = new Date().toISOString()
): MergeLedgerHistoryResult {
  const requests = new Map<string, RequestRecord>();
  const audit = new Map<string, AuditEvent>();

  for (const request of base.requests || []) {
    if (request?.id && !requests.has(request.id)) {
      requests.set(request.id, request);
    }
  }
  for (const event of base.audit || []) {
    if (event?.id && !audit.has(event.id)) {
      audit.set(event.id, event);
    }
  }

  let addedRequests = 0;
  let addedAudit = 0;
  let neutralizedRequests = 0;
  const contributingSources: string[] = [];

  for (const source of sources) {
    let contributed = false;

    for (const request of source.store.requests || []) {
      if (!request?.id || requests.has(request.id)) {
        continue;
      }
      if (isRestorableRequestState(request.state)) {
        requests.set(request.id, request);
      } else {
        requests.set(request.id, neutralizeRequest(request, nowIso));
        neutralizedRequests += 1;
      }
      addedRequests += 1;
      contributed = true;
    }

    for (const event of source.store.audit || []) {
      if (!event?.id || audit.has(event.id)) {
        continue;
      }
      audit.set(event.id, event);
      addedAudit += 1;
      contributed = true;
    }

    if (contributed) {
      contributingSources.push(source.label);
    }
  }

  return {
    requests: [...requests.values()].sort((left, right) => requestSortKey(left).localeCompare(requestSortKey(right))),
    audit: [...audit.values()].sort((left, right) => auditSortKey(left).localeCompare(auditSortKey(right))),
    addedRequests,
    addedAudit,
    neutralizedRequests,
    sources: contributingSources
  };
}

/**
 * Compare two s-gw runtime versions. Returns a negative number when `left` is older than
 * `right`, zero when they are equivalent, and a positive number when `left` is newer.
 * Release versions outrank their own prereleases (0.1.21 is newer than 0.1.21-preview.6).
 */
export function compareRuntimeVersions(left: string, right: string): number {
  const parsedLeft = parseRuntimeVersion(left);
  const parsedRight = parseRuntimeVersion(right);
  if (!parsedLeft || !parsedRight) {
    return 0;
  }

  for (let index = 0; index < 3; index += 1) {
    if (parsedLeft.release[index] !== parsedRight.release[index]) {
      return parsedLeft.release[index] < parsedRight.release[index] ? -1 : 1;
    }
  }

  if (parsedLeft.prerelease === parsedRight.prerelease) {
    return 0;
  }
  if (!parsedLeft.prerelease) {
    return 1;
  }
  if (!parsedRight.prerelease) {
    return -1;
  }
  return parsedLeft.prerelease < parsedRight.prerelease ? -1 : 1;
}

function parseRuntimeVersion(value: string): { release: [number, number, number]; prerelease: string } | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(value.trim());
  if (!match) {
    return undefined;
  }
  return {
    release: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] || ""
  };
}

export function isRuntimeVersion(value: unknown): value is string {
  return typeof value === "string" && parseRuntimeVersion(value) !== undefined;
}
