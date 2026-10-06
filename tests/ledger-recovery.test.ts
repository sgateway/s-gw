import { describe, expect, it } from "vitest";
import {
  compareRuntimeVersions,
  isHistoryFreeLedger,
  isRuntimeVersion,
  ledgerHistoryStats,
  mergeLedgerHistory,
  neutralizedRequestError
} from "../src/ledger-recovery.js";
import type { AuditEvent, CommandAction, RequestRecord, RequestState, StoreFile } from "../src/types.js";

function action(): CommandAction {
  return { kind: "env_command", command: "/usr/bin/true", args: [], env: [] } as unknown as CommandAction;
}

function request(id: string, state: RequestState, createdAt: string, overrides: Partial<RequestRecord> = {}): RequestRecord {
  return {
    id,
    handle: "sec_demo",
    reason: `request ${id}`,
    action: action(),
    state,
    createdAt,
    updatedAt: createdAt,
    ...overrides
  };
}

function auditEvent(id: string, ts: string): AuditEvent {
  return { id, ts, type: "request.created", message: `audit ${id}` };
}

function ledger(requests: RequestRecord[], audit: AuditEvent[]): StoreFile {
  return {
    version: 1,
    secrets: [],
    requests,
    audit,
    approvalSettings: {} as StoreFile["approvalSettings"],
    approvalGrants: [],
    approvalPolicyRules: []
  };
}

describe("ledger history detection", () => {
  it("treats a control-plane checkpoint as history free", () => {
    expect(isHistoryFreeLedger(ledger([], []))).toBe(true);
  });

  it("does not treat a ledger with only audit rows as history free", () => {
    expect(isHistoryFreeLedger(ledger([], [auditEvent("a1", "2026-09-01T00:00:00.000Z")]))).toBe(false);
  });

  it("counts requests and audit rows", () => {
    const stats = ledgerHistoryStats(ledger(
      [request("r1", "executed", "2026-09-01T00:00:00.000Z")],
      [auditEvent("a1", "2026-09-01T00:00:00.000Z"), auditEvent("a2", "2026-09-02T00:00:00.000Z")]
    ));
    expect(stats).toEqual({ requests: 1, audit: 2 });
  });
});

describe("mergeLedgerHistory", () => {
  it("restores request and audit history into a history-free checkpoint", () => {
    const base = ledger([], []);
    const donor = ledger(
      [
        request("r1", "executed", "2026-09-01T00:00:00.000Z"),
        request("r2", "denied", "2026-09-02T00:00:00.000Z")
      ],
      [auditEvent("a1", "2026-09-01T00:00:00.000Z")]
    );

    const merged = mergeLedgerHistory(base, [{ label: "store-backup.json", store: donor }]);

    expect(merged.addedRequests).toBe(2);
    expect(merged.addedAudit).toBe(1);
    expect(merged.neutralizedRequests).toBe(0);
    expect(merged.sources).toEqual(["store-backup.json"]);
    expect(merged.requests.map((entry) => entry.id)).toEqual(["r1", "r2"]);
  });

  it("never overwrites a row the base ledger already holds", () => {
    const base = ledger([request("r1", "executed", "2026-09-01T00:00:00.000Z", { reason: "authoritative" })], []);
    const donor = ledger([request("r1", "failed", "2026-09-01T00:00:00.000Z", { reason: "stale copy" })], []);

    const merged = mergeLedgerHistory(base, [{ label: "donor.json", store: donor }]);

    expect(merged.addedRequests).toBe(0);
    expect(merged.requests).toHaveLength(1);
    expect(merged.requests[0].reason).toBe("authoritative");
    expect(merged.requests[0].state).toBe("executed");
  });

  it("closes merged requests that still held authority and strips their approval", () => {
    const donor = ledger(
      [
        request("r1", "approved", "2026-09-01T00:00:00.000Z", {
          approvedAt: "2026-09-01T00:00:01.000Z",
          approvalGrantId: "grant-1",
          approvalPolicyRuleId: "rule-1",
          approvalSource: "policy" as RequestRecord["approvalSource"]
        }),
        request("r3", "executing", "2026-09-03T00:00:00.000Z")
      ],
      []
    );

    const merged = mergeLedgerHistory(ledger([], []), [{ label: "donor.json", store: donor }]);

    expect(merged.neutralizedRequests).toBe(2);
    for (const entry of merged.requests) {
      expect(entry.state).toBe("failed");
      expect(entry.approvedAt).toBeUndefined();
      expect(entry.approvalGrantId).toBeUndefined();
      expect(entry.approvalPolicyRuleId).toBeUndefined();
      expect(entry.approvalSource).toBeUndefined();
      expect(entry.error).toContain(neutralizedRequestError);
    }
  });

  it("restores a pending request as pending because it grants nothing on its own", () => {
    const pending = request("r1", "pending", "2026-09-02T00:00:00.000Z");
    const merged = mergeLedgerHistory(ledger([], []), [{ label: "donor.json", store: ledger([pending], []) }]);

    expect(merged.neutralizedRequests).toBe(0);
    expect(merged.requests[0]).toEqual(pending);
  });

  it("keeps terminal requests exactly as recorded", () => {
    const executed = request("r1", "executed", "2026-09-01T00:00:00.000Z", {
      executedAt: "2026-09-01T00:00:05.000Z",
      approvalGrantId: "grant-1"
    });
    const merged = mergeLedgerHistory(ledger([], []), [{ label: "donor.json", store: ledger([executed], []) }]);

    expect(merged.neutralizedRequests).toBe(0);
    expect(merged.requests[0]).toEqual(executed);
  });

  it("deduplicates across donors and records only contributing sources", () => {
    const shared = request("r1", "executed", "2026-09-01T00:00:00.000Z");
    const newer = ledger([shared, request("r2", "executed", "2026-09-02T00:00:00.000Z")], []);
    const older = ledger([shared], []);
    const empty = ledger([], []);

    const merged = mergeLedgerHistory(ledger([], []), [
      { label: "newer.json", store: newer },
      { label: "older.json", store: older },
      { label: "empty.json", store: empty }
    ]);

    expect(merged.requests).toHaveLength(2);
    expect(merged.addedRequests).toBe(2);
    expect(merged.sources).toEqual(["newer.json"]);
  });

  it("orders merged history oldest first", () => {
    const donor = ledger(
      [
        request("r3", "executed", "2026-09-03T00:00:00.000Z"),
        request("r1", "executed", "2026-09-01T00:00:00.000Z"),
        request("r2", "executed", "2026-09-02T00:00:00.000Z")
      ],
      [auditEvent("a2", "2026-09-02T00:00:00.000Z"), auditEvent("a1", "2026-09-01T00:00:00.000Z")]
    );

    const merged = mergeLedgerHistory(ledger([], []), [{ label: "donor.json", store: donor }]);

    expect(merged.requests.map((entry) => entry.id)).toEqual(["r1", "r2", "r3"]);
    expect(merged.audit.map((entry) => entry.id)).toEqual(["a1", "a2"]);
  });

  it("never takes secrets, grants, or policy rules from a donor", () => {
    const donor = {
      ...ledger([request("r1", "executed", "2026-09-01T00:00:00.000Z")], []),
      secrets: [{ handle: "sec_injected" }] as unknown as StoreFile["secrets"],
      approvalGrants: [{ id: "grant-injected" }] as unknown as StoreFile["approvalGrants"],
      approvalPolicyRules: [{ id: "rule-injected" }] as unknown as StoreFile["approvalPolicyRules"]
    };

    const merged = mergeLedgerHistory(ledger([], []), [{ label: "donor.json", store: donor }]);

    expect(Object.keys(merged)).toEqual([
      "requests",
      "audit",
      "addedRequests",
      "addedAudit",
      "neutralizedRequests",
      "sources"
    ]);
  });
});

describe("compareRuntimeVersions", () => {
  it("orders release versions", () => {
    expect(compareRuntimeVersions("0.1.20", "0.1.21")).toBeLessThan(0);
    expect(compareRuntimeVersions("0.1.21", "0.1.20")).toBeGreaterThan(0);
    expect(compareRuntimeVersions("0.1.21", "0.1.21")).toBe(0);
    expect(compareRuntimeVersions("0.1.0", "0.1.21")).toBeLessThan(0);
    expect(compareRuntimeVersions("0.2.0", "0.10.0")).toBeLessThan(0);
  });

  it("ranks a release above its own prereleases", () => {
    expect(compareRuntimeVersions("0.1.22-preview.6", "0.1.22")).toBeLessThan(0);
    expect(compareRuntimeVersions("0.1.22", "0.1.22-preview.6")).toBeGreaterThan(0);
    expect(compareRuntimeVersions("0.1.22-preview.5", "0.1.22-preview.6")).toBeLessThan(0);
  });

  it("treats unparseable versions as equivalent so a guard never fires on garbage", () => {
    expect(compareRuntimeVersions("not-a-version", "0.1.21")).toBe(0);
    expect(compareRuntimeVersions("0.1.21", "")).toBe(0);
  });

  it("recognizes valid runtime versions", () => {
    expect(isRuntimeVersion("0.1.21")).toBe(true);
    expect(isRuntimeVersion("0.1.22-preview.6")).toBe(true);
    expect(isRuntimeVersion("0.1")).toBe(false);
    expect(isRuntimeVersion(undefined)).toBe(false);
  });
});
