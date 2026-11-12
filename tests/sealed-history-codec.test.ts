import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { openSealedHistory, sealHistory } from "../src/sealed-history-codec.js";
import type { AuditEvent, RequestRecord } from "../src/types.js";

const ts = "2026-11-12T02:00:00.000Z";
const key = randomBytes(32);

function request(): RequestRecord {
  return {
    id: "req_synthetic", handle: "s-gw:synthetic:one", reason: "private reason marker",
    action: {
      kind: "http_request", command: "private command marker", args: ["private argument marker"],
      injectEnv: "TOKEN", timeoutMs: 1000,
      http: {
        url: "https://private-host-marker.test/path", method: "POST",
        headers: { "x-private": "private header marker" }, body: "private body marker",
        auth: { kind: "bearer" }
      }
    },
    state: "failed", createdAt: ts, updatedAt: ts,
    resultSummary: {
      exitCode: 1, signal: null, stdout: "private stdout marker", stderr: "private stderr marker",
      proof: "private proof marker", durationMs: 12, timeoutMs: 1000,
      timedOut: false, sanitized: true
    },
    error: "private error marker"
  };
}

function event(): AuditEvent {
  return {
    id: "audit_synthetic", ts, type: "request.failed", handle: "s-gw:synthetic:one",
    requestId: "req_synthetic", message: "private audit marker"
  };
}

function fixture() {
  return { requests: [{ revision: 1, record: request() }], audit: [{ revision: 1, record: event() }] };
}

function revisions(rows: { requests: { revision: number; record: { id: string } }[];
    audit: { revision: number; record: { id: string } }[] }): Map<string, number> {
  const found = new Map<string, number>();
  for (const item of rows.requests) found.set(item.record.id, item.revision);
  for (const item of rows.audit) found.set(item.record.id, item.revision);
  return found;
}

describe("sealed history v3 codec", () => {
  it("seals complete request and audit detail and exposes only index metadata", () => {
    const rows = fixture();
    const sealed = sealHistory(rows, key);
    expect(Object.keys(sealed)).toEqual(["version", "requests", "audit"]);
    expect(Object.keys(sealed.requests[0])).toEqual(["id", "updatedAt", "state", "revision", "box"]);
    expect(Object.keys(sealed.audit[0])).toEqual(["id", "ts", "revision", "box"]);
    expect(JSON.stringify(sealed)).not.toMatch(/private|s-gw:synthetic:one|request\.failed/);
    expect(openSealedHistory(JSON.stringify(sealed), key, revisions(rows))).toEqual(rows);
  });

  it("round-trips empty legacy reason and audit message fields", () => {
    const rows = fixture();
    rows.requests[0].record.reason = "";
    rows.audit[0].record.message = "";
    expect(openSealedHistory(sealHistory(rows, key), key, revisions(rows))).toEqual(rows);
  });

  it("keeps SSH transfer, model relay, and future nested action detail inside ciphertext", () => {
    const sshRequest = request();
    sshRequest.id = "req_ssh";
    sshRequest.action = {
      kind: "ssh_session", command: "ssh", args: [], injectEnv: "SSH_KEY", timeoutMs: 1000,
      ssh: {
        target: "private ssh target marker", port: 22, managedRouteId: "private route marker",
        transfer: {
          direction: "upload", sourcePath: "/private/source-marker",
          destinationPath: "/private/destination-marker", sha256: "private sha marker",
          approvalScope: "spooled-content-sha256", spoolId: "private spool marker",
          spoolExpiresAt: ts
        }
      }
    };
    const modelRequest = request();
    modelRequest.id = "req_model";
    modelRequest.action = {
      kind: "model_relay", command: "model-relay", args: [], injectEnv: "MODEL_KEY", timeoutMs: 1000,
      model: {
        provider: "anthropic", routes: ["private model route marker"], ttlMs: 1000,
        payloadProfile: "strict", toolBoundary: "client-only",
        allowedModels: ["private model name marker"], workspaceId: "private workspace marker"
      }
    };
    Object.assign(modelRequest.action, { futureField: "private future action marker" });
    const rows = { requests: [
      { revision: 1, record: sshRequest }, { revision: 1, record: modelRequest }
    ], audit: [] };

    const sealed = sealHistory(rows, key);
    expect(JSON.stringify(sealed)).not.toMatch(/private|source-marker|destination-marker|futureField/);
    expect(openSealedHistory(sealed, key, revisions(rows))).toEqual(rows);
  });

  it("rejects unknown versions, fields, and duplicate IDs", () => {
    const rows = fixture();
    const sealed = sealHistory(rows, key);
    const anchor = revisions(rows);
    expect(() => sealHistory({ requests: [rows.requests[0], rows.requests[0]], audit: [] }, key))
      .toThrow("Duplicate sealed history ID");
    expect(() => sealHistory({ requests: rows.requests,
      audit: [{ revision: 1, record: { ...event(), id: rows.requests[0].record.id } }] }, key))
      .toThrow("Duplicate sealed history ID");

    const duplicate = structuredClone(sealed);
    duplicate.requests.push(duplicate.requests[0]);
    expect(() => openSealedHistory(duplicate, key, anchor)).toThrow("Duplicate sealed history ID");
    expect(() => openSealedHistory({ ...sealed, version: 4 }, key, anchor)).toThrow("Unsupported sealed history format");
    expect(() => openSealedHistory({ ...sealed, surprise: "private marker" }, key, anchor))
      .toThrow("Unknown sealed history field");
    expect(() => openSealedHistory({ ...sealed, requests: [{ ...sealed.requests[0], leak: "private" }] }, key, anchor))
      .toThrow("Unknown sealed history field");
    expect(() => openSealedHistory({ ...sealed, audit: [{ ...sealed.audit[0],
      box: { ...sealed.audit[0].box, unknown: true } }] }, key, anchor)).toThrow("Unknown sealed history field");
    expect(() => sealHistory({ ...rows, unknown: "private" } as typeof rows, key))
      .toThrow("Unknown sealed history field");
    expect(() => sealHistory({ ...rows, requests: [{ ...rows.requests[0], unknown: true }] } as typeof rows, key))
      .toThrow("Unknown sealed history field");
    expect(() => sealHistory({ requests: [{ revision: 1, record: { ...request(),
      futureDetail: "private" } as RequestRecord }], audit: [] }, key))
      .toThrow("Unknown sealed history detail field");
  });

  it("authenticates kind, ID, revision, time, state, key, and ciphertext", () => {
    const rows = fixture();
    const sealed = sealHistory(rows, key);
    const anchor = revisions(rows);
    const altered = (change: (copy: typeof sealed) => void) => {
      const copy = structuredClone(sealed);
      change(copy);
      expect(() => openSealedHistory(copy, key, anchor)).toThrow();
    };
    altered(copy => { copy.requests[0].id = "req_other"; });
    altered(copy => { copy.requests[0].revision = 2; });
    altered(copy => { copy.requests[0].updatedAt = "2026-11-12T02:01:00.000Z"; });
    altered(copy => { copy.requests[0].state = "approved"; });
    altered(copy => { copy.audit[0].ts = "2026-11-12T02:01:00.000Z"; });
    altered(copy => { copy.audit[0].box = copy.requests[0].box; });
    altered(copy => { copy.requests[0].box.ciphertext = "AAAA"; });
    expect(() => openSealedHistory(sealed, randomBytes(32), anchor)).toThrow();
  });

  it("fails closed on a torn write and detects replay using a trusted revision anchor", () => {
    const first = sealHistory(fixture(), key);
    const nextRows = fixture();
    nextRows.requests[0].revision = 2;
    nextRows.requests[0].record.reason = "private later revision marker";
    const latest = sealHistory(nextRows, key);
    const anchor = new Map([["req_synthetic", 2], ["audit_synthetic", 1]]);

    expect(() => openSealedHistory(latest, key, undefined as unknown as Map<string, number>))
      .toThrow("trusted history revision anchor is required");
    expect(() => openSealedHistory(JSON.stringify(latest).slice(0, -8), key, anchor)).toThrow();
    const tornRow = structuredClone(latest);
    tornRow.requests[0].box.ciphertext = tornRow.requests[0].box.ciphertext.slice(0, -4);
    expect(() => openSealedHistory(tornRow, key, anchor)).toThrow();
    expect(openSealedHistory(latest, key, anchor)).toEqual(nextRows);
    expect(() => openSealedHistory(first, key, anchor)).toThrow("revision anchor mismatch");
    expect(() => openSealedHistory({ ...latest, audit: [] }, key, anchor))
      .toThrow("revision anchor mismatch");
  });
});
