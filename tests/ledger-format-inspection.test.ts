import { describe, expect, it } from "vitest";
import { encryptSecret } from "../src/crypto.js";
import { compareLedgerControl, inspectLedgerFormat } from "../src/ledger-format-inspection.js";

const timestamp = "2026-10-21T00:00:00.000Z";

function baseLedger() {
  return {
    version: 1,
    secrets: [{ handle: "s-gw:test:one", policy: { allowedCommands: ["/usr/bin/true"] } }],
    requests: [{
      id: "req_one",
      handle: "s-gw:test:one",
      reason: "",
      action: { kind: "env_command", command: "/usr/bin/true", args: [] },
      state: "failed",
      createdAt: timestamp,
      updatedAt: timestamp
    }],
    audit: [{ id: "audit_one", ts: timestamp, type: "request.failed", message: "" }],
    approvalSettings: { mode: "per-transaction", durationMs: 900000 },
    approvalGrants: [{ id: "grant_one", mode: "timed", agentScope: "same-agent" }],
    approvalPolicyRules: [{
      id: "rule_one",
      name: "Exact command",
      enabled: true,
      priority: 100,
      decision: "allow",
      conditions: {
        handles: ["s-gw:test:one"],
        envBindings: [{ handle: "s-gw:test:one", injectEnv: "TEST_TOKEN" }],
        resolvedCommands: ["/usr/bin/true"],
        principalIds: ["principal_one"],
        actionKeys: ["opaque-action-key"]
      },
      createdAt: timestamp,
      updatedAt: timestamp
    }]
  };
}

function generationTwoLedger() {
  return {
    ...baseLedger(),
    writerGeneration: 2,
    agentIdentities: [{ id: "agent_one", canonicalName: "Claude", customName: "Team Claude" }],
    sensitiveMetadata: encryptSecret(JSON.stringify({
      requests: { req_one: { reason: "private legacy reason", args: ["private legacy argument"] } },
      audit: { audit_one: "private legacy audit" }
    }), "synthetic passphrase")
  };
}

function appLedger() {
  const ledger = baseLedger();
  return {
    ...ledger,
    requests: [{
      ...ledger.requests[0],
      reason: "private current reason",
      action: { ...ledger.requests[0].action, args: ["private current argument"] }
    }],
    audit: [{ ...ledger.audit[0], message: "private current audit" }],
    managedSshRoutes: [{
      id: "route_one",
      name: "Managed route",
      route: { host: "example.test", port: 22 },
      createdAt: timestamp,
      updatedAt: timestamp
    }]
  };
}

describe("ledger format inspection", () => {
  it("identifies encrypted generation-2 metadata without decrypting or returning values", () => {
    const inspected = inspectLedgerFormat(JSON.stringify(generationTwoLedger()));

    expect(inspected).toMatchObject({
      shape: "generation-2",
      writerGeneration: 2,
      secrets: 1,
      requests: 1,
      audit: 1,
      agentIdentities: 1,
      hasEncryptedSensitiveMetadata: true,
      managedSshRoutes: 0,
      plaintextRequestRows: 0,
      plaintextAuditRows: 0
    });
    expect(JSON.stringify(inspected)).not.toMatch(/private legacy|Team Claude|principal_one|opaque-action-key/);
  });

  it("identifies managed routes, every known rule condition field, and plaintext history", () => {
    const inspected = inspectLedgerFormat(JSON.stringify(appLedger()));

    expect(inspected.shape).toBe("app");
    expect(inspected.managedSshRoutes).toBe(1);
    expect(inspected.conditionFields).toEqual([
      "actionKeys", "envBindings", "handles", "principalIds", "resolvedCommands"
    ]);
    expect(inspected.plaintextRequestRows).toBe(1);
    expect(inspected.plaintextAuditRows).toBe(1);
    expect(JSON.stringify(inspected)).not.toMatch(/private current|principal_one|opaque-action-key|example.test/);
  });

  it("compares complete policy conditions and routes without returning their values", () => {
    const first = appLedger();
    const same = JSON.parse(JSON.stringify(first));
    same.approvalPolicyRules[0].conditions = {
      resolvedCommands: ["/usr/bin/true"],
      actionKeys: ["opaque-action-key"],
      principalIds: ["principal_one"],
      envBindings: [{ injectEnv: "TEST_TOKEN", handle: "s-gw:test:one" }],
      handles: ["s-gw:test:one"]
    };
    expect(compareLedgerControl(JSON.stringify(first), JSON.stringify(same))).toEqual({
      secretsOnlyInFirst: 0,
      secretsOnlyInSecond: 0,
      secretsChanged: 0,
      grantsOnlyInFirst: 0,
      grantsOnlyInSecond: 0,
      grantsChanged: 0,
      approvalSettingsChanged: false,
      rulesOnlyInFirst: 0,
      rulesOnlyInSecond: 0,
      rulesChanged: 0,
      ruleConditionsChanged: 0,
      routesOnlyInFirst: 0,
      routesOnlyInSecond: 0,
      routesChanged: 0
    });

    same.approvalPolicyRules[0].conditions.envBindings[0].handle = "s-gw:test:changed";
    same.managedSshRoutes[0].route.port = 2222;
    const changed = compareLedgerControl(JSON.stringify(first), JSON.stringify(same));
    expect(changed.rulesChanged).toBe(1);
    expect(changed.ruleConditionsChanged).toBe(1);
    expect(changed.routesChanged).toBe(1);
    expect(JSON.stringify(changed)).not.toMatch(/s-gw:test:changed|2222/);
  });

  it("detects approval decisions and rule metadata changes even when conditions match", () => {
    const first = appLedger();
    const second = JSON.parse(JSON.stringify(first));
    second.approvalPolicyRules[0].decision = "deny";
    second.approvalPolicyRules[0].enabled = false;
    second.approvalPolicyRules[0].priority = 5;
    second.approvalPolicyRules[0].name = "Different rule";
    second.approvalPolicyRules[0].expiresAt = timestamp;
    second.approvalPolicyRules[0].updatedAt = "2026-10-22T00:00:00.000Z";

    const compared = compareLedgerControl(JSON.stringify(first), JSON.stringify(second));
    expect(compared.rulesChanged).toBe(1);
    expect(compared.ruleConditionsChanged).toBe(0);
  });

  it("detects credential, grant, and approval-setting drift without returning values", () => {
    const first = appLedger();
    const second = JSON.parse(JSON.stringify(first));
    second.secrets[0].policy.allowedCommands = ["/private/changed-command"];
    second.approvalGrants[0].mode = "unlimited";
    second.approvalSettings.durationMs = 30000;

    const compared = compareLedgerControl(JSON.stringify(first), JSON.stringify(second));
    expect(compared.secretsChanged).toBe(1);
    expect(compared.grantsChanged).toBe(1);
    expect(compared.approvalSettingsChanged).toBe(true);
    expect(compared.rulesChanged).toBe(0);
    expect(compared.routesChanged).toBe(0);
    expect(JSON.stringify(compared)).not.toMatch(/private|unlimited|30000/);
  });

  it("counts missing credentials and grants separately from changed records", () => {
    const first = appLedger();
    const second = JSON.parse(JSON.stringify(first));
    second.secrets = [{ handle: "s-gw:test:second" }];
    second.approvalGrants = [];

    const compared = compareLedgerControl(JSON.stringify(first), JSON.stringify(second));
    expect(compared.secretsOnlyInFirst).toBe(1);
    expect(compared.secretsOnlyInSecond).toBe(1);
    expect(compared.secretsChanged).toBe(0);
    expect(compared.grantsOnlyInFirst).toBe(1);
    expect(compared.grantsOnlyInSecond).toBe(0);
  });

  it("counts unrecognized condition keys without returning names or values", () => {
    const ledger = appLedger();
    const condition = ledger.approvalPolicyRules[0].conditions as Record<string, unknown>;
    condition["private custom condition"] = "private custom value";

    const inspected = inspectLedgerFormat(JSON.stringify(ledger));
    expect(inspected.unknownConditionFields).toBe(1);
    expect(JSON.stringify(inspected)).not.toContain("private custom");

    const changed = JSON.parse(JSON.stringify(ledger));
    changed.approvalPolicyRules[0].conditions["private custom condition"] = "different private value";
    expect(compareLedgerControl(JSON.stringify(ledger), JSON.stringify(changed)).rulesChanged).toBe(1);
    expect(compareLedgerControl(JSON.stringify(ledger), JSON.stringify(changed)).ruleConditionsChanged).toBe(1);
  });

  it("detects plaintext HTTP headers even if the other display fields are redacted", () => {
    const ledger = generationTwoLedger();
    Object.assign(ledger.requests[0].action, { http: { headers: { Authorization: "private header" } } });

    expect(inspectLedgerFormat(JSON.stringify(ledger)).plaintextRequestRows).toBe(1);
  });

  it("does not echo invalid ledger data in errors", () => {
    expect(() => inspectLedgerFormat("private invalid JSON"))
      .toThrow("Invalid ledger JSON.");
    expect(() => inspectLedgerFormat(JSON.stringify({ ...baseLedger(), sensitiveMetadata: "private malformed value" })))
      .toThrow("Invalid sensitive metadata structure in ledger.");
  });
});
