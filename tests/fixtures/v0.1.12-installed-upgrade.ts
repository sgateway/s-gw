import type { StoreFile } from "../../src/types.js";

export const installedV0112Counts = {
  credentials: 83,
  policies: 2,
  requests: 1_453,
  audit: 4_680
} as const;

export function installedV0112Store(): StoreFile {
  const createdAt = "2026-07-15T18:00:00.000Z";
  const secrets: StoreFile["secrets"] = [];
  for (let index = 0; index < installedV0112Counts.credentials; index += 1) {
    const suffix = String(index + 1).padStart(3, "0");
    const backend = index < 57 ? "keychain" : index < 74 ? "local" : "onepassword";
    secrets.push({
      handle: `s-gw:credential:upgrade-${suffix}`,
      name: `Installed credential ${suffix}`,
      type: "credential",
      backend,
      provider: index % 2 === 0 ? "aws" : "github",
      createdAt,
      updatedAt: `2026-07-16T00:${String(index % 60).padStart(2, "0")}:00.000Z`,
      fingerprint: String(index + 1).padStart(64, "0"),
      encrypted: {
        alg: "aes-256-gcm",
        kdf: "scrypt",
        salt: "c2FsdA==",
        iv: "aXY=",
        authTag: "dGFn",
        ciphertext: `fixture-${suffix}`
      },
      policy: {
        injectEnv: `UPGRADE_CREDENTIAL_${suffix}`,
        allowedCommands: ["node"],
        maxOutputBytes: 1_048_576
      }
    });
  }

  const requests: StoreFile["requests"] = [];
  for (let index = 0; index < installedV0112Counts.requests; index += 1) {
    const handle = secrets[index % secrets.length].handle;
    requests.push({
      id: `req_upgrade_${String(index + 1).padStart(4, "0")}`,
      handle,
      reason: "Installed 0.1.12 upgrade fixture",
      agentName: index % 2 === 0 ? "Codex" : "Claude Code",
      agentSource: "configured",
      action: {
        kind: "env_command",
        command: "node",
        args: ["--version"],
        injectEnv: secrets[index % secrets.length].policy.injectEnv!,
        timeoutMs: 30_000
      },
      state: index % 5 === 0 ? "denied" : "executed",
      createdAt,
      updatedAt: createdAt
    });
  }

  const audit: StoreFile["audit"] = [];
  for (let index = 0; index < installedV0112Counts.audit; index += 1) {
    const request = requests[index % requests.length];
    audit.push({
      id: `audit_upgrade_${String(index + 1).padStart(4, "0")}`,
      ts: createdAt,
      type: index % 5 === 0 ? "request.denied" : "request.executed",
      handle: request.handle,
      requestId: request.id,
      message: `Installed upgrade audit row ${index + 1}`
    });
  }

  return {
    version: 1,
    secrets,
    requests,
    audit,
    approvalSettings: { mode: "per-transaction", durationMs: 900_000 },
    approvalGrants: [],
    approvalPolicyRules: [
      {
        id: "policy_installed_allow",
        name: "Allow installed development tools",
        enabled: true,
        priority: 100,
        decision: "allow",
        conditions: { agents: ["Codex"], handles: [secrets[0].handle] },
        createdAt,
        updatedAt: createdAt
      },
      {
        id: "policy_installed_ask",
        name: "Ask for other installed tools",
        enabled: true,
        priority: 110,
        decision: "ask",
        conditions: { actionKinds: ["env_command"] },
        createdAt,
        updatedAt: createdAt
      }
    ]
  };
}
