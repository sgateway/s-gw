type LedgerShape = "generation-2" | "app" | "mixed" | "unmarked";

export interface LedgerFormatInspection {
  /** Field markers are not proof of which runtime wrote the ledger. */
  shape: LedgerShape;
  writerGeneration?: number;
  secrets: number;
  requests: number;
  audit: number;
  agentIdentities: number;
  hasEncryptedSensitiveMetadata: boolean;
  managedSshRoutes: number;
  approvalPolicyRules: number;
  conditionFields: string[];
  unknownConditionFields: number;
  plaintextRequestRows: number;
  plaintextAuditRows: number;
}

export interface LedgerControlComparison {
  secretsOnlyInFirst: number;
  secretsOnlyInSecond: number;
  secretsChanged: number;
  grantsOnlyInFirst: number;
  grantsOnlyInSecond: number;
  grantsChanged: number;
  approvalSettingsChanged: boolean;
  rulesOnlyInFirst: number;
  rulesOnlyInSecond: number;
  rulesChanged: number;
  ruleConditionsChanged: number;
  routesOnlyInFirst: number;
  routesOnlyInSecond: number;
  routesChanged: number;
}

const knownConditionFields = new Set([
  "handles", "envBindings", "secretTypes", "providers", "minSeverity",
  "agents", "principalIds", "actionKinds", "commands", "resolvedCommands",
  "injectEnvs", "workingDirs", "sshTargets", "sshPorts", "actionKeys"
]);

interface LedgerDocument extends Record<string, unknown> {
  version: 1;
  secrets: unknown[];
  requests: unknown[];
  audit: unknown[];
  approvalSettings: Record<string, unknown>;
  approvalGrants: unknown[];
  approvalPolicyRules: unknown[];
}

export function inspectLedgerFormat(raw: string): LedgerFormatInspection {
  const ledger = parseLedger(raw);
  const hasGenerationTwoFields = ["writerGeneration", "agentIdentities", "sensitiveMetadata"]
    .some((field) => Object.hasOwn(ledger, field));
  const hasAppFields = Object.hasOwn(ledger, "managedSshRoutes");
  const identities = optionalArray(ledger.agentIdentities);
  const routes = optionalArray(ledger.managedSshRoutes);
  const conditionFields = new Set<string>();
  let unknownConditionFields = 0;

  for (const value of ledger.approvalPolicyRules) {
    const rule = objectValue(value);
    const conditions = objectValue(rule?.conditions);
    if (!conditions) throw new Error("Invalid approval policy structure in ledger.");
    for (const field of Object.keys(conditions)) {
      if (knownConditionFields.has(field)) conditionFields.add(field);
      else unknownConditionFields += 1;
    }
  }

  const writerGeneration = ledger.writerGeneration;
  if (writerGeneration !== undefined && (!Number.isInteger(writerGeneration) || Number(writerGeneration) < 1)) {
    throw new Error("Invalid writer generation in ledger.");
  }
  if (ledger.sensitiveMetadata !== undefined && !encryptedBoxShape(ledger.sensitiveMetadata)) {
    throw new Error("Invalid sensitive metadata structure in ledger.");
  }

  return {
    shape: hasGenerationTwoFields && hasAppFields ? "mixed"
      : hasGenerationTwoFields ? "generation-2"
        : hasAppFields ? "app" : "unmarked",
    ...(writerGeneration !== undefined ? { writerGeneration: Number(writerGeneration) } : {}),
    secrets: ledger.secrets.length,
    requests: ledger.requests.length,
    audit: ledger.audit.length,
    agentIdentities: identities.length,
    hasEncryptedSensitiveMetadata: ledger.sensitiveMetadata !== undefined,
    managedSshRoutes: routes.length,
    approvalPolicyRules: ledger.approvalPolicyRules.length,
    conditionFields: [...conditionFields].sort(),
    unknownConditionFields,
    plaintextRequestRows: ledger.requests.filter(requestHasPlaintext).length,
    plaintextAuditRows: ledger.audit.filter((entry) => hasText(objectValue(entry)?.message)).length
  };
}

export function compareLedgerControl(firstRaw: string, secondRaw: string): LedgerControlComparison {
  const first = parseLedger(firstRaw);
  const second = parseLedger(secondRaw);
  const firstSecrets = recordsByKey(first.secrets, "handle");
  const secondSecrets = recordsByKey(second.secrets, "handle");
  const firstGrants = recordsByKey(first.approvalGrants, "id");
  const secondGrants = recordsByKey(second.approvalGrants, "id");
  const firstRules = recordsByKey(first.approvalPolicyRules, "id");
  const secondRules = recordsByKey(second.approvalPolicyRules, "id");
  const firstRoutes = recordsByKey(optionalArray(first.managedSshRoutes), "id");
  const secondRoutes = recordsByKey(optionalArray(second.managedSshRoutes), "id");

  let ruleConditionsChanged = 0;
  for (const [id, rule] of firstRules) {
    const other = secondRules.get(id);
    if (!other) continue;
    if (canonical(rule.conditions) !== canonical(other.conditions)) ruleConditionsChanged += 1;
  }

  return {
    secretsOnlyInFirst: countMissing(firstSecrets, secondSecrets),
    secretsOnlyInSecond: countMissing(secondSecrets, firstSecrets),
    secretsChanged: countChanged(firstSecrets, secondSecrets),
    grantsOnlyInFirst: countMissing(firstGrants, secondGrants),
    grantsOnlyInSecond: countMissing(secondGrants, firstGrants),
    grantsChanged: countChanged(firstGrants, secondGrants),
    approvalSettingsChanged: canonical(first.approvalSettings) !== canonical(second.approvalSettings),
    rulesOnlyInFirst: countMissing(firstRules, secondRules),
    rulesOnlyInSecond: countMissing(secondRules, firstRules),
    rulesChanged: countChanged(firstRules, secondRules),
    ruleConditionsChanged,
    routesOnlyInFirst: countMissing(firstRoutes, secondRoutes),
    routesOnlyInSecond: countMissing(secondRoutes, firstRoutes),
    routesChanged: countChanged(firstRoutes, secondRoutes)
  };
}

function parseLedger(raw: string): LedgerDocument {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error("Invalid ledger JSON.");
  }
  const ledger = objectValue(value);
  if (!ledger || ledger.version !== 1 || !Array.isArray(ledger.secrets)
      || !Array.isArray(ledger.requests) || !Array.isArray(ledger.audit)
      || !objectValue(ledger.approvalSettings) || !Array.isArray(ledger.approvalGrants)
      || !Array.isArray(ledger.approvalPolicyRules)) {
    throw new Error("Unsupported or invalid ledger structure.");
  }
  return ledger as LedgerDocument;
}

function optionalArray(value: unknown): unknown[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("Invalid optional ledger collection.");
  return value;
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function encryptedBoxShape(value: unknown): boolean {
  const box = objectValue(value);
  return Boolean(box && box.alg === "aes-256-gcm" && box.kdf === "scrypt"
    && ["salt", "iv", "authTag", "ciphertext"].every((field) => typeof box[field] === "string"));
}

function hasText(value: unknown): boolean {
  return typeof value === "string" && value.length > 0;
}

function requestHasPlaintext(value: unknown): boolean {
  const request = objectValue(value);
  const action = objectValue(request?.action);
  const ssh = objectValue(action?.ssh);
  const transfer = objectValue(ssh?.transfer);
  const http = objectValue(action?.http);
  const headers = objectValue(http?.headers);
  const auth = objectValue(http?.auth);
  const result = objectValue(request?.resultSummary);
  return Boolean(hasText(request?.reason) || hasText(request?.error)
    || (Array.isArray(action?.args) && action.args.length > 0)
    || hasText(action?.workingDir) || hasText(ssh?.target)
    || hasText(transfer?.sourcePath) || hasText(transfer?.destinationPath)
    || hasText(http?.url) || hasText(http?.body) || (headers && Object.keys(headers).length > 0)
    || hasText(auth?.username)
    || hasText(result?.stdout) || hasText(result?.stderr));
}

function recordsByKey(values: unknown[], key: "id" | "handle"): Map<string, Record<string, unknown>> {
  const records = new Map<string, Record<string, unknown>>();
  for (const value of values) {
    const record = objectValue(value);
    const id = record?.[key];
    if (!record || typeof id !== "string" || !id || records.has(id)) {
      throw new Error("Invalid or duplicate ledger record key.");
    }
    records.set(id, record);
  }
  return records;
}

function countChanged(first: Map<string, Record<string, unknown>>, second: Map<string, Record<string, unknown>>): number {
  let changed = 0;
  for (const [id, record] of first) {
    const other = second.get(id);
    if (other && canonical(record) !== canonical(other)) changed += 1;
  }
  return changed;
}

function countMissing(first: Map<string, unknown>, second: Map<string, unknown>): number {
  let missing = 0;
  for (const id of first.keys()) {
    if (!second.has(id)) missing += 1;
  }
  return missing;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = objectValue(value);
  if (object) {
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
