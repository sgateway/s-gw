import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, chmod, mkdir, open, readFile, readdir, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { decryptSecret, encryptSecret, fingerprintSecret, shortId } from "./crypto.js";
import { requestAgentIdentity, requestAgentName, type AgentIdentityContext } from "./agent-context.js";
import { normalizeOnePasswordReference, readOnePasswordReference } from "./onepassword.js";
import { SGW_SSH_SESSION_COMMAND, normalizeSshPort, normalizeSshTarget, sshSessionIdentity } from "./ssh.js";
import { ensureSgwHome, getSgwHome, getStorePath } from "./paths.js";
import {
  defaultSecretKeychainService,
  deleteMacKeychainItem,
  getMacKeychainItem,
  setMacKeychainItem,
  type MacKeychainItemRef
} from "./unlock.js";
import type {
  ApprovalGrant,
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyActionKind,
  ApprovalPolicyConditions,
  ApprovalPolicyDecision,
  ApprovalPolicyRule,
  ApprovalSettings,
  AuditEvent,
  CommandAction,
  CommandEnvBinding,
  ExecutionSummary,
  HandleSummary,
  RequestRecord,
  RequestState,
  SecretPolicy,
  SecretRecord,
  SecretSeverity,
  SecretType,
  SecretValueCache,
  StoreFile
} from "./types.js";

const defaultApprovalSettings: ApprovalSettings = {
  mode: "per-transaction",
  durationMs: 15 * 60 * 1000
};

const maxApprovalDurationMs = 30 * 24 * 60 * 60 * 1000;
const lockTimeoutMs = 5_000;
const staleLockMs = 30_000;

// A request gets claimed into "executing" right before its secret is revealed. If the
// runner is killed, sleeps, or crashes before markExecuted/markFailed, that request is
// stranded. Anything still "executing" past this window almost certainly lost its runner,
// so we reap it back to a terminal failed state instead of bricking it forever.
const staleExecutionMs = 10 * 60 * 1000;
const maxStoreBackups = 20;

const emptyStore = (): StoreFile => ({
  version: 1,
  secrets: [],
  requests: [],
  audit: [],
  approvalSettings: { ...defaultApprovalSettings },
  approvalGrants: [],
  approvalPolicyRules: []
});

export interface AddSecretInput {
  name: string;
  type: SecretType;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  value: string;
  source?: string;
  policy?: Partial<SecretPolicy>;
}

export interface AddOnePasswordReferenceInput {
  name: string;
  type: SecretType;
  reference: string;
  source?: string;
  policy?: Partial<SecretPolicy>;
}

export interface AddKeychainSecretInput extends AddSecretInput {
  service?: string;
}

export interface SetApprovalSettingsInput {
  mode: ApprovalMode;
  durationMs?: number;
}

export interface AddApprovalPolicyRuleInput {
  name?: string;
  enabled?: boolean;
  priority?: number;
  decision: ApprovalPolicyDecision;
  conditions?: Partial<ApprovalPolicyConditions>;
  expiresAt?: string;
  durationMs?: number;
}

export interface SetApprovalPolicyRuleEnabledResult {
  id: string;
  enabled: boolean;
}

export interface ApproveRequestOptions {
  mode?: ApprovalMode;
  durationMs?: number;
  agentScope?: ApprovalAgentScope;
}

export interface DeleteSecretResult {
  handle: string;
  name: string;
  revokedApprovalGrants: number;
  revokedApprovalPolicies: number;
  failedRequests: RequestRecord[];
}

export interface ClearApprovalGrantsResult {
  revokedCount: number;
  revoked: ApprovalGrant[];
}

export interface RequestListOptions {
  state?: RequestState;
  active?: boolean;
  limit?: number;
}

export interface CleanupRequestsOptions {
  pendingOlderThanMs?: number;
  approvedOlderThanMs?: number;
  duplicatePending?: boolean;
}

export interface CleanupRequestsResult {
  cleanedCount: number;
  requests: RequestRecord[];
}

export interface StoreBackupSummary {
  path: string;
  bytes: number;
  modifiedAt: string;
}

export class SecretStore {
  readonly home: string;
  readonly storePath: string;

  constructor(home = getSgwHome()) {
    this.home = home;
    this.storePath = getStorePath(home);
  }

  async init(): Promise<void> {
    await ensureSgwHome(this.home);
    await this.withStoreLock(async () => {
      const exists = await this.exists();
      if (exists) {
        return;
      }

      await this.writeUnlocked(emptyStore());
      await chmod(this.storePath, 0o600);
    });
  }

  async addSecret(input: AddSecretInput): Promise<SecretRecord> {
    if (!input.value) {
      throw new Error("Cannot add an empty secret.");
    }

    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(input.value);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.provider = input.provider || existing.provider;
        existing.backend = existing.backend || "local";
        existing.ruleId = input.ruleId || existing.ruleId;
        existing.severity = input.severity || existing.severity;
        existing.confidence = input.confidence ?? existing.confidence;
        existing.source = input.source || existing.source;
        existing.policy = normalizePolicy(input.policy, existing.policy);
        store.audit.push(audit("secret.matched", `Existing handle reused for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle: makeHandle(input.type),
        name: input.name,
        type: input.type,
        backend: "local",
        provider: input.provider,
        ruleId: input.ruleId,
        severity: input.severity,
        confidence: input.confidence,
        createdAt: now,
        updatedAt: now,
        source: input.source,
        fingerprint,
        encrypted: encryptSecret(input.value),
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added local handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async addKeychainSecret(input: AddKeychainSecretInput): Promise<SecretRecord> {
    if (!input.value) {
      throw new Error("Cannot add an empty secret.");
    }

    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(input.value);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      const handle = existing?.handle || makeHandle(input.type);
      const ref: MacKeychainItemRef = {
        service: input.service || defaultSecretKeychainService(),
        account: handle,
        label: keychainSecretLabel(input.name || existing?.name || handle)
      };

      setMacKeychainItem(ref, input.value);

      const encryptedRef = encryptSecret(JSON.stringify(keychainRefPayload(ref)));
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.backend = "keychain";
        existing.provider = credentialStoreProvider();
        existing.ruleId = input.ruleId || existing.ruleId;
        existing.severity = input.severity || existing.severity;
        existing.confidence = input.confidence ?? existing.confidence;
        existing.source = input.source || existing.source || credentialStoreProvider();
        existing.encrypted = encryptedRef;
        existing.policy = normalizePolicy(input.policy, existing.policy);
        delete existing.cache;
        store.audit.push(audit("secret.matched", `Existing handle moved to OS credential store for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle,
        name: input.name,
        type: input.type,
        backend: "keychain",
        provider: credentialStoreProvider(),
        ruleId: input.ruleId,
        severity: input.severity,
        confidence: input.confidence,
        createdAt: now,
        updatedAt: now,
        source: input.source || credentialStoreProvider(),
        fingerprint,
        encrypted: encryptedRef,
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added OS credential-store-backed handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async addOnePasswordReference(input: AddOnePasswordReferenceInput): Promise<SecretRecord> {
    const reference = normalizeOnePasswordReference(input.reference);
    return this.mutate(async (store) => {
      const fingerprint = fingerprintSecret(`onepassword:${reference}`);
      const now = new Date().toISOString();
      const existing = store.secrets.find((secret) => secret.fingerprint === fingerprint);
      if (existing) {
        existing.updatedAt = now;
        existing.name = input.name || existing.name;
        existing.type = input.type || existing.type;
        existing.backend = "onepassword";
        existing.provider = "1password";
        existing.source = input.source || existing.source || "onepassword";
        existing.policy = normalizePolicy(input.policy, existing.policy);
        store.audit.push(audit("secret.matched", `Existing 1Password handle reused for ${existing.name}.`, existing.handle));
        return existing;
      }

      const record: SecretRecord = {
        handle: makeHandle(input.type),
        name: input.name,
        type: input.type,
        backend: "onepassword",
        provider: "1password",
        severity: "medium",
        confidence: 1,
        createdAt: now,
        updatedAt: now,
        source: input.source || "onepassword",
        fingerprint,
        encrypted: encryptSecret(reference),
        policy: normalizePolicy(input.policy)
      };

      store.secrets.push(record);
      store.audit.push(audit("secret.added", `Added 1Password-backed handle for ${record.name}.`, record.handle));
      return record;
    });
  }

  async listHandles(): Promise<HandleSummary[]> {
    const store = await this.read();
    return store.secrets.map((secret) => summarizeSecret(secret));
  }

  async getHandle(handle: string): Promise<HandleSummary | undefined> {
    const store = await this.read();
    const found = store.secrets.find((secret) => secret.handle === handle);
    return found ? summarizeSecret(found) : undefined;
  }

  async allowCommand(handle: string, command: string): Promise<HandleSummary> {
    const trimmed = command.trim();
    if (!trimmed) {
      throw new Error("Command is required.");
    }

    return this.mutate((store) => {
      const secret = store.secrets.find((item) => item.handle === handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      const allowed = new Set(secret.policy.allowedCommands || []);
      allowed.add(trimmed);
      secret.policy = normalizePolicy({ allowedCommands: [...allowed] }, secret.policy);
      secret.updatedAt = new Date().toISOString();
      store.audit.push(audit("secret.policy.updated", `Allowed ${trimmed} for ${secret.name}.`, handle));
      return summarizeSecret(secret);
    });
  }

  async setInjectEnv(handle: string, injectEnv: string): Promise<HandleSummary> {
    const trimmed = injectEnv.trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed)) {
      throw new Error(`Invalid environment variable name: ${trimmed || "(empty)"}`);
    }

    return this.mutate((store) => {
      const secret = store.secrets.find((item) => item.handle === handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      secret.policy = normalizePolicy({ injectEnv: trimmed }, secret.policy);
      secret.updatedAt = new Date().toISOString();
      store.audit.push(audit("secret.policy.updated", `Set inject environment to ${trimmed} for ${secret.name}.`, handle));
      return summarizeSecret(secret);
    });
  }

  async getSecretRecord(handle: string): Promise<SecretRecord> {
    const store = await this.read();
    const found = store.secrets.find((secret) => secret.handle === handle);
    if (!found) {
      throw new Error(`Unknown secret handle: ${handle}`);
    }

    return found;
  }

  async revealSecretForLocalUse(handle: string, request?: RequestRecord): Promise<string> {
    const record = await this.getSecretRecord(handle);
    if (record.backend === "onepassword") {
      const cached = cachedOnePasswordValue(record, request);
      if (cached) {
        return cached;
      }

      const reference = decryptSecret(record.encrypted);
      const value = await readOnePasswordReference(reference);
      await this.storeOnePasswordCache(handle, value, request);
      return value;
    }

    if (record.backend === "keychain") {
      return getMacKeychainItem(keychainRefFromRecord(record));
    }

    return decryptSecret(record.encrypted);
  }

  private async storeOnePasswordCache(handle: string, value: string, request?: RequestRecord): Promise<void> {
    if (!request?.approvalGrantId || !value) {
      return;
    }

    await this.mutate((store) => {
      const now = new Date().toISOString();
      pruneExpiredApprovalGrants(store, now);
      const secret = store.secrets.find((item) => item.handle === handle && item.backend === "onepassword");
      const grant = store.approvalGrants.find((item) => {
        return item.id === request.approvalGrantId && requestReferencesHandle(request, handle);
      });
      if (!secret || !grant || !grantAllowsCache(grant, now)) {
        return;
      }

      const existing = secret.cache;
      secret.cache = {
        backend: "onepassword",
        encrypted: encryptSecret(value),
        fingerprint: fingerprintSecret(`onepassword-cache:${value}`),
        approvalGrantId: grant.id,
        createdAt: existing?.approvalGrantId === grant.id ? existing.createdAt : now,
        updatedAt: now,
        expiresAt: grant.expiresAt,
        loginSessionId: grant.mode === "always" ? undefined : grant.loginSessionId
      };
      secret.updatedAt = now;
      store.audit.push(audit("secret.cache.updated", `Cached 1Password value for ${secret.name}.`, handle, request.id));
    });
  }

  async deleteSecret(handle: string): Promise<DeleteSecretResult> {
    let keychainRef: MacKeychainItemRef | undefined;
    const result = await this.mutate((store) => {
      const index = store.secrets.findIndex((secret) => secret.handle === handle);
      if (index < 0) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      const [deleted] = store.secrets.splice(index, 1);
      if (deleted.backend === "keychain") {
        keychainRef = keychainRefFromRecord(deleted);
      }

      const beforeGrants = store.approvalGrants.length;
      const beforePolicies = (store.approvalPolicyRules || []).length;
      const requestsById = new Map(store.requests.map((request) => [request.id, request]));
      store.approvalGrants = store.approvalGrants.filter((grant) => {
        if (grant.handle === handle) {
          return false;
        }

        const request = grant.lastRequestId ? requestsById.get(grant.lastRequestId) : undefined;
        return !request || !requestReferencesHandle(request, handle);
      });
      store.approvalPolicyRules = (store.approvalPolicyRules || []).filter((rule) => {
        return !(rule.conditions.handles || []).includes(handle);
      });

      const now = new Date().toISOString();
      const failedRequests: RequestRecord[] = [];
      for (const request of store.requests) {
        if (!requestReferencesHandle(request, handle) || isTerminalRequestState(request.state)) {
          continue;
        }

        request.state = "failed";
        request.updatedAt = now;
        request.error = "Credential handle was deleted before the request completed.";
        failedRequests.push(request);
        store.audit.push(
          audit("request.failed", `Request ${request.id} failed because credential ${handle} was deleted.`, handle, request.id)
        );
      }

      store.audit.push(audit("secret.deleted", `Deleted credential handle for ${deleted.name}.`, handle));
      return {
        handle,
        name: deleted.name,
        revokedApprovalGrants: beforeGrants - store.approvalGrants.length,
        revokedApprovalPolicies: beforePolicies - store.approvalPolicyRules.length,
        failedRequests
      };
    });

    if (keychainRef) {
      deleteMacKeychainItem(keychainRef);
    }

    return result;
  }

  async getApprovalSettings(): Promise<ApprovalSettings> {
    const store = await this.read();
    return normalizeApprovalSettings(store.approvalSettings);
  }

  async setApprovalSettings(input: SetApprovalSettingsInput): Promise<ApprovalSettings> {
    return this.mutate((store) => {
      const settings = normalizeApprovalSettings(input);
      store.approvalSettings = settings;
      store.approvalGrants = [];
      clearOnePasswordCaches(store);
      store.audit.push(audit("approval.settings.updated", `Approval mode changed to ${settings.mode}.`));
      return settings;
    });
  }

  async listApprovalGrants(): Promise<ApprovalGrant[]> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      return [...store.approvalGrants].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    });
  }

  async revokeApprovalGrant(id: string): Promise<ApprovalGrant> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      const index = store.approvalGrants.findIndex((grant) => grant.id === id);
      if (index < 0) {
        throw new Error(`Unknown approval grant: ${id}`);
      }

      const [revoked] = store.approvalGrants.splice(index, 1);
      clearOnePasswordCaches(store, new Set([revoked.id]));
      store.audit.push(audit("approval.grant.revoked", `Revoked approval grant ${id}.`, revoked.handle, revoked.lastRequestId));
      return revoked;
    });
  }

  async clearApprovalGrants(): Promise<ClearApprovalGrantsResult> {
    return this.mutate((store) => {
      pruneExpiredApprovalGrants(store, new Date().toISOString());
      const revoked = store.approvalGrants;
      store.approvalGrants = [];
      clearOnePasswordCaches(store);
      if (revoked.length > 0) {
        store.audit.push(audit("approval.grants.cleared", `Revoked ${revoked.length} approval grant(s).`));
      }

      return {
        revokedCount: revoked.length,
        revoked
      };
    });
  }

  async listApprovalPolicyRules(): Promise<ApprovalPolicyRule[]> {
    const store = await this.read();
    return sortApprovalPolicyRules(store.approvalPolicyRules || []);
  }

  async addApprovalPolicyRule(input: AddApprovalPolicyRuleInput): Promise<ApprovalPolicyRule> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const rule = normalizeApprovalPolicyRule(
        {
          id: shortId("policy"),
          name: input.name || defaultPolicyRuleName(input.decision),
          enabled: input.enabled !== false,
          priority: input.priority ?? nextPolicyPriority(store),
          decision: input.decision,
          conditions: normalizeApprovalPolicyConditions(input.conditions),
          expiresAt: policyExpiresAt(input, now),
          createdAt: now,
          updatedAt: now
        },
        now
      );

      store.approvalPolicyRules = sortApprovalPolicyRules([...(store.approvalPolicyRules || []), rule]);
      store.audit.push(audit("approval.policy.created", `Created approval policy ${rule.name}.`));
      return rule;
    });
  }

  async deleteApprovalPolicyRule(id: string): Promise<ApprovalPolicyRule> {
    return this.mutate((store) => {
      const rules = store.approvalPolicyRules || [];
      const index = rules.findIndex((rule) => rule.id === id);
      if (index < 0) {
        throw new Error(`Unknown approval policy: ${id}`);
      }

      const [deleted] = rules.splice(index, 1);
      store.approvalPolicyRules = rules;
      store.audit.push(audit("approval.policy.deleted", `Deleted approval policy ${deleted.name}.`));
      return deleted;
    });
  }

  async setApprovalPolicyRuleEnabled(id: string, enabled: boolean): Promise<SetApprovalPolicyRuleEnabledResult> {
    return this.mutate((store) => {
      const rule = (store.approvalPolicyRules || []).find((item) => item.id === id);
      if (!rule) {
        throw new Error(`Unknown approval policy: ${id}`);
      }

      rule.enabled = enabled;
      rule.updatedAt = new Date().toISOString();
      store.audit.push(
        audit("approval.policy.updated", `${enabled ? "Enabled" : "Disabled"} approval policy ${rule.name}.`)
      );
      return { id, enabled };
    });
  }

  async createRequest(
    handle: string,
    action: CommandAction,
    reason: string,
    agentContext: AgentIdentityContext = {}
  ): Promise<RequestRecord> {
    return this.mutate((store) => {
      const secret = store.secrets.find((item) => item.handle === handle);
      if (!secret) {
        throw new Error(`Unknown secret handle: ${handle}`);
      }

      const now = new Date().toISOString();
      pruneExpiredApprovalGrants(store, now);
      const normalizedAction = normalizeAction(action);
      const agent = requestAgentIdentity(reason, agentContext);
      assertActionAllowed(secret, normalizedAction);
      assertBoundHandlesAllowed(store, handle, normalizedAction);
      const policyRule = matchingApprovalPolicyRule(store, secret, normalizedAction, agent.name, now);
      const deniedByPolicy = policyRule?.decision === "deny";
      const allowedByPolicy = policyRule?.decision === "allow";
      const grant = activeApprovalGrant(store, handle, normalizedAction, agent.name, now);
      const record: RequestRecord = {
        id: shortId("req"),
        handle,
        reason: reason || "No reason supplied.",
        agentName: agent.name,
        agentSource: agent.source,
        action: normalizedAction,
        state: deniedByPolicy ? "denied" : (grant || allowedByPolicy ? "approved" : "pending"),
        createdAt: now,
        updatedAt: now,
        approvedAt: grant || allowedByPolicy ? now : undefined,
        approvalGrantId: grant?.id,
        approvalPolicyRuleId: policyRule?.id,
        deniedAt: deniedByPolicy ? now : undefined,
        error: deniedByPolicy ? `Denied by approval policy ${policyRule?.name || policyRule?.id}.` : undefined
      };

      if (grant) {
        grant.lastRequestId = record.id;
        grant.updatedAt = now;
      }

      store.requests.push(record);
      const superseded = record.state === "pending" ? supersedeOlderPendingDuplicates(store, record, now) : [];
      const eventType = deniedByPolicy
        ? "request.denied_by_policy"
        : (allowedByPolicy ? "request.auto_approved_by_policy" : (grant ? "request.auto_approved" : "request.created"));
      const message = requestCreationMessage(record, grant, policyRule, superseded.length);
      store.audit.push(audit(eventType, message, handle, record.id));
      return record;
    });
  }

  async listRequests(stateOrOptions?: RequestState | RequestListOptions): Promise<RequestRecord[]> {
    await this.recoverStaleExecutions();
    const store = await this.read();
    const options = typeof stateOrOptions === "string" ? { state: stateOrOptions } : stateOrOptions || {};
    let requests = sortRequestsForOperators(store.requests);
    if (options.state) {
      requests = requests.filter((request) => request.state === options.state);
    }
    if (options.active) {
      requests = requests.filter((request) => !isTerminalRequestState(request.state));
    }

    const limit = normalizeListLimit(options.limit);
    return limit ? requests.slice(0, limit) : requests;
  }

  async cleanupRequests(options: CleanupRequestsOptions = {}): Promise<CleanupRequestsResult> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const cleaned: RequestRecord[] = [];
      if (options.duplicatePending !== false) {
        cleaned.push(...cleanupDuplicatePendingRequests(store, now));
      }

      const pendingMs = options.pendingOlderThanMs ?? 24 * 60 * 60 * 1000;
      const approvedMs = options.approvedOlderThanMs ?? 60 * 60 * 1000;
      cleaned.push(...cleanupOldRequests(store, now, pendingMs, approvedMs));

      return {
        cleanedCount: cleaned.length,
        requests: cleaned
      };
    });
  }

  async listStoreBackups(): Promise<StoreBackupSummary[]> {
    return listStoreBackups(this.home);
  }

  async getRequest(id: string): Promise<RequestRecord> {
    const store = await this.read();
    const found = store.requests.find((request) => request.id === id);
    if (!found) {
      throw new Error(`Unknown request: ${id}`);
    }

    return found;
  }

  async approveRequest(id: string, options: ApproveRequestOptions = {}): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "pending") {
        throw new Error(`Only pending requests can be approved. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      request.state = "approved";
      request.approvedAt = now;
      request.updatedAt = now;
      const grant = createApprovalGrant(store, request, now, options);
      request.approvalGrantId = grant?.id;
      store.audit.push(audit("request.approved", `Approved execution request ${id}.`, request.handle, id));
    });
  }

  async denyRequest(id: string): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "pending") {
        throw new Error(`Only pending requests can be denied. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      request.state = "denied";
      request.deniedAt = now;
      request.updatedAt = now;
      store.audit.push(audit("request.denied", `Denied execution request ${id}.`, request.handle, id));
    });
  }

  async claimApprovedRequest(id: string): Promise<RequestRecord> {
    return this.mutate((store) => {
      // Reap any abandoned executions first so a previously-stranded request for the same
      // handle does not keep its approval grant alive or confuse the audit trail.
      reapStaleExecutions(store, new Date().toISOString());
      const request = store.requests.find((item) => item.id === id);
      if (!request) {
        throw new Error(`Unknown request: ${id}`);
      }
      if (request.state !== "approved") {
        throw new Error(`Request ${id} is ${request.state}; local approval is required before execution.`);
      }

      request.state = "executing";
      request.updatedAt = new Date().toISOString();
      store.audit.push(audit("request.executing", `Executing approved request ${id}.`, request.handle, id));
      return request;
    });
  }

  /**
   * Mark requests stranded in "executing" (runner crashed/killed before reporting back) as
   * failed so the store self-heals. Returns the requests that were recovered.
   */
  async recoverStaleExecutions(): Promise<RequestRecord[]> {
    const store = await this.read();
    if (!store.requests.some((request) => request.state === "executing")) {
      return [];
    }

    let recovered: RequestRecord[] = [];
    await this.mutate((mutable) => {
      recovered = reapStaleExecutions(mutable, new Date().toISOString());
    });
    return recovered;
  }

  /**
   * Explicit user-driven recovery for requests stuck in "executing". Unlike the time-gated
   * automatic sweep, this fails them immediately — the operator has told us the runner is gone
   * (laptop slept, command was Ctrl-C'd, etc.). Pass a request id to recover just that one;
   * omit it to clear every stranded execution.
   */
  async forceRecoverExecutions(requestId?: string): Promise<RequestRecord[]> {
    return this.mutate((store) => {
      const now = new Date().toISOString();
      const targets = store.requests.filter((request) => {
        if (request.state !== "executing") {
          return false;
        }
        return !requestId || request.id === requestId;
      });

      if (requestId && targets.length === 0) {
        // Tell the user why nothing happened instead of silently returning an empty list.
        const found = store.requests.find((request) => request.id === requestId);
        if (!found) {
          throw new Error(`Unknown request: ${requestId}`);
        }
        throw new Error(`Request ${requestId} is ${found.state}, not executing; nothing to recover.`);
      }

      for (const request of targets) {
        request.state = "failed";
        request.updatedAt = now;
        request.error = "Execution was recovered manually before it finished. Create a new request to retry.";
        store.audit.push(
          audit("request.recovered", `Manually recovered stranded execution request ${request.id}.`, request.handle, request.id)
        );
      }

      return targets;
    });
  }

  async markExecuted(id: string, summary: ExecutionSummary): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "executing" && request.state !== "approved") {
        throw new Error(`Only approved or executing requests can be marked executed. Current state: ${request.state}`);
      }

      const now = new Date().toISOString();
      request.state = "executed";
      request.executedAt = now;
      request.updatedAt = now;
      request.resultSummary = summary;
      request.error = undefined;
      store.audit.push(audit("request.executed", `Executed request ${id}.`, request.handle, id));
    });
  }

  async markFailed(id: string, errorMessage: string): Promise<RequestRecord> {
    return this.updateRequest(id, (request, store) => {
      if (request.state !== "executing" && request.state !== "approved") {
        throw new Error(`Only approved or executing requests can be marked failed. Current state: ${request.state}`);
      }

      request.state = "failed";
      request.updatedAt = new Date().toISOString();
      request.error = errorMessage;
      store.audit.push(audit("request.failed", `Request ${id} failed: ${errorMessage}`, request.handle, id));
    });
  }

  async auditLog(): Promise<AuditEvent[]> {
    const store = await this.read();
    return store.audit;
  }

  private async updateRequest(
    id: string,
    updater: (request: RequestRecord, store: StoreFile) => void
  ): Promise<RequestRecord> {
    return this.mutate((store) => {
      const found = store.requests.find((request) => request.id === id);
      if (!found) {
        throw new Error(`Unknown request: ${id}`);
      }

      updater(found, store);
      return found;
    });
  }

  private async exists(): Promise<boolean> {
    try {
      await access(this.storePath, constants.F_OK);
      return true;
    } catch {
      return false;
    }
  }

  private async read(): Promise<StoreFile> {
    const exists = await this.exists();
    if (!exists) {
      await this.init();
    }

    return this.readUnlocked();
  }

  private async readUnlocked(): Promise<StoreFile> {
    const raw = await readFile(this.storePath, "utf8");
    const parsed = JSON.parse(raw) as Partial<StoreFile>;
    if (parsed.version !== 1 || !Array.isArray(parsed.secrets) || !Array.isArray(parsed.requests)) {
      throw new Error(`Invalid s-gw store at ${this.storePath}`);
    }

    return normalizeStoreFile(parsed);
  }

  private async writeUnlocked(store: StoreFile): Promise<void> {
    await ensureSgwHome(this.home);
    await backupCurrentStore(this.home, this.storePath);
    const tmpPath = path.join(this.home, `.store.${process.pid}.${Date.now()}.tmp`);
    await writeFile(tmpPath, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
    await rename(tmpPath, this.storePath);
    await chmod(this.storePath, 0o600);
  }

  private async mutate<T>(updater: (store: StoreFile) => T | Promise<T>): Promise<T> {
    await ensureSgwHome(this.home);
    return this.withStoreLock(async () => {
      if (!(await this.exists())) {
        await this.writeUnlocked(emptyStore());
      }

      const store = await this.readUnlocked();
      const result = await updater(store);
      await this.writeUnlocked(store);
      return result;
    });
  }

  private async withStoreLock<T>(body: () => Promise<T>): Promise<T> {
    const lockPath = `${this.storePath}.lock`;
    const started = Date.now();
    let lockHandle: Awaited<ReturnType<typeof open>> | undefined;

    while (!lockHandle) {
      try {
        lockHandle = await open(lockPath, "wx", 0o600);
      } catch (error) {
        if (!isNodeError(error) || error.code !== "EEXIST") {
          throw error;
        }

        await removeStaleLock(lockPath);
        if (Date.now() - started > lockTimeoutMs) {
          throw new Error(`Timed out waiting for s-gw store lock at ${lockPath}.`);
        }
        await sleep(25);
      }
    }

    try {
      return await body();
    } finally {
      await lockHandle.close().catch(() => undefined);
      await unlink(lockPath).catch(() => undefined);
    }
  }
}

async function backupCurrentStore(home: string, storePath: string): Promise<void> {
  let current = "";
  try {
    current = await readFile(storePath, "utf8");
  } catch {
    return;
  }

  if (!current.trim()) {
    return;
  }

  const backupDir = path.join(home, "backups");
  await mkdir(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[-:.]/g, "").slice(0, 15);
  const backupPath = path.join(backupDir, `store-${stamp}-${process.pid}-${Date.now()}.json`);
  await writeFile(backupPath, current, { mode: 0o600 });
  await pruneStoreBackups(backupDir);
}

async function listStoreBackups(home: string): Promise<StoreBackupSummary[]> {
  const backupDir = path.join(home, "backups");
  const entries = await readdir(backupDir).catch(() => []);
  const backups: StoreBackupSummary[] = [];
  for (const entry of entries) {
    if (!/^store-\d{8}T\d{6}-\d+-\d+\.json$/.test(entry)) {
      continue;
    }

    const backupPath = path.join(backupDir, entry);
    const info = await stat(backupPath).catch(() => undefined);
    if (!info?.isFile()) {
      continue;
    }

    backups.push({
      path: backupPath,
      bytes: info.size,
      modifiedAt: info.mtime.toISOString()
    });
  }

  return backups.sort((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
}

async function pruneStoreBackups(backupDir: string): Promise<void> {
  const backups = await listStoreBackups(path.dirname(backupDir));
  for (const backup of backups.slice(maxStoreBackups)) {
    await rm(backup.path, { force: true }).catch(() => undefined);
  }
}

function normalizeStoreFile(parsed: Partial<StoreFile>): StoreFile {
  return {
    version: 1,
    secrets: (parsed.secrets || []).map((secret) => normalizeSecretRecord(secret)),
    requests: parsed.requests || [],
    audit: parsed.audit || [],
    approvalSettings: normalizeApprovalSettings(parsed.approvalSettings),
    approvalGrants: Array.isArray(parsed.approvalGrants)
      ? parsed.approvalGrants.filter(isValidApprovalGrant)
      : [],
    approvalPolicyRules: Array.isArray(parsed.approvalPolicyRules)
      ? sortApprovalPolicyRules(parsed.approvalPolicyRules.map((rule) => normalizeApprovalPolicyRule(rule)).filter(isValidApprovalPolicyRule))
      : []
  };
}

function normalizeSecretRecord(secret: SecretRecord): SecretRecord {
  if (!secret.cache || isValidSecretCache(secret.cache)) {
    return secret;
  }

  const clone = { ...secret };
  delete clone.cache;
  return clone;
}

function keychainRefPayload(ref: MacKeychainItemRef): Pick<MacKeychainItemRef, "service" | "account"> {
  return {
    service: ref.service,
    account: ref.account
  };
}

function keychainRefFromRecord(record: SecretRecord): MacKeychainItemRef {
  try {
    const decoded = JSON.parse(decryptSecret(record.encrypted)) as Partial<MacKeychainItemRef>;
    if (typeof decoded.service === "string" && typeof decoded.account === "string") {
      return {
        service: decoded.service,
        account: decoded.account,
        label: keychainSecretLabel(record.name)
      };
    }
  } catch {
    // Older experimental records may only have used the handle as account.
  }

  return {
    service: defaultSecretKeychainService(),
    account: record.handle,
    label: keychainSecretLabel(record.name)
  };
}

function keychainSecretLabel(name: string): string {
  const trimmed = name.trim();
  return `s-gw secret: ${trimmed || "credential"}`.slice(0, 128);
}

function credentialStoreProvider(): string {
  return process.platform === "win32" ? "windows-credential-manager" : "macos-keychain";
}

function normalizeApprovalSettings(input?: Partial<ApprovalSettings>): ApprovalSettings {
  const mode = isApprovalMode(input?.mode) ? input.mode : defaultApprovalSettings.mode;
  return {
    mode,
    durationMs: clampApprovalDuration(input?.durationMs)
  };
}

function isApprovalMode(value: unknown): value is ApprovalMode {
  return value === "per-transaction" || value === "timed-session" || value === "login-session" || value === "always";
}

function isApprovalAgentScope(value: unknown): value is ApprovalAgentScope {
  return value === "same-agent" || value === "any-agent";
}

function clampApprovalDuration(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return defaultApprovalSettings.durationMs;
  }

  return Math.min(Math.max(Math.floor(value), 60_000), maxApprovalDurationMs);
}

function isValidApprovalGrant(grant: ApprovalGrant): boolean {
  return (
    Boolean(grant) &&
    typeof grant.id === "string" &&
    typeof grant.handle === "string" &&
    typeof grant.actionKey === "string" &&
    (grant.mode === "timed-session" || grant.mode === "login-session" || grant.mode === "always") &&
    typeof grant.loginSessionId === "string"
  );
}

function isValidSecretCache(cache: SecretValueCache): boolean {
  return (
    Boolean(cache) &&
    cache.backend === "onepassword" &&
    typeof cache.fingerprint === "string" &&
    typeof cache.approvalGrantId === "string" &&
    typeof cache.createdAt === "string" &&
    typeof cache.updatedAt === "string" &&
    isEncryptedBox(cache.encrypted)
  );
}

function isEncryptedBox(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }

  const box = value as Record<string, unknown>;
  return (
    box.alg === "aes-256-gcm" &&
    box.kdf === "scrypt" &&
    typeof box.salt === "string" &&
    typeof box.iv === "string" &&
    typeof box.authTag === "string" &&
    typeof box.ciphertext === "string"
  );
}

function isTerminalRequestState(state: RequestState): boolean {
  return state === "denied" || state === "executed" || state === "failed";
}

function cachedOnePasswordValue(record: SecretRecord, request?: RequestRecord): string | undefined {
  const cache = record.cache;
  if (record.backend !== "onepassword" || !cache || !request?.approvalGrantId) {
    return undefined;
  }

  const now = new Date().toISOString();
  if (!isValidSecretCache(cache) || cache.approvalGrantId !== request.approvalGrantId) {
    return undefined;
  }

  if (cache.expiresAt && cache.expiresAt <= now) {
    return undefined;
  }

  if (cache.loginSessionId && cache.loginSessionId !== currentLoginSessionId()) {
    return undefined;
  }

  return decryptSecret(cache.encrypted);
}

function grantAllowsCache(grant: ApprovalGrant, nowIso: string): boolean {
  if (!isValidApprovalGrant(grant)) {
    return false;
  }

  if (grant.expiresAt && grant.expiresAt <= nowIso) {
    return false;
  }

  return grant.mode === "always" || grant.loginSessionId === currentLoginSessionId();
}

function clearOnePasswordCaches(store: StoreFile, grantIds?: Set<string>): void {
  for (const secret of store.secrets) {
    if (!secret.cache) {
      continue;
    }

    if (!grantIds || grantIds.has(secret.cache.approvalGrantId)) {
      delete secret.cache;
    }
  }
}

function activeApprovalGrant(
  store: StoreFile,
  handle: string,
  action: CommandAction,
  agentName: string,
  nowIso: string
): ApprovalGrant | undefined {
  const settings = normalizeApprovalSettings(store.approvalSettings);
  store.approvalSettings = settings;

  const actionKey = approvalActionKey(handle, action);
  const loginSessionId = currentLoginSessionId();
  return store.approvalGrants.find((grant) => {
    if (grant.handle !== handle || grant.actionKey !== actionKey) {
      return false;
    }
    if (grant.mode !== "always" && grant.loginSessionId !== loginSessionId) {
      return false;
    }
    if ((grant.agentScope || "same-agent") === "same-agent" && grant.agentName !== agentName) {
      return false;
    }
    return !grant.expiresAt || grant.expiresAt > nowIso;
  });
}

function createApprovalGrant(
  store: StoreFile,
  request: RequestRecord,
  nowIso: string,
  options: ApproveRequestOptions = {}
): ApprovalGrant | undefined {
  const settings = normalizeApprovalSettings(store.approvalSettings);
  store.approvalSettings = settings;
  const mode = options.mode && isApprovalMode(options.mode) ? options.mode : settings.mode;
  if (mode === "per-transaction") {
    return undefined;
  }

  pruneExpiredApprovalGrants(store, nowIso);

  const loginSessionId = currentLoginSessionId();
  const actionKey = approvalActionKey(request.handle, request.action);
  const durationMs = clampApprovalDuration(options.durationMs ?? settings.durationMs);
  const expiresAt = mode === "timed-session"
    ? new Date(Date.parse(nowIso) + durationMs).toISOString()
    : undefined;
  const agentScope = isApprovalAgentScope(options.agentScope) ? options.agentScope : "same-agent";
  const agentName = request.agentName || requestAgentName(request.reason);
  const existing = store.approvalGrants.find((grant) => {
    return (
      grant.mode === mode &&
      grant.handle === request.handle &&
      grant.actionKey === actionKey &&
      grant.loginSessionId === loginSessionId &&
      (grant.agentScope || "same-agent") === agentScope &&
      (agentScope === "any-agent" || grant.agentName === agentName)
    );
  });

  if (existing) {
    existing.updatedAt = nowIso;
    existing.expiresAt = expiresAt;
    existing.lastRequestId = request.id;
    store.audit.push(audit("approval.grant.updated", `Updated approval grant ${existing.id}.`, request.handle, request.id));
    return existing;
  }

  const grant: ApprovalGrant = {
    id: shortId("grant"),
    handle: request.handle,
    actionKey,
    mode,
    agentScope,
    agentName: agentScope === "same-agent" ? agentName : undefined,
    loginSessionId,
    createdAt: nowIso,
    updatedAt: nowIso,
    expiresAt,
    lastRequestId: request.id
  };

  store.approvalGrants.push(grant);
  store.audit.push(audit("approval.grant.created", `Created approval grant ${grant.id}.`, request.handle, request.id));
  return grant;
}

function requestReferencesHandle(request: RequestRecord, handle: string): boolean {
  return request.handle === handle || (request.action.env || []).some((binding) => binding.handle === handle);
}

function requestDuplicateKey(request: RequestRecord): string {
  return JSON.stringify({
    handle: request.handle,
    actionKey: approvalActionKey(request.handle, request.action),
    agentName: request.agentName || requestAgentName(request.reason)
  });
}

function supersedeOlderPendingDuplicates(store: StoreFile, latest: RequestRecord, nowIso: string): RequestRecord[] {
  const latestKey = requestDuplicateKey(latest);
  const superseded: RequestRecord[] = [];
  for (const request of store.requests) {
    if (request.id === latest.id || request.state !== "pending") {
      continue;
    }
    if (requestDuplicateKey(request) !== latestKey) {
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = `Superseded by newer duplicate pending request ${latest.id}.`;
    superseded.push(request);
    store.audit.push(
      audit("request.superseded", `Request ${request.id} was superseded by newer duplicate ${latest.id}.`, request.handle, request.id)
    );
  }

  return superseded;
}

function cleanupDuplicatePendingRequests(store: StoreFile, nowIso: string): RequestRecord[] {
  const newestByKey = new Map<string, RequestRecord>();
  const pending = store.requests
    .filter((request) => request.state === "pending")
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));

  const cleaned: RequestRecord[] = [];
  for (const request of pending) {
    const key = requestDuplicateKey(request);
    const newest = newestByKey.get(key);
    if (!newest) {
      newestByKey.set(key, request);
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = `Superseded by newer duplicate pending request ${newest.id}.`;
    cleaned.push(request);
    store.audit.push(
      audit("request.superseded", `Cleaned duplicate pending request ${request.id}; newest is ${newest.id}.`, request.handle, request.id)
    );
  }

  return cleaned;
}

function cleanupOldRequests(
  store: StoreFile,
  nowIso: string,
  pendingOlderThanMs: number,
  approvedOlderThanMs: number
): RequestRecord[] {
  const now = Date.parse(nowIso);
  const cleaned: RequestRecord[] = [];
  for (const request of store.requests) {
    if (request.state !== "pending" && request.state !== "approved") {
      continue;
    }

    const timestamp = request.state === "approved" && request.approvedAt
      ? Date.parse(request.approvedAt)
      : Date.parse(request.createdAt);
    if (!Number.isFinite(timestamp)) {
      continue;
    }

    const ttl = request.state === "approved" ? approvedOlderThanMs : pendingOlderThanMs;
    if (!Number.isFinite(ttl) || ttl <= 0 || now - timestamp < ttl) {
      continue;
    }

    const oldState = request.state;
    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = oldState === "approved"
      ? "Approved request expired before execution. Create a fresh request to retry."
      : "Pending request expired before approval. Create a fresh request to retry.";
    cleaned.push(request);
    store.audit.push(audit("request.expired", `Cleaned stale ${oldState} request ${request.id}.`, request.handle, request.id));
  }

  return cleaned;
}

function sortRequestsForOperators(requests: RequestRecord[]): RequestRecord[] {
  const rank: Record<RequestState, number> = {
    pending: 0,
    approved: 1,
    executing: 2,
    failed: 3,
    denied: 4,
    executed: 5
  };

  return [...requests].sort((a, b) => {
    const rankOrder = rank[a.state] - rank[b.state];
    return rankOrder || b.updatedAt.localeCompare(a.updatedAt);
  });
}

function normalizeListLimit(value?: number): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isFinite(value) || value <= 0) {
    return undefined;
  }

  return Math.min(Math.floor(value), 1000);
}

function reapStaleExecutions(store: StoreFile, nowIso: string): RequestRecord[] {
  const cutoff = Date.parse(nowIso) - staleExecutionMs;
  const recovered: RequestRecord[] = [];

  for (const request of store.requests) {
    if (request.state !== "executing") {
      continue;
    }

    const claimedAt = Date.parse(request.updatedAt);
    // Leave a NaN timestamp alone rather than failing a request we cannot reason about.
    if (Number.isFinite(claimedAt) && claimedAt > cutoff) {
      continue;
    }

    request.state = "failed";
    request.updatedAt = nowIso;
    request.error = "Execution was interrupted before it finished. Create a new request to retry.";
    store.audit.push(
      audit("request.recovered", `Recovered stranded execution request ${request.id}.`, request.handle, request.id)
    );
    recovered.push(request);
  }

  return recovered;
}

function pruneExpiredApprovalGrants(store: StoreFile, nowIso: string): void {
  migrateApprovalGrantActionKeys(store);

  const active = (store.approvalGrants || []).filter((grant) => {
    return isValidApprovalGrant(grant) && (!grant.expiresAt || grant.expiresAt > nowIso);
  });
  const byIdentity = new Map<string, ApprovalGrant>();
  for (const grant of active) {
    const key = approvalGrantIdentityKey(grant);
    const existing = byIdentity.get(key);
    if (!existing || approvalGrantIsNewer(grant, existing)) {
      byIdentity.set(key, grant);
    }
  }
  store.approvalGrants = [...byIdentity.values()];
  pruneOnePasswordCaches(store, nowIso);
}

function pruneOnePasswordCaches(store: StoreFile, nowIso: string): void {
  const liveGrantIds = new Set(
    store.approvalGrants
      .filter((grant) => grantAllowsCache(grant, nowIso))
      .map((grant) => grant.id)
  );

  for (const secret of store.secrets) {
    const cache = secret.cache;
    if (!cache) {
      continue;
    }

    if (
      !isValidSecretCache(cache) ||
      !liveGrantIds.has(cache.approvalGrantId) ||
      (cache.expiresAt && cache.expiresAt <= nowIso) ||
      (cache.loginSessionId && cache.loginSessionId !== currentLoginSessionId())
    ) {
      delete secret.cache;
    }
  }
}

function migrateApprovalGrantActionKeys(store: StoreFile): void {
  const requestsById = new Map(store.requests.map((request) => [request.id, request]));
  for (const grant of store.approvalGrants || []) {
    if (!isValidApprovalGrant(grant) || !grant.lastRequestId) {
      continue;
    }

    const request = requestsById.get(grant.lastRequestId);
    if (!request || request.handle !== grant.handle) {
      continue;
    }

    grant.actionKey = approvalActionKey(request.handle, request.action);
  }
}

function approvalGrantIdentityKey(grant: ApprovalGrant): string {
  return JSON.stringify({
    handle: grant.handle,
    actionKey: grant.actionKey,
    mode: grant.mode,
    agentScope: grant.agentScope || "same-agent",
    agentName: grant.agentScope === "any-agent" ? "" : grant.agentName || "",
    loginSessionId: grant.mode === "always" ? "" : grant.loginSessionId
  });
}

function approvalGrantIsNewer(candidate: ApprovalGrant, current: ApprovalGrant): boolean {
  const candidateExpires = candidate.expiresAt ? Date.parse(candidate.expiresAt) : Number.POSITIVE_INFINITY;
  const currentExpires = current.expiresAt ? Date.parse(current.expiresAt) : Number.POSITIVE_INFINITY;
  if (candidateExpires !== currentExpires) {
    return candidateExpires > currentExpires;
  }
  return candidate.updatedAt > current.updatedAt;
}

function approvalActionKey(handle: string, action: CommandAction): string {
  const normalized = normalizeAction(action);
  const payload = {
    handle,
    kind: normalized.kind,
    command: normalizeCommandGrant(normalized.command),
    injectEnv: normalized.injectEnv,
    env: normalized.env || [],
    workingDir: normalized.workingDir ? path.resolve(normalized.workingDir) : "",
    ssh: normalized.kind === "ssh_session" && normalized.ssh ? sshSessionIdentity(normalized) : ""
  };

  return createHash("sha256").update(JSON.stringify(payload)).digest("base64url");
}

function matchingApprovalPolicyRule(
  store: StoreFile,
  secret: SecretRecord,
  action: CommandAction,
  agentName: string,
  nowIso: string
): ApprovalPolicyRule | undefined {
  const rules = sortApprovalPolicyRules(store.approvalPolicyRules || []);
  for (const rule of rules) {
    if (!rule.enabled || !isValidApprovalPolicyRule(rule)) {
      continue;
    }
    if (rule.expiresAt && rule.expiresAt <= nowIso) {
      continue;
    }
    if (approvalPolicyMatches(rule, secret, action, agentName)) {
      return rule;
    }
  }

  return undefined;
}

function approvalPolicyMatches(
  rule: ApprovalPolicyRule,
  secret: SecretRecord,
  action: CommandAction,
  agentName: string
): boolean {
  const conditions = normalizeApprovalPolicyConditions(rule.conditions);
  if (conditions.handles?.length && !conditions.handles.includes(secret.handle)) {
    return false;
  }
  if (conditions.secretTypes?.length && !conditions.secretTypes.includes(secret.type)) {
    return false;
  }
  if (conditions.providers?.length && !conditions.providers.includes((secret.provider || "").toLowerCase())) {
    return false;
  }
  if (conditions.minSeverity && severityRank(secret.severity || "low") < severityRank(conditions.minSeverity)) {
    return false;
  }

  if (conditions.agents?.length && !conditions.agents.includes(agentName.toLowerCase())) {
    return false;
  }
  if (conditions.actionKinds?.length && !conditions.actionKinds.includes(action.kind)) {
    return false;
  }
  if (conditions.commands?.length) {
    const requested = normalizeCommandGrant(action.command);
    if (!conditions.commands.includes(requested)) {
      return false;
    }
  }
  if (conditions.injectEnvs?.length) {
    const names = new Set([action.injectEnv, ...(action.env || []).map((binding) => binding.injectEnv)]);
    if (![...names].some((name) => conditions.injectEnvs?.includes(name))) {
      return false;
    }
  }
  if (conditions.workingDirs?.length) {
    const cwd = action.workingDir ? path.resolve(action.workingDir) : "";
    if (!conditions.workingDirs.includes(cwd)) {
      return false;
    }
  }
  if (conditions.sshTargets?.length) {
    const target = action.ssh?.target ? normalizeSshTarget(action.ssh.target) : "";
    if (!conditions.sshTargets.includes(target)) {
      return false;
    }
  }
  if (conditions.sshPorts?.length) {
    const port = action.ssh?.port ? normalizeSshPort(action.ssh.port) : undefined;
    if (!port || !conditions.sshPorts.includes(port)) {
      return false;
    }
  }

  return true;
}

function requestCreationMessage(
  record: RequestRecord,
  grant: ApprovalGrant | undefined,
  policyRule: ApprovalPolicyRule | undefined,
  supersededCount: number
): string {
  if (policyRule?.decision === "deny") {
    return `Denied execution request ${record.id} by approval policy ${policyRule.name}.`;
  }
  if (policyRule?.decision === "allow") {
    return `Created execution request ${record.id} using approval policy ${policyRule.name}.`;
  }
  if (grant) {
    return `Created execution request ${record.id} using approval grant ${grant.id}.`;
  }
  return `Created execution request ${record.id}${supersededCount ? ` and superseded ${supersededCount} older duplicate(s)` : ""}.`;
}

function normalizeApprovalPolicyRule(rule: Partial<ApprovalPolicyRule>, nowIso = new Date().toISOString()): ApprovalPolicyRule {
  const decision = isApprovalPolicyDecision(rule.decision) ? rule.decision : "ask";
  return {
    id: typeof rule.id === "string" && rule.id.trim() ? rule.id.trim() : shortId("policy"),
    name: typeof rule.name === "string" && rule.name.trim() ? rule.name.trim().slice(0, 120) : defaultPolicyRuleName(decision),
    enabled: rule.enabled !== false,
    priority: normalizePolicyPriority(rule.priority),
    decision,
    conditions: normalizeApprovalPolicyConditions(rule.conditions),
    expiresAt: normalizePolicyExpiresAt(rule.expiresAt),
    createdAt: typeof rule.createdAt === "string" && rule.createdAt ? rule.createdAt : nowIso,
    updatedAt: typeof rule.updatedAt === "string" && rule.updatedAt ? rule.updatedAt : nowIso
  };
}

function normalizeApprovalPolicyConditions(input?: Partial<ApprovalPolicyConditions>): ApprovalPolicyConditions {
  return {
    handles: optionalStrings(input?.handles),
    secretTypes: optionalSecretTypes(input?.secretTypes),
    providers: optionalStrings(input?.providers).map((provider) => provider.toLowerCase()),
    minSeverity: isSecretSeverity(input?.minSeverity) ? input.minSeverity : undefined,
    agents: optionalStrings(input?.agents).map((agent) => agent.toLowerCase()),
    actionKinds: optionalActionKinds(input?.actionKinds),
    commands: optionalStrings(input?.commands).map((command) => safeNormalizeCommandGrant(command)).filter(Boolean) as string[],
    injectEnvs: optionalStrings(input?.injectEnvs),
    workingDirs: optionalStrings(input?.workingDirs).map((dir) => path.resolve(dir)),
    sshTargets: optionalStrings(input?.sshTargets).map((target) => normalizeSshTarget(target)),
    sshPorts: optionalPorts(input?.sshPorts)
  };
}

function safeNormalizeCommandGrant(command: string): string | undefined {
  try {
    return normalizeCommandGrant(command);
  } catch {
    return undefined;
  }
}

function isValidApprovalPolicyRule(rule: ApprovalPolicyRule): boolean {
  return (
    Boolean(rule) &&
    typeof rule.id === "string" &&
    typeof rule.name === "string" &&
    typeof rule.enabled === "boolean" &&
    typeof rule.priority === "number" &&
    isApprovalPolicyDecision(rule.decision) &&
    Boolean(rule.conditions) &&
    typeof rule.createdAt === "string" &&
    typeof rule.updatedAt === "string"
  );
}

function isApprovalPolicyDecision(value: unknown): value is ApprovalPolicyDecision {
  return value === "ask" || value === "allow" || value === "deny";
}

function sortApprovalPolicyRules(rules: ApprovalPolicyRule[]): ApprovalPolicyRule[] {
  return [...rules].sort((a, b) => {
    const priority = a.priority - b.priority;
    return priority || b.updatedAt.localeCompare(a.updatedAt);
  });
}

function nextPolicyPriority(store: StoreFile): number {
  const priorities = (store.approvalPolicyRules || []).map((rule) => rule.priority).filter(Number.isFinite);
  return priorities.length ? Math.max(...priorities) + 10 : 100;
}

function defaultPolicyRuleName(decision: ApprovalPolicyDecision): string {
  switch (decision) {
  case "allow":
    return "Allow matching agent access";
  case "deny":
    return "Deny matching agent access";
  case "ask":
    return "Require approval for matching access";
  }
}

function policyExpiresAt(input: AddApprovalPolicyRuleInput, nowIso: string): string | undefined {
  const explicit = normalizePolicyExpiresAt(input.expiresAt);
  if (explicit) {
    return explicit;
  }
  if (input.durationMs === undefined) {
    return undefined;
  }
  return new Date(Date.parse(nowIso) + clampApprovalDuration(input.durationMs)).toISOString();
}

function normalizePolicyExpiresAt(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.trim()) {
    return undefined;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : undefined;
}

function normalizePolicyPriority(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return 100;
  }
  return Math.max(0, Math.min(10_000, Math.floor(value)));
}

function optionalStrings(values: unknown): string[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return uniqueStrings(values.filter((value): value is string => typeof value === "string"));
}

function optionalSecretTypes(values: unknown): SecretType[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return uniqueStrings(values.filter((value): value is SecretType => isSecretType(value))) as SecretType[];
}

function optionalActionKinds(values: unknown): ApprovalPolicyActionKind[] {
  if (!Array.isArray(values)) {
    return [];
  }
  return uniqueStrings(values.filter((value): value is ApprovalPolicyActionKind => {
    return value === "env_command" || value === "ssh_session";
  })) as ApprovalPolicyActionKind[];
}

function optionalPorts(values: unknown): number[] {
  if (!Array.isArray(values)) {
    return [];
  }
  const out: number[] = [];
  for (const value of values) {
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535 || out.includes(port)) {
      continue;
    }
    out.push(port);
  }
  return out;
}

function isSecretType(value: unknown): value is SecretType {
  return (
    value === "api-token" ||
    value === "ssh-key" ||
    value === "private-key" ||
    value === "password" ||
    value === "credential" ||
    value === "access-key" ||
    value === "unknown"
  );
}

function isSecretSeverity(value: unknown): value is SecretSeverity {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

function severityRank(value: SecretSeverity): number {
  switch (value) {
  case "low":
    return 0;
  case "medium":
    return 1;
  case "high":
    return 2;
  case "critical":
    return 3;
  }
}

function currentLoginSessionId(): string {
  const override = process.env.SGW_LOGIN_SESSION_ID?.trim();
  if (override) {
    return override.slice(0, 160);
  }

  const user = os.userInfo();
  const parts = [
    process.platform,
    String(user.uid),
    user.username,
    process.env.TMPDIR || "",
    process.env.XDG_RUNTIME_DIR || "",
    process.env.SSH_AUTH_SOCK || ""
  ];
  return createHash("sha256").update(parts.join("\0")).digest("base64url").slice(0, 32);
}

function normalizePolicy(input?: Partial<SecretPolicy>, existing?: SecretPolicy): SecretPolicy {
  const allowedCommands = input?.allowedCommands ?? existing?.allowedCommands ?? [];
  const injectEnv = input?.injectEnv ?? existing?.injectEnv;
  if (injectEnv && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(injectEnv)) {
    throw new Error(`Invalid environment variable name: ${injectEnv}`);
  }
  return {
    injectEnv,
    allowedCommands: uniqueStrings(allowedCommands),
    maxOutputBytes: input?.maxOutputBytes ?? existing?.maxOutputBytes ?? 16_384
  };
}

function normalizeAction(action: CommandAction): CommandAction {
  const kind = action.kind === "ssh_session" ? "ssh_session" : "env_command";
  if (kind === "ssh_session") {
    return {
      kind,
      command: SGW_SSH_SESSION_COMMAND,
      args: Array.isArray(action.args) ? action.args : [],
      injectEnv: action.injectEnv || "SGW_SSH_CREDENTIAL",
      env: [],
      workingDir: action.workingDir,
      timeoutMs: clampTimeout(action.timeoutMs),
      ssh: {
        target: normalizeSshTarget(action.ssh?.target || ""),
        port: normalizeSshPort(action.ssh?.port)
      }
    };
  }

  return {
    kind,
    command: action.command,
    args: Array.isArray(action.args) ? action.args : [],
    injectEnv: action.injectEnv,
    env: normalizeEnvBindings(action.env),
    workingDir: action.workingDir,
    timeoutMs: clampTimeout(action.timeoutMs)
  };
}

function normalizeEnvBindings(bindings?: CommandEnvBinding[]): CommandEnvBinding[] {
  if (!Array.isArray(bindings) || bindings.length === 0) {
    return [];
  }

  const seenEnv = new Set<string>();
  const normalized: CommandEnvBinding[] = [];
  for (const binding of bindings) {
    const handle = binding?.handle?.trim();
    const injectEnv = binding?.injectEnv?.trim();
    if (!handle) {
      throw new Error("Additional env bindings require a handle.");
    }
    if (!injectEnv || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(injectEnv)) {
      throw new Error(`Invalid environment variable name: ${injectEnv || "(empty)"}`);
    }
    if (handle.includes("\0") || injectEnv.includes("\0")) {
      throw new Error("Additional env bindings cannot contain null bytes.");
    }
    if (seenEnv.has(injectEnv)) {
      throw new Error(`Environment variable ${injectEnv} is bound more than once.`);
    }

    seenEnv.add(injectEnv);
    normalized.push({ handle, injectEnv });
  }

  normalized.sort((a, b) => {
    const envOrder = a.injectEnv.localeCompare(b.injectEnv);
    return envOrder || a.handle.localeCompare(b.handle);
  });
  return normalized;
}

function assertBoundHandlesAllowed(store: StoreFile, primaryHandle: string, action: CommandAction): void {
  const seenEnv = new Set([action.injectEnv]);
  for (const binding of action.env || []) {
    if (binding.handle === primaryHandle) {
      throw new Error(`Additional env binding ${binding.injectEnv} repeats the primary handle ${primaryHandle}.`);
    }
    if (seenEnv.has(binding.injectEnv)) {
      throw new Error(`Environment variable ${binding.injectEnv} is bound more than once.`);
    }

    const secret = store.secrets.find((item) => item.handle === binding.handle);
    if (!secret) {
      throw new Error(`Unknown secret handle: ${binding.handle}`);
    }

    assertActionAllowed(secret, {
      ...action,
      injectEnv: binding.injectEnv,
      env: []
    });
    seenEnv.add(binding.injectEnv);
  }
}

export function assertActionAllowed(secret: SecretRecord, action: CommandAction): void {
  if (action.kind !== "env_command" && action.kind !== "ssh_session") {
    throw new Error("Unsupported request action kind.");
  }

  if (!action.command || action.command.includes("\0")) {
    throw new Error("Command is required.");
  }

  for (const arg of action.args) {
    if (arg.includes("\0")) {
      throw new Error("Command arguments cannot contain null bytes.");
    }
  }

  if (!action.injectEnv) {
    throw new Error("injectEnv is required so the secret has a narrow local binding.");
  }

  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(action.injectEnv)) {
    throw new Error(`Invalid environment variable name: ${action.injectEnv}`);
  }

  if (secret.policy.injectEnv && action.injectEnv !== secret.policy.injectEnv) {
    throw new Error(`Handle ${secret.handle} can only be injected as ${secret.policy.injectEnv}.`);
  }

  const allowed = secret.policy.allowedCommands.map((cmd) => normalizeCommandGrant(cmd));
  if (action.kind === "ssh_session") {
    normalizeSshTarget(action.ssh?.target || "");
    normalizeSshPort(action.ssh?.port);
    if (allowed.length === 0 || !allowed.some(commandAllowsSshSession)) {
      throw new Error(`Handle ${secret.handle} is not allowed for s-gw-owned SSH sessions. Add ${SGW_SSH_SESSION_COMMAND} to the handle policy.`);
    }
    return;
  }

  const requestedCommand = normalizeCommandGrant(action.command);
  if (allowed.length === 0 || !allowed.includes(requestedCommand)) {
    throw new Error(`Command '${action.command}' is not allowed for handle ${secret.handle}.`);
  }
}

function commandAllowsSshSession(command: string): boolean {
  return command === SGW_SSH_SESSION_COMMAND || path.basename(command) === "ssh";
}

function normalizeCommandGrant(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) {
    throw new Error("Command grant cannot be empty.");
  }

  if (trimmed.includes("\0")) {
    throw new Error("Command grant cannot contain null bytes.");
  }

  if (path.isAbsolute(trimmed)) {
    return path.normalize(trimmed);
  }

  if (trimmed.includes("/") || trimmed.includes("\\")) {
    throw new Error(`Relative command paths are not allowed: ${trimmed}`);
  }

  return trimmed;
}

function summarizeSecret(secret: SecretRecord): HandleSummary {
  return {
    handle: secret.handle,
    name: secret.name,
    type: secret.type,
    backend: secret.backend || "local",
    provider: secret.provider,
    ruleId: secret.ruleId,
    severity: secret.severity,
    confidence: secret.confidence,
    createdAt: secret.createdAt,
    updatedAt: secret.updatedAt,
    source: secret.source,
    fingerprint: secret.fingerprint,
    policy: secret.policy
  };
}

function makeHandle(type: SecretType): string {
  return `s-gw:${type}:${shortId()}`;
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }

    seen.add(trimmed);
    out.push(trimmed);
  }

  return out;
}

function clampTimeout(timeoutMs: number): number {
  if (!Number.isFinite(timeoutMs)) {
    return 30_000;
  }

  if (timeoutMs === 0) {
    return 0;
  }

  if (timeoutMs < 0) {
    return 30_000;
  }

  return Math.min(Math.floor(timeoutMs), 24 * 60 * 60 * 1000);
}

function audit(type: string, message: string, handle?: string, requestId?: string): AuditEvent {
  return {
    id: shortId("audit"),
    ts: new Date().toISOString(),
    type,
    handle,
    requestId,
    message
  };
}

async function removeStaleLock(lockPath: string): Promise<void> {
  try {
    const info = await stat(lockPath);
    if (Date.now() - info.mtimeMs > staleLockMs) {
      await unlink(lockPath).catch(() => undefined);
    }
  } catch {
    // Another process may have released the lock between our open and stat.
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
