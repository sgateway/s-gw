import type { CommandAction, ModelRelaySpec } from "./types.js";

export const SGW_MODEL_RELAY_COMMAND = "s-gw:model-relay";

export interface ModelRelayGrant extends Omit<ModelRelaySpec, "routes" | "allowedBetaValues"> {
  handle: string;
  routes?: readonly string[];
  allowedBetaValues?: readonly string[];
}

export const modelRelayRoutes = {
  anthropic: ["POST /v1/messages", "POST /v1/messages/count_tokens", "GET /v1/models"],
  openai: ["POST /v1/responses"]
} as const;

const maxGrantMs = 30 * 60_000;

export function normalizeModelRelayGrant(input: ModelRelayGrant): ModelRelaySpec & { handle: string } {
  if (!input || typeof input.handle !== "string" || !/^s-gw:api-token:[A-Za-z0-9_-]{1,128}$/.test(input.handle)) {
    throw new Error("A model relay grant needs an API-token handle.");
  }
  return { ...normalizeModelRelaySpec(input), handle: input.handle };
}

function normalizeModelRelaySpec(input: Omit<ModelRelayGrant, "handle">): ModelRelaySpec {
  if (!input || (input.provider !== "anthropic" && input.provider !== "openai")) {
    throw new Error("Unsupported model provider.");
  }
  if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > maxGrantMs) {
    throw new Error("A model relay grant needs a finite lifetime of at most 30 minutes.");
  }
  if (input.payloadProfile !== undefined && input.payloadProfile !== "strict") {
    throw new Error("Invalid model relay payload profile.");
  }
  if (input.maxRequests !== undefined &&
      (!Number.isSafeInteger(input.maxRequests) || input.maxRequests < 1 || input.maxRequests > 10_000)) {
    throw new Error("Invalid model relay request count limit.");
  }
  if (input.allowedModels !== undefined && (!Array.isArray(input.allowedModels) ||
      input.allowedModels.length < 1 || input.allowedModels.length > 64 ||
      input.allowedModels.some(model => typeof model !== "string" || model.length < 1 || model.length > 256 ||
        /[\x00-\x1f\x7f]/.test(model)) || new Set(input.allowedModels).size !== input.allowedModels.length)) {
    throw new Error("Invalid model relay model allowlist.");
  }

  const permitted: readonly string[] = modelRelayRoutes[input.provider];
  const requested = input.routes ?? [...permitted];
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > permitted.length ||
      requested.some(route => typeof route !== "string" || !permitted.includes(route)) ||
      new Set(requested).size !== requested.length) {
    throw new Error("Invalid model relay route set.");
  }
  const routes = permitted.filter(route => requested.includes(route));

  for (const value of [input.workspaceId, input.organizationId, input.projectId]) {
    if (value !== undefined && (typeof value !== "string" || value.length > 512 || /[\x00-\x1f\x7f]/.test(value))) {
      throw new Error("Invalid operator-owned model account ID.");
    }
  }
  if (input.provider === "anthropic" && (input.organizationId || input.projectId)) {
    throw new Error("OpenAI account IDs cannot be used with Anthropic.");
  }
  if (input.provider === "openai" && input.workspaceId) {
    throw new Error("An Anthropic workspace ID cannot be used with OpenAI.");
  }
  if (input.anthropicVersion !== undefined &&
      (input.provider !== "anthropic" || !/^\d{4}-\d{2}-\d{2}$/.test(input.anthropicVersion))) {
    throw new Error("Invalid operator-owned Anthropic API version.");
  }
  const beta = input.allowedBetaValues ?? [];
  if (!Array.isArray(beta) || beta.length > 16 || beta.some(value =>
    typeof value !== "string" || value.length < 1 || value.length > 512 || /[\x00-\x1f\x7f]/.test(value)) ||
      new Set(beta).size !== beta.length) {
    throw new Error("Invalid operator-owned model beta values.");
  }

  return {
    provider: input.provider,
    routes,
    ttlMs: input.ttlMs,
    ...(input.payloadProfile ? { payloadProfile: input.payloadProfile } : {}),
    ...(input.maxRequests !== undefined ? { maxRequests: input.maxRequests } : {}),
    ...(input.allowedModels ? { allowedModels: [...input.allowedModels] } : {}),
    ...(input.workspaceId ? { workspaceId: input.workspaceId } : {}),
    ...(input.organizationId ? { organizationId: input.organizationId } : {}),
    ...(input.projectId ? { projectId: input.projectId } : {}),
    ...(input.anthropicVersion ? { anthropicVersion: input.anthropicVersion } : {}),
    allowedBetaValues: [...beta]
  };
}

export function buildModelRelayAction(input: ModelRelayGrant): CommandAction {
  const { handle: _handle, ...model } = normalizeModelRelayGrant(input);
  return {
    kind: "model_relay",
    command: SGW_MODEL_RELAY_COMMAND,
    args: [],
    injectEnv: "",
    timeoutMs: 0,
    owned: true,
    model
  };
}

export function normalizeModelRelayAction(action: CommandAction): CommandAction {
  if (action.kind !== "model_relay" || !action.model || action.command !== SGW_MODEL_RELAY_COMMAND ||
      !Array.isArray(action.args) || action.args.length !== 0 || action.injectEnv !== "" ||
      action.timeoutMs !== 0 || action.owned !== true || action.env?.length || action.ssh || action.http ||
      action.resolvedCommand || action.workingDir) {
    throw new Error("Invalid broker-owned model relay action.");
  }
  return { ...action, args: [], model: normalizeModelRelaySpec(action.model) };
}

export function grantFromModelRelayAction(handle: string, action: CommandAction): ModelRelayGrant {
  const normalized = normalizeModelRelayAction(action);
  return normalizeModelRelayGrant({ ...normalized.model!, handle });
}
