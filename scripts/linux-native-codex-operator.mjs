import { randomUUID } from "node:crypto";
import { principalForVerifiedPeer } from "../dist/agent-context.js";
import { SGW_MODEL_RELAY_COMMAND } from "../dist/model-relay-action.js";
import { SecretStore } from "../dist/store.js";

const [mode, ...args] = process.argv.slice(2);
if (process.platform !== "linux" || process.geteuid() === 0 || process.env.CI !== "true" ||
    process.env.SGW_DISABLE_KEYCHAIN !== "1" || !process.env.SGW_HOME ||
    !process.env.SGW_RECOVERY_HOME) {
  throw new Error("The native Codex operator requires its disposable unprivileged store.");
}

const store = new SecretStore();
await store.init();

if (mode === "seed" && args.length === 0) {
  const value = `synthetic-codex-broker-${randomUUID()}`;
  const record = await store.addSecret({ name: "Native Codex synthetic provider",
    type: "api-token", value,
    policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND],
      allowedDestinations: ["api.openai.com:443"] } });
  process.stdout.write(`${JSON.stringify({ handle: record.handle, value })}\n`);
} else if (mode === "pending" && args.length === 4) {
  const [sessionId, name, handle, generation] = args;
  if (!/^[a-f0-9]{32}$/.test(generation)) throw new Error("Invalid identity generation.");
  const pending = (await store.listRequests("pending")).filter(item =>
    item.agentSessionId === sessionId && item.action.kind === "model_relay");
  if (pending.length !== 1) throw new Error("Expected one native Codex approval request.");
  const request = pending[0];
  if (request.agentSource !== "managed-peer" || request.agentName !== name ||
      request.principalId !== `linux:managed:${generation}` || request.handle !== handle ||
      request.action.model?.provider !== "openai" ||
      request.action.model?.payloadProfile !== "strict" ||
      request.action.model?.toolBoundary !== "client-only" ||
      request.action.model?.routes?.join(",") !== "POST /v1/responses" ||
      request.action.model?.allowedModels?.join(",") !== "gpt-5.3-codex") {
    throw new Error("Native Codex request is not bound to its verified agent and strict grant.");
  }
  process.stdout.write(`${request.id}\n`);
} else if (mode === "approve" && args.length === 1) {
  const [requestId] = args;
  const request = await store.getRequest(requestId);
  if (!request || request.state !== "pending" || request.action.kind !== "model_relay" ||
      request.action.model?.provider !== "openai" ||
      request.action.model?.payloadProfile !== "strict" ||
      request.action.model?.toolBoundary !== "client-only") {
    throw new Error("Native Codex grant is not pending approval.");
  }
  await store.approveRequest(requestId, { mode: "per-transaction" });
  process.stdout.write(`${requestId}\n`);
} else if (mode === "state" && args.length === 2) {
  const [requestId, state] = args;
  const request = await store.getRequest(requestId);
  if (!request || request.action.kind !== "model_relay" || request.state !== state ||
      request.action.model?.toolBoundary !== "client-only") {
    throw new Error(`Native Codex grant has not reached ${state}.`);
  }
  process.stdout.write(`${state}\n`);
} else if (mode === "reject-foreign" && args.length === 4) {
  const [requestId, sessionId, name, generation] = args;
  const principal = principalForVerifiedPeer(`linux:managed:${generation}`, name, sessionId);
  let denied = false;
  try { await store.claimApprovedModelRelayRequest(requestId, principal); }
  catch (error) {
    if (/different verified agent/.test(String(error))) denied = true;
    else throw error;
  }
  if (!denied || (await store.getRequest(requestId))?.state !== "approved") {
    throw new Error("Foreign agent claimed another Codex grant.");
  }
  process.stdout.write("denied\n");
} else {
  throw new Error("Invalid native Codex operator command.");
}
