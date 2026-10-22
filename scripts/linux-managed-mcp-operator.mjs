import { principalForVerifiedPeer } from "../dist/agent-context.js";
import { SGW_HTTP_COMMAND } from "../dist/http-action.js";
import { SGW_MODEL_RELAY_COMMAND } from "../dist/model-relay-action.js";
import { SecretStore } from "../dist/store.js";
import { randomUUID } from "node:crypto";

const [mode, ...args] = process.argv.slice(2);
if (process.platform !== "linux" || process.geteuid() === 0 || process.env.CI !== "true" ||
    process.env.SGW_DISABLE_KEYCHAIN !== "1" || !process.env.SGW_HOME ||
    !process.env.SGW_RECOVERY_HOME) {
  throw new Error("The native fixture operator needs its disposable unprivileged Linux store.");
}

const store = new SecretStore();
await store.init();

if (mode === "seed" && args.length === 1) {
  const [port] = args;
  if (!/^\d{1,5}$/.test(port)) {
    throw new Error("Invalid native fixture HTTPS seed.");
  }
  const value = `synthetic-managed-mcp-${randomUUID()}`;
  const record = await store.addSecret({ name: "Native managed MCP HTTPS fixture",
    type: "api-token", value,
    policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: [`127.0.0.1:${port}`] } });
  process.stdout.write(`${JSON.stringify({ handle: record.handle, value })}\n`);
} else if (mode === "seed-relay" && args.length === 0) {
  const value = `synthetic-managed-model-${randomUUID()}`;
  const record = await store.addSecret({ name: "Native managed model relay fixture",
    type: "api-token", value,
    policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND],
      allowedDestinations: ["api.anthropic.com:443"] } });
  process.stdout.write(`${JSON.stringify({ handle: record.handle, value })}\n`);
} else if (mode === "relay-pending" && args.length === 4) {
  const [sessionId, name, handle, generation] = args;
  if (!/^[a-f0-9]{32}$/.test(generation)) throw new Error("Invalid native model identity generation.");
  const pending = (await store.listRequests("pending")).filter(item =>
    item.agentSessionId === sessionId && item.action.kind === "model_relay");
  if (pending.length === 0) process.stdout.write("none\n");
  else {
    if (pending.length !== 1) throw new Error("Expected one native model relay approval request.");
    const request = pending[0];
    if (request.agentSource !== "managed-peer" || request.agentName !== name ||
        request.principalId !== `linux:managed:${generation}` || request.handle !== handle ||
        request.action.model?.provider !== "anthropic" ||
        request.action.model?.payloadProfile !== "strict" ||
        request.action.model?.routes?.join(",") !== "POST /v1/messages") {
      throw new Error("Native model request was not bound to its agent and strict grant.");
    }
    process.stdout.write(`${request.id}\n`);
  }
} else if (mode === "relay-created" && args.length === 1) {
  const [sessionId] = args;
  const count = (await store.listRequests()).filter(item =>
    item.agentSessionId === sessionId && item.action.kind === "model_relay").length;
  process.stdout.write(`${count}\n`);
} else if (mode === "approve-relay" && args.length === 1) {
  const [requestId] = args;
  const request = await store.getRequest(requestId);
  if (!request || request.action.kind !== "model_relay" || request.state !== "pending" ||
      request.action.model?.payloadProfile !== "strict") {
    throw new Error("Native model relay request is not pending with a strict grant.");
  }
  await store.approveRequest(requestId, { mode: "per-transaction" });
  process.stdout.write(`${requestId}\n`);
} else if (mode === "assert-relay-state" && args.length === 2) {
  const [requestId, state] = args;
  const request = await store.getRequest(requestId);
  if (!request || request.action.kind !== "model_relay" || request.state !== state) {
    throw new Error(`Native model relay request has not reached ${state}.`);
  }
  process.stdout.write(`${state}\n`);
} else if (mode === "reject-relay-claim" && args.length === 4) {
  const [requestId, sessionId, name, generation] = args;
  if (!/^[a-f0-9]{32}$/.test(generation)) throw new Error("Invalid foreign relay identity generation.");
  const principal = principalForVerifiedPeer(`linux:managed:${generation}`, name, sessionId);
  let denied = false;
  try { await store.claimApprovedModelRelayRequest(requestId, principal); }
  catch (error) {
    if (/different verified agent/.test(String(error))) denied = true;
    else throw error;
  }
  if (!denied || (await store.getRequest(requestId))?.state !== "approved") {
    throw new Error("Another native agent claimed an approved model relay request.");
  }
  process.stdout.write("denied\n");
} else if (mode === "reject-relay-reclaim" && args.length === 4) {
  const [requestId, sessionId, name, generation] = args;
  if (!/^[a-f0-9]{32}$/.test(generation)) throw new Error("Invalid relay identity generation.");
  const principal = principalForVerifiedPeer(`linux:managed:${generation}`, name, sessionId);
  let denied = false;
  try { await store.claimApprovedModelRelayRequest(requestId, principal); }
  catch (error) {
    if (/approved model relay request/.test(String(error))) denied = true;
    else throw error;
  }
  const state = (await store.getRequest(requestId))?.state;
  if (!denied || state !== "executed") {
    throw new Error("A native model relay approval could be reclaimed after teardown.");
  }
  process.stdout.write(`${state}\n`);
} else if (mode === "approve" && (args.length === 5 || args.length === 6)) {
  const [sessionId, uidText, name, handle, url, generation] = args;
  const uid = Number(uidText);
  if (!Number.isSafeInteger(uid) || uid < 1) throw new Error("Invalid native fixture UID.");
  if (generation !== undefined && !/^[a-f0-9]{32}$/.test(generation)) {
    throw new Error("Invalid native fixture identity generation.");
  }
  const principalId = generation ? `linux:managed:${generation}` : `linux:uid:${uid}`;
  const pending = (await store.listRequests("pending")).filter(item =>
    item.agentSessionId === sessionId);
  if (pending.length !== 1) throw new Error(`Expected one native managed request; found ${pending.length}.`);
  const request = pending[0];
  if (request.agentSource !== "managed-peer" || request.agentName !== name ||
      request.principalId !== principalId || request.agentSessionId !== sessionId ||
      request.handle !== handle || request.action.kind !== "http_request" ||
      request.action.http?.url !== url || request.action.http?.method !== "GET" ||
      request.action.http?.auth.kind !== "bearer") {
    throw new Error("The native HTTPS request was not bound to the expected verified agent and action.");
  }
  await store.approveRequest(request.id, { mode: "per-transaction" });
  const otherPrincipal = generation
    ? `linux:managed:${generation === "0".repeat(32) ? "1".repeat(32) : "0".repeat(32)}`
    : `linux:uid:${uid + 1}`;
  for (const caller of [{ mcpClientName: name },
    { managedPrincipal: principalForVerifiedPeer(otherPrincipal, name, sessionId) },
    { managedPrincipal: principalForVerifiedPeer(principalId, name, `${sessionId}-wrong`) }]) {
    try {
      await store.claimApprovedRequest(request.id, caller);
    } catch (error) {
      if (/different verified agent/.test(String(error))) continue;
      throw error;
    }
    throw new Error("A claimant outside the verified agent session executed its request.");
  }
  if ((await store.getRequest(request.id)).state !== "approved") {
    throw new Error("An unauthorized claimant changed the approved request state.");
  }
  process.stdout.write(`${request.id}\n`);
} else {
  throw new Error("Usage: linux-managed-mcp-operator seed <port> | approve <session> <uid> <name> <handle> <url> [generation]");
}
