import { principalForVerifiedPeer } from "../dist/agent-context.js";
import { SGW_HTTP_COMMAND } from "../dist/http-action.js";
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
