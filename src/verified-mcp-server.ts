import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { executeApprovedRequest } from "./executor.js";
import { buildHttpRequestAction } from "./http-action.js";
import type { OwnedHttpOptions } from "./http-executor.js";
import { managedSshHostFingerprint } from "./managed-ssh.js";
import { traceLinuxManagedStart } from "./linux-agent-unit.js";
import { startLinuxMessageGate } from "./linux-message-gate.js";
import { startVerifiedPeerServer, type PeerSession, type VerifiedPeerServerOptions } from "./peer-identity.js";
import { defaultSshInjectEnv } from "./ssh.js";
import type { SecretStore } from "./store.js";
import { CURRENT_VERSION } from "./version.js";

export interface VerifiedMcpServerOptions extends Pick<VerifiedPeerServerOptions,
  "socketPath" | "socketMode" | "socketGid" | "activatedFd" | "requireLinuxMessageGate"> {
  store: SecretStore;
  http?: OwnedHttpOptions;
}

export interface VerifiedMcpServer {
  registerSession(session: PeerSession): () => void;
  assertSocketBinding(): Promise<void>;
  close(): Promise<void>;
}

function asText(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

export async function startVerifiedMcpServer(options: VerifiedMcpServerOptions): Promise<VerifiedMcpServer> {
  if (!options.store) throw new Error("Verified MCP needs a broker-owned store.");
  const gated = options.requireLinuxMessageGate === true;
  const sessions = new Map<string, PeerSession>();
  const activeTools = new Map<string, number>();
  let closed = false;
  const peer = await startVerifiedPeerServer({
    socketPath: options.socketPath,
    socketMode: options.socketMode,
    socketGid: options.socketGid,
    activatedFd: options.activatedFd,
    requireLinuxPeerPidfd: true,
    requireLinuxMessageGate: gated,
    async onConnection(socket, principal) {
      const session = principal.sessionId ? sessions.get(principal.sessionId) : undefined;
      if (!session) { socket.destroy(); return; }
      if (gated) traceLinuxManagedStart(session.uid, "mcp peer authenticated");
      const connection = new AbortController();
      socket.once("close", () => connection.abort());
      const active = () => {
        if (closed || connection.signal.aborted || socket.destroyed || sessions.get(session.sessionId) !== session) {
          throw new Error("Verified agent session ended.");
        }
      };
      const withSlot = async <T>(run: () => Promise<T>): Promise<T> => {
        active();
        const count = activeTools.get(session.sessionId) ?? 0;
        if (count >= 4) throw new Error("Verified agent session is busy.");
        activeTools.set(session.sessionId, count + 1);
        try { return await run(); }
        finally {
          const current = activeTools.get(session.sessionId);
          if (current !== undefined) activeTools.set(session.sessionId, current - 1);
        }
      };
      const caller = { managedPrincipal: principal };
      const server = new McpServer({ name: "s-gw", version: CURRENT_VERSION });

      server.registerTool("sgw_list_handles", {
        title: "List Handles", description: "List local secret handles and non-secret metadata.", inputSchema: {}
      }, async () => withSlot(async () => asText(await options.store.listHandles())));

      server.registerTool("sgw_describe_handle", {
        title: "Describe Handle", description: "Show non-secret metadata for one handle.",
        inputSchema: { handle: z.string().min(1) }
      }, async ({ handle }) => withSlot(async () => asText(await options.store.getHandle(handle) ?? { error: "unknown_handle", handle })));

      server.registerTool("sgw_list_ssh_routes", {
        title: "List Managed SSH Routes", description: "List operator-managed SSH route IDs and endpoint metadata.", inputSchema: {}
      }, async () => withSlot(async () => {
        return asText((await options.store.listManagedSshRoutes()).map(item => ({
          id: item.id, name: item.name, host: item.route.host, user: item.route.user,
          port: item.route.port, hostKeyFingerprint: managedSshHostFingerprint(item.route)
        })));
      }));

      server.registerTool("sgw_request_ssh_session", {
        title: "Request s-gw-Owned SSH Session",
        description: "Request an SSH command through an operator-managed route.",
        inputSchema: {
          handle: z.string().min(1), routeId: z.string().min(1), args: z.array(z.string()).optional(),
          timeoutMs: z.number().int().nonnegative().optional(), reason: z.string().optional()
        }
      }, async ({ handle, routeId, args, timeoutMs, reason }) => withSlot(async () => {
        active();
        const secret = await options.store.getSecretRecord(handle);
        active();
        const request = await options.store.createManagedSshRequest(handle, routeId, {
          args, timeoutMs, injectEnv: defaultSshInjectEnv(secret)
        }, reason || "Agent requested s-gw-owned SSH access.", caller, active);
        return asText({ approvalRequired: request.state !== "approved", request });
      }));

      server.registerTool("sgw_request_http", {
        title: "Request s-gw-Owned HTTPS Operation",
        description: "Request an approved HTTPS operation executed by s-gw.",
        inputSchema: {
          handle: z.string().min(1), url: z.string().url(),
          method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
          headers: z.record(z.string(), z.string()).optional(), body: z.string().optional(),
          auth: z.discriminatedUnion("kind", [z.object({ kind: z.literal("bearer") }),
            z.object({ kind: z.literal("header"), name: z.string() }),
            z.object({ kind: z.literal("basic"), username: z.string() })]),
          timeoutMs: z.number().int().positive().optional(), reason: z.string().optional()
        }
      }, async ({ handle, url, method, headers, body, auth, timeoutMs, reason }) => withSlot(async () => {
        active();
        const secret = await options.store.getSecretRecord(handle);
        active();
        const action = buildHttpRequestAction({ url, method, headers: headers || {}, body, auth }, timeoutMs, secret.policy.injectEnv);
        const request = await options.store.createRequest(handle, action, reason || "Agent requested an owned HTTPS operation.", caller, active);
        return asText({ approvalRequired: request.state !== "approved", request });
      }));

      server.registerTool("sgw_execute_request", {
        title: "Execute Approved Request", description: "Execute an approved owned SSH or HTTPS request.",
        inputSchema: { requestId: z.string().min(1) }
      }, async ({ requestId }) => withSlot(async () => {
        return asText(await executeApprovedRequest(options.store, requestId, {
          operationsOnly: true, caller, http: options.http,
          agentSession: { signal: connection.signal, assertActive: active }
        }));
      }));

      socket.once("close", () => { void server.close().catch(() => {}); });
      if (gated) {
        const gate = await startLinuxMessageGate(socket, session.uid, session.gid!, session.linuxCgroup!);
        traceLinuxManagedStart(session.uid, "mcp message gate started");
        void server.connect(new StdioServerTransport(gate.input, gate.output,
          { maxBufferSize: 1024 * 1024 })).then(
          () => traceLinuxManagedStart(session.uid, "mcp transport connected"),
          () => { traceLinuxManagedStart(session.uid, "mcp transport rejected"); socket.destroy(); });
      } else {
        void server.connect(new StdioServerTransport(socket, socket, { maxBufferSize: 1024 * 1024 }))
          .then(() => socket.resume(), () => socket.destroy());
      }
    }
  });

  return {
    registerSession(session) {
      if (closed) throw new Error("Verified MCP listener is closed.");
      if (sessions.has(session.sessionId)) throw new Error("This verified MCP session is already registered.");
      const registered = { ...session };
      const stopPeer = peer.registerSession(registered);
      sessions.set(registered.sessionId, registered);
      activeTools.set(registered.sessionId, 0);
      return () => {
        if (sessions.get(registered.sessionId) !== registered) return;
        sessions.delete(registered.sessionId);
        activeTools.delete(registered.sessionId);
        stopPeer();
      };
    },
    assertSocketBinding: () => peer.assertSocketBinding(),
    async close() {
      if (closed) return;
      closed = true;
      sessions.clear();
      activeTools.clear();
      await peer.close();
    }
  };
}
