import { principalForVerifiedPeer, type VerifiedAgentPrincipal } from "./agent-context.js";
import { normalizeModelRelayGrant, type ModelRelayGrant } from "./model-relay-action.js";
import type { ModelRelayApproval, VerifiedModelRelayServer } from "./model-relay-server.js";
import type { PeerSession } from "./peer-identity.js";
import type { SecretStore } from "./store.js";

interface ClaimedRelay {
  requestId: string;
  principal: VerifiedAgentPrincipal;
  grant: ModelRelayGrant;
  uid: number;
}

export class StoreBackedModelRelayApprovals implements ModelRelayApproval {
  private readonly active = new Map<string, ClaimedRelay>();
  private readonly pendingEnds = new Map<string, ClaimedRelay>();
  private readonly claiming = new Set<string>();

  constructor(private readonly store: SecretStore) {}

  async claim(requestId: string, session: PeerSession): Promise<ModelRelayGrant> {
    const sessionId = session.sessionId;
    if (!sessionId || this.active.has(sessionId) || this.claiming.has(sessionId)) {
      throw new Error("Model relay session is already claimed.");
    }
    this.claiming.add(sessionId);
    try {
      const principal = principalForVerifiedPeer(`${process.platform}:uid:${session.uid}`, session.name, sessionId);
      const grant = await this.store.claimApprovedModelRelayRequest(requestId, principal);
      this.active.set(sessionId, { requestId, principal, grant, uid: session.uid });
      return grant;
    } finally {
      this.claiming.delete(sessionId);
    }
  }

  async assertAuthorized(principal: VerifiedAgentPrincipal, grant: Readonly<ModelRelayGrant>): Promise<void> {
    const claimed = principal.sessionId ? this.active.get(principal.sessionId) : undefined;
    if (!claimed || principal.id !== claimed.principal.id ||
        JSON.stringify(normalizeModelRelayGrant(grant)) !== JSON.stringify(claimed.grant)) {
      throw new Error("Model relay has no matching durable approval.");
    }
    await this.store.assertModelRelayRequestAuthorized(claimed.requestId, principal, claimed.grant);
  }

  async onSessionEnded(session: PeerSession): Promise<void> {
    const claimed = this.active.get(session.sessionId);
    if (claimed && claimed.uid === session.uid) {
      this.active.delete(session.sessionId);
      this.pendingEnds.set(session.sessionId, claimed);
    }
    const pending = this.pendingEnds.get(session.sessionId);
    if (!pending || pending.uid !== session.uid) return;
    await this.store.finishModelRelayRequest(pending.requestId);
    this.pendingEnds.delete(session.sessionId);
  }

  async retryPendingSessionEnds(): Promise<void> {
    const attempts = [...this.pendingEnds.entries()].map(async ([sessionId, pending]) => {
      await this.store.finishModelRelayRequest(pending.requestId);
      this.pendingEnds.delete(sessionId);
    });
    const results = await Promise.allSettled(attempts);
    const errors = results.filter(result => result.status === "rejected").map(result => result.reason);
    if (errors.length) throw new AggregateError(errors, "Model relay session-end audit retry failed.");
  }

  async abandon(session: PeerSession): Promise<void> {
    const claimed = this.active.get(session.sessionId);
    if (!claimed || claimed.uid !== session.uid) return;
    this.active.delete(session.sessionId);
    await this.store.markFailed(claimed.requestId, "Verified model relay listener rejected the agent session.");
  }
}

export async function registerDurableModelRelaySession(
  server: VerifiedModelRelayServer,
  approval: StoreBackedModelRelayApprovals,
  session: PeerSession,
  requestId: string
): Promise<() => void> {
  const grant = await approval.claim(requestId, session);
  try {
    return server.registerSession(session, grant);
  } catch (error) {
    await approval.abandon(session).catch(() => {});
    throw error;
  }
}
