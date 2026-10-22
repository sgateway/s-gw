import { principalForVerifiedPeer, type VerifiedAgentPrincipal } from "./agent-context.js";
import { normalizeModelRelayGrant, type ModelRelayGrant } from "./model-relay-action.js";
import type { ModelRelayApproval, VerifiedModelRelayServer } from "./model-relay-server.js";
import { principalIdForPeerSession, type PeerSession } from "./peer-identity.js";
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
  private readonly pendingFailures = new Map<string, ClaimedRelay>();
  private readonly claiming = new Set<string>();

  constructor(private readonly store: SecretStore) {}

  async claim(requestId: string, session: PeerSession): Promise<ModelRelayGrant> {
    const sessionId = session.sessionId;
    if (!sessionId || this.active.has(sessionId) || this.claiming.has(sessionId) ||
        this.pendingEnds.has(sessionId) || this.pendingFailures.has(sessionId)) {
      throw new Error("Model relay session is already claimed.");
    }
    this.claiming.add(sessionId);
    try {
      const principal = principalForVerifiedPeer(principalIdForPeerSession(session), session.name, sessionId);
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
    if (claimed && claimed.uid === session.uid && claimed.principal.id === principalIdForPeerSession(session)) {
      this.active.delete(session.sessionId);
      this.pendingEnds.set(session.sessionId, claimed);
    }
    const pending = this.pendingEnds.get(session.sessionId);
    if (!pending || pending.uid !== session.uid || pending.principal.id !== principalIdForPeerSession(session)) return;
    await this.store.finishModelRelayRequest(pending.requestId);
    this.pendingEnds.delete(session.sessionId);
  }

  async retryPendingSessionEnds(): Promise<void> {
    const attempts = [...this.pendingEnds.entries()].map(async ([sessionId, pending]) => {
      await this.store.finishModelRelayRequest(pending.requestId);
      this.pendingEnds.delete(sessionId);
    });
    for (const [sessionId, pending] of this.pendingFailures) {
      attempts.push(this.failAbandoned(sessionId, pending));
    }
    const results = await Promise.allSettled(attempts);
    const errors = results.filter(result => result.status === "rejected").map(result => result.reason);
    if (errors.length) throw new AggregateError(errors, "Model relay session-end audit retry failed.");
  }

  async abandon(session: PeerSession): Promise<void> {
    const claimed = this.active.get(session.sessionId);
    if (!claimed || claimed.uid !== session.uid ||
        claimed.principal.id !== principalIdForPeerSession(session)) return;
    this.active.delete(session.sessionId);
    this.pendingFailures.set(session.sessionId, claimed);
    await this.failAbandoned(session.sessionId, claimed);
  }

  private async failAbandoned(sessionId: string, claimed: ClaimedRelay): Promise<void> {
    const reason = "Verified model relay listener rejected the agent session.";
    try {
      await this.store.markFailed(claimed.requestId, reason);
    } catch (error) {
      const request = await this.store.getRequest(claimed.requestId).catch(() => undefined);
      if (request?.state !== "failed" || request.error !== reason) throw error;
    }
    this.pendingFailures.delete(sessionId);
  }
}

export async function registerDurableModelRelaySession(
  server: VerifiedModelRelayServer,
  approval: StoreBackedModelRelayApprovals,
  session: PeerSession,
  requestId: string,
  expectedGrant?: ModelRelayGrant
): Promise<() => void> {
  const grant = await approval.claim(requestId, session);
  try {
    if (expectedGrant && JSON.stringify(normalizeModelRelayGrant(grant)) !==
        JSON.stringify(normalizeModelRelayGrant(expectedGrant))) {
      throw new Error("Approved model relay grant differs from the root-managed agent plan.");
    }
    return server.registerSession(session, grant);
  } catch (error) {
    try { await approval.abandon(session); }
    catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "Model relay registration and durable cleanup failed.");
    }
    throw error;
  }
}
