import type { Socket } from "node:net";
import { requestAgentIdentity, type VerifiedAgentPrincipal } from "./agent-context.js";
import type { UnixPeer } from "./peer-identity.js";

const probeDeadlineMs = 1500;

export async function acknowledgeMacAgentLaunch(
  socket: Socket,
  principal: VerifiedAgentPrincipal,
  peer: UnixPeer
): Promise<void> {
  if (process.platform !== "darwin") throw new Error("macOS agent launch probes require macOS.");
  const identity = requestAgentIdentity("", { managedPrincipal: principal, env: {} });
  const session = identity.agentSessionId;
  if (!Number.isSafeInteger(peer.uid) || peer.uid < 1 ||
      identity.principalId !== `darwin:uid:${peer.uid}` ||
      !session || !/^[A-Za-z0-9_-]{1,64}$/.test(session)) {
    throw new Error("The launch probe does not match a verified macOS agent session.");
  }

  const expected = Buffer.from(`HELLO-V1 ${peer.uid} ${session}\n`);
  const reply = `READY-V1 ${peer.uid} ${session}\n`;
  await new Promise<void>((resolve, reject) => {
    let offset = 0;
    let done = false;
    const timer = setTimeout(() => fail(new Error("macOS agent launch probe timed out.")), probeDeadlineMs);

    function cleanup(): void {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("end", onEnd);
      socket.off("error", fail);
      socket.off("close", onClose);
    }

    function fail(error: Error): void {
      if (done) return;
      done = true;
      cleanup();
      socket.destroy();
      reject(error);
    }

    function onClose(): void { fail(new Error("macOS agent launch probe closed early.")); }

    function onData(chunk: Buffer | string): void {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      for (const byte of bytes) {
        if (offset >= expected.length || byte !== expected[offset]) {
          fail(new Error("Invalid macOS agent launch probe."));
          return;
        }
        offset++;
      }
    }

    function onEnd(): void {
      if (offset !== expected.length) {
        fail(new Error("Incomplete macOS agent launch probe."));
        return;
      }
      socket.off("data", onData);
      socket.off("end", onEnd);
      try {
        socket.end(reply, () => {
          if (done) return;
          done = true;
          cleanup();
          resolve();
        });
      } catch (error) {
        fail(error instanceof Error ? error : new Error("Could not acknowledge macOS agent launch."));
      }
    }

    socket.on("data", onData);
    socket.on("end", onEnd);
    socket.on("error", fail);
    socket.on("close", onClose);
    socket.resume();
  });
}
