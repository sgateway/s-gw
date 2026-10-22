import type { Socket } from "node:net";
import { Duplex } from "node:stream";
import type { LinuxMessageGate } from "./linux-message-gate.js";

export function modelRelayHttpSocket(raw: Socket, gate: LinuxMessageGate): Duplex {
  const bridge = Duplex.from({ readable: gate.input, writable: gate.output });
  bridge.on("error", () => raw.destroy());
  raw.once("close", () => bridge.destroy());
  bridge.once("close", () => raw.destroy());
  if (raw.destroyed) bridge.destroy();
  return bridge;
}

export function watchModelBodyIdle(socket: Duplex, idleMs: number, onIdle: () => void): () => void {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let stopped = false;
  const refresh = () => {
    if (stopped) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { stopped = true; onIdle(); }, idleMs);
    timer.unref();
  };
  const stop = () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    socket.off("data", refresh);
    socket.off("close", stop);
  };
  socket.on("data", refresh);
  socket.once("close", stop);
  refresh();
  return stop;
}
