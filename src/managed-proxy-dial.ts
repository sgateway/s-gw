import { lookup } from "node:dns/promises";
import { BlockList, connect as netConnect, isIP, type Socket } from "node:net";
import { modelAddressAllowed } from "./model-relay-transport.js";

type IpFamily = 4 | 6;
type LookupAnswer = { address: string; family: number };
type Address = { address: string; family: IpFamily };

export interface ManagedProxyDialOptions {
  signal?: AbortSignal;
  lookup?: (host: string, signal: AbortSignal) => Promise<readonly LookupAnswer[]>;
  connect?: (address: string, port: number, family: IpFamily, signal: AbortSignal) => Promise<Socket>;
  lookupTimeoutMs?: number;
  connectTimeoutMs?: number;
}

export interface ManagedProxyConnection {
  requestedHost: string;
  address: string;
  family: IpFamily;
  socket: Socket;
}

const extraSpecialUse = new BlockList();
const capacity = {
  lookup: { active: 0, max: 16 },
  connection: { active: 0, max: 32 }
};
for (const subnet of ["192.0.0.0", "192.31.196.0", "192.52.193.0", "192.175.48.0"]) {
  extraSpecialUse.addSubnet(subnet, 24);
}
extraSpecialUse.addSubnet("2620:4f:8000::", 48, "ipv6");

function publicAddress(address: LookupAnswer): address is Address {
  if (isIP(address.address) !== address.family || !modelAddressAllowed(address.address)) return false;
  // IPv4-mapped IPv6 is special use even when the embedded IPv4 address is public.
  if (address.family === 6) {
    const canonical = new URL(`http://[${address.address}]/`).hostname;
    if (canonical.startsWith("[::ffff:")) return false;
  }
  return !extraSpecialUse.check(address.address, address.family === 4 ? "ipv4" : "ipv6");
}

function timeoutMs(value: number | undefined, name: string): number {
  const ms = value ?? 5_000;
  if (!Number.isSafeInteger(ms) || ms < 1 || ms > 30_000) throw new Error(`Invalid managed proxy ${name} timeout.`);
  return ms;
}

function dialHost(host: string): { requestedHost: string; lookupHost: string; literal: IpFamily | 0 } {
  if (!host || host.length > 253) throw new Error("Invalid managed proxy host.");
  const bracketed = host.startsWith("[") && host.endsWith("]");
  const lookupHost = bracketed ? host.slice(1, -1) : host;
  const literal = isIP(lookupHost) as IpFamily | 0;
  if (literal) {
    if (bracketed && literal !== 6) throw new Error("Invalid managed proxy host.");
    return { requestedHost: host, lookupHost, literal };
  }
  if (bracketed || !/^[a-zA-Z0-9_.-]+$/.test(host) || host.startsWith(".") || host.includes("..")) {
    throw new Error("Invalid managed proxy host.");
  }
  return { requestedHost: host, lookupHost, literal: 0 };
}

function limitedWork<T>(kind: "lookup" | "connection", work: () => Promise<T>): Promise<T> {
  const limit = capacity[kind];
  if (limit.active >= limit.max) throw new Error(`Managed proxy ${kind} capacity exceeded.`);
  limit.active++;
  const pending = Promise.resolve().then(work);
  // A cancelled dial may leave its underlying DNS or connector work running.
  void pending.then(() => { limit.active--; }, () => { limit.active--; });
  return pending;
}

async function withDeadline<T>(work: Promise<T>, ms: number, label: string, signal?: AbortSignal, onStop?: () => void): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  let stopped = false;
  const stop = (reject: (error: Error) => void, error: Error) => {
    if (stopped) return;
    stopped = true;
    onStop?.();
    reject(error);
  };
  let onAbort: (() => void) | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      stop(reject, new Error(`Managed proxy ${label} timed out.`));
    }, ms);
    onAbort = () => stop(reject, new Error("Managed proxy dial aborted."));
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
  try { return await Promise.race([work, expired]); }
  finally {
    clearTimeout(timer);
    if (onAbort) signal?.removeEventListener("abort", onAbort);
  }
}

function connectNumeric(address: string, port: number, family: IpFamily, signal: AbortSignal): Promise<Socket> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new Error("Managed proxy dial aborted.")); return; }
    const socket = netConnect({ host: address, port, family });
    const done = (error?: Error) => {
      socket.off("connect", onConnect);
      socket.off("error", onError);
      signal.removeEventListener("abort", onAbort);
      if (error) { socket.destroy(); reject(error); }
      else resolve(socket);
    };
    const onConnect = () => done();
    const onError = (error: Error) => done(error);
    const onAbort = () => done(new Error("Managed proxy connection timed out."));
    socket.once("connect", onConnect);
    socket.once("error", onError);
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

export async function dialManagedProxyHost(host: string, port: number, options: ManagedProxyDialOptions = {}): Promise<ManagedProxyConnection> {
  if (options.signal?.aborted) throw new Error("Managed proxy dial aborted.");
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error("Invalid managed proxy port.");
  const target = dialHost(host);
  const lookupLimit = timeoutMs(options.lookupTimeoutMs, "lookup");
  const connectLimit = timeoutMs(options.connectTimeoutMs, "connection");
  let addresses: readonly LookupAnswer[];
  if (target.literal) addresses = [{ address: target.lookupHost, family: target.literal }];
  else {
    const resolver = options.lookup ?? ((name: string) => lookup(name, { all: true }));
    const cancelLookup = new AbortController();
    try {
      const pending = limitedWork("lookup", () => {
        if (cancelLookup.signal.aborted) throw new Error("Managed proxy dial aborted.");
        return resolver(target.lookupHost, cancelLookup.signal);
      });
      addresses = await withDeadline(pending, lookupLimit, "lookup", options.signal, () => cancelLookup.abort());
    } catch (error) {
      if (error instanceof Error && ["Managed proxy lookup timed out.", "Managed proxy dial aborted.",
        "Managed proxy lookup capacity exceeded."].includes(error.message)) throw error;
      throw new Error("Managed proxy lookup failed.", { cause: error });
    }
  }
  if (options.signal?.aborted) throw new Error("Managed proxy dial aborted.");
  if (!Array.isArray(addresses) || !addresses.length || addresses.some(item => !item)) {
    throw new Error("Managed proxy host resolves to a restricted address.");
  }
  const vetted: Address[] = [];
  for (const address of addresses) {
    if (!publicAddress(address)) throw new Error("Managed proxy host resolves to a restricted address.");
    vetted.push(address);
  }

  const chosen = vetted[0];
  const cancel = new AbortController();
  const connector = options.connect ?? connectNumeric;
  if (options.signal?.aborted) throw new Error("Managed proxy dial aborted.");
  const pending = limitedWork("connection", () => {
    if (cancel.signal.aborted || options.signal?.aborted) throw new Error("Managed proxy dial aborted.");
    return connector(chosen.address, port, chosen.family, cancel.signal);
  });
  try {
    const socket = await withDeadline(pending, connectLimit, "connection", options.signal, () => cancel.abort());
    if (options.signal?.aborted) { socket.destroy(); throw new Error("Managed proxy dial aborted."); }
    return { requestedHost: target.requestedHost, address: chosen.address, family: chosen.family, socket };
  } catch (error) {
    cancel.abort();
    // An injected connector may finish after the deadline; do not leave its socket open.
    void pending.then(socket => socket.destroy(), () => {});
    if (error instanceof Error && ["Managed proxy connection timed out.", "Managed proxy dial aborted.",
      "Managed proxy connection capacity exceeded."].includes(error.message)) throw error;
    throw new Error("Managed proxy connection failed.", { cause: error });
  }
}
