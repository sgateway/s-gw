import { Socket } from "node:net";
import { describe, expect, it, vi } from "vitest";
import { dialManagedProxyHost } from "../src/managed-proxy-dial.js";

const fakeSocket = () => new Socket();

describe("managed proxy dial", () => {
  it("refuses loopback, private, link-local, metadata, and special-use DNS answers", async () => {
    for (const address of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "192.168.1.1",
      "192.0.0.9", "192.31.196.1", "198.18.0.1", "203.0.113.7", "::1", "fc00::1",
      "fe80::1", "2001:db8::1", "2620:4f:8000::1"]) {
      const family = address.includes(":") ? 6 : 4;
      const connect = vi.fn(async () => fakeSocket());
      await expect(dialManagedProxyHost("allowed.test", 443, {
        lookup: async () => [{ address, family: family as 4 | 6 }], connect
      }), address).rejects.toThrow("restricted address");
      expect(connect).not.toHaveBeenCalled();
    }
  });

  it("rejects every answer when public and private addresses are mixed", async () => {
    const connect = vi.fn(async () => fakeSocket());
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }], connect
    })).rejects.toThrow("restricted address");
    expect(connect).not.toHaveBeenCalled();
  });

  it("rejects IPv4-mapped DNS answers and literals", async () => {
    const lookup = vi.fn(async () => [{ address: "8.8.8.8", family: 4 as const }]);
    const connect = vi.fn(async () => fakeSocket());
    for (const address of ["::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:8.8.8.8", "0:0:0:0:0:ffff:808:808"]) {
      await expect(dialManagedProxyHost("allowed.test", 443, {
        lookup: async () => [{ address, family: 6 }], connect
      }), address).rejects.toThrow("restricted address");
      await expect(dialManagedProxyHost(`[${address}]`, 443, { lookup, connect }), address).rejects.toThrow("restricted address");
    }
    expect(lookup).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });

  it("dials only the vetted numeric address even if DNS changes afterward", async () => {
    const lookup = vi.fn()
      .mockResolvedValueOnce([{ address: "8.8.8.8", family: 4 }, { address: "2606:4700:4700::1111", family: 6 }])
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]);
    const socket = fakeSocket();
    const connect = vi.fn(async () => socket);
    const result = await dialManagedProxyHost("allowed.test", 443, { lookup, connect });
    expect(result).toEqual({ requestedHost: "allowed.test", address: "8.8.8.8", family: 4, socket });
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(connect).toHaveBeenCalledWith("8.8.8.8", 443, 4, expect.any(AbortSignal));
    socket.destroy();
  });

  it("uses a public IP literal without DNS and keeps its original host", async () => {
    const lookup = vi.fn(async () => []);
    const socket = fakeSocket();
    const result = await dialManagedProxyHost("[2606:4700:4700::1111]", 443, {
      lookup, connect: async (address, port, family) => {
        expect([address, port, family]).toEqual(["2606:4700:4700::1111", 443, 6]);
        return socket;
      }
    });
    expect(result.requestedHost).toBe("[2606:4700:4700::1111]");
    expect(lookup).not.toHaveBeenCalled();
    socket.destroy();

    const ipv4 = fakeSocket();
    const v4Result = await dialManagedProxyHost("8.8.8.8", 443, {
      lookup, connect: async (address, _port, family) => {
        expect([address, family]).toEqual(["8.8.8.8", 4]);
        return ipv4;
      }
    });
    expect(v4Result.requestedHost).toBe("8.8.8.8");
    expect(lookup).not.toHaveBeenCalled();
    ipv4.destroy();
  });

  it("bounds lookup and connection waits and closes a late socket", async () => {
    const connect = vi.fn(async () => fakeSocket());
    let finishLookup!: (answers: { address: string; family: number }[]) => void;
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: () => new Promise(resolve => { finishLookup = resolve; }), connect, lookupTimeoutMs: 10
    })).rejects.toThrow("lookup timed out");
    finishLookup([{ address: "8.8.8.8", family: 4 }]);
    await new Promise(resolve => setImmediate(resolve));
    expect(connect).not.toHaveBeenCalled();

    let finish: ((socket: Socket) => void) | undefined;
    let signal: AbortSignal | undefined;
    const late = new Promise<Socket>(resolve => { finish = resolve; });
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [{ address: "8.8.8.8", family: 4 }],
      connect: (_address, _port, _family, currentSignal) => { signal = currentSignal; return late; },
      connectTimeoutMs: 10
    })).rejects.toThrow("connection timed out");
    expect(signal?.aborted).toBe(true);
    const socket = fakeSocket();
    finish!(socket);
    await vi.waitFor(() => expect(socket.destroyed).toBe(true));
  });

  it("does not start a lookup or connection after caller cancellation", async () => {
    const controller = new AbortController();
    controller.abort();
    const lookup = vi.fn(async () => [{ address: "8.8.8.8", family: 4 }]);
    const connect = vi.fn(async () => fakeSocket());
    await expect(dialManagedProxyHost("allowed.test", 443, {
      signal: controller.signal, lookup, connect
    })).rejects.toThrow("aborted");
    expect(lookup).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();
  });

  it("does not connect if the caller cancels during DNS", async () => {
    const controller = new AbortController();
    let finish!: (answers: { address: string; family: number }[]) => void;
    const lookup = () => new Promise<{ address: string; family: number }[]>(resolve => { finish = resolve; });
    const sockets: Socket[] = [];
    const connect = vi.fn(async () => {
      const socket = fakeSocket();
      sockets.push(socket);
      return socket;
    });
    const pending = dialManagedProxyHost("allowed.test", 443, { signal: controller.signal, lookup, connect });
    try {
      await vi.waitFor(() => expect(finish).toBeDefined());
      controller.abort();
      finish([{ address: "8.8.8.8", family: 4 }]);
      await expect(pending).rejects.toThrow("aborted");
      expect(connect).not.toHaveBeenCalled();
    } finally {
      controller.abort();
      if (finish) finish([{ address: "8.8.8.8", family: 4 }]);
      for (const socket of sockets) socket.destroy();
      await Promise.allSettled([pending]);
    }
  });

  it("notifies a cooperative resolver when the caller cancels", async () => {
    const controller = new AbortController();
    let resolverSignal: AbortSignal | undefined;
    const pending = dialManagedProxyHost("allowed.test", 443, {
      signal: controller.signal,
      lookup: (_host, signal) => new Promise((_resolve, reject) => {
        resolverSignal = signal;
        signal.addEventListener("abort", () => reject(new Error("resolver stopped")), { once: true });
      })
    });
    await vi.waitFor(() => expect(resolverSignal).toBeDefined());
    controller.abort();
    await expect(pending).rejects.toThrow("aborted");
    expect(resolverSignal?.aborted).toBe(true);
  });

  it("closes a connector's late socket after caller cancellation", async () => {
    const controller = new AbortController();
    let finish!: (socket: Socket) => void;
    const late = fakeSocket();
    const pending = dialManagedProxyHost("8.8.8.8", 443, {
      signal: controller.signal,
      connect: () => new Promise<Socket>(resolve => { finish = resolve; })
    });
    try {
      await vi.waitFor(() => expect(finish).toBeDefined());
      controller.abort();
      finish(late);
      await expect(pending).rejects.toThrow("aborted");
      await vi.waitFor(() => expect(late.destroyed).toBe(true));
    } finally {
      controller.abort();
      if (finish) finish(late);
      late.destroy();
      await Promise.allSettled([pending]);
    }
  });

  it("holds DNS capacity until cancelled or timed-out lookups settle", async () => {
    const controllers = Array.from({ length: 16 }, () => new AbortController());
    const finish: Array<(answers: { address: string; family: number }[]) => void> = [];
    const lookup = () => new Promise<{ address: string; family: number }[]>(resolve => { finish.push(resolve); });
    const connect = vi.fn(async () => fakeSocket());
    const pending = controllers.map((controller, index) => dialManagedProxyHost("allowed.test", 443, {
      signal: controller.signal, lookup, connect, lookupTimeoutMs: index < 8 ? 1_000 : 30
    }).catch(error => error));
    try {
      await vi.waitFor(() => expect(finish).toHaveLength(16));
      await expect(dialManagedProxyHost("allowed.test", 443, {
        lookup, connect, lookupTimeoutMs: 20
      })).rejects.toThrow("lookup capacity");
      for (const controller of controllers.slice(0, 8)) controller.abort();
      const outcomes = await Promise.all(pending);
      expect(outcomes.slice(0, 8).every(error => error.message === "Managed proxy dial aborted.")).toBe(true);
      expect(outcomes.slice(8).every(error => error.message === "Managed proxy lookup timed out.")).toBe(true);
      await expect(dialManagedProxyHost("allowed.test", 443, {
        lookup, connect, lookupTimeoutMs: 20
      })).rejects.toThrow("lookup capacity");
    } finally {
      for (const controller of controllers) controller.abort();
      for (const resolve of finish) resolve([{ address: "8.8.8.8", family: 4 }]);
      await Promise.allSettled(pending);
    }
    expect(connect).not.toHaveBeenCalled();
    const socket = fakeSocket();
    const result = await dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [{ address: "8.8.8.8", family: 4 }], connect: async () => socket
    });
    expect(result.socket).toBe(socket);
    socket.destroy();
  });

  it("holds connection capacity until cancelled connectors settle", async () => {
    const controllers = Array.from({ length: 32 }, () => new AbortController());
    const finish: Array<(socket: Socket) => void> = [];
    const connect = () => new Promise<Socket>(resolve => { finish.push(resolve); });
    const pending = controllers.map(controller => dialManagedProxyHost("8.8.8.8", 443, {
      signal: controller.signal, connect, connectTimeoutMs: 1_000
    }).catch(error => error));
    const sockets: Socket[] = [];
    try {
      await vi.waitFor(() => expect(finish).toHaveLength(32));
      await expect(dialManagedProxyHost("8.8.8.8", 443, {
        connect, connectTimeoutMs: 20
      })).rejects.toThrow("connection capacity");
      for (const controller of controllers) controller.abort();
      await expect(dialManagedProxyHost("8.8.8.8", 443, {
        connect, connectTimeoutMs: 20
      })).rejects.toThrow("connection capacity");
    } finally {
      for (const controller of controllers) controller.abort();
      for (const resolve of finish) {
        const socket = fakeSocket();
        sockets.push(socket);
        resolve(socket);
      }
      await Promise.allSettled(pending);
      for (const socket of sockets) socket.destroy();
    }
    const socket = fakeSocket();
    const result = await dialManagedProxyHost("8.8.8.8", 443, { connect: async () => socket });
    expect(result.socket).toBe(socket);
    socket.destroy();
  });

  it("rejects malformed answers and propagates connection failure", async () => {
    const connect = vi.fn(async () => fakeSocket());
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [{ address: "allowed.test", family: 4 }], connect
    })).rejects.toThrow("restricted address");
    expect(connect).not.toHaveBeenCalled();
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [], connect
    })).rejects.toThrow("restricted address");
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => { throw new Error("synthetic DNS failure"); }, connect
    })).rejects.toThrow("Managed proxy lookup failed");
    expect(connect).not.toHaveBeenCalled();
    await expect(dialManagedProxyHost("allowed.test", 443, {
      lookup: async () => [{ address: "8.8.8.8", family: 4 }],
      connect: async () => { throw new Error("synthetic refusal"); }
    })).rejects.toThrow("Managed proxy connection failed");
  });
});
