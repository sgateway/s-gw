import { createServer } from "node:http";
import { createConnection, createServer as createNetServer, Socket } from "node:net";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { modelRelayHttpSocket, watchModelBodyIdle } from "../src/model-relay-socket.js";

describe("model relay message-gate socket", () => {
  it("returns an HTTP response after the client shuts down its write side", async () => {
    const server = createServer(async (req, res) => {
      let body = "";
      for await (const chunk of req) body += String(chunk);
      res.end(`received:${body}`);
    });
    let rawSocket: Socket | undefined;
    const listener = createNetServer({ allowHalfOpen: true }, raw => {
      rawSocket = raw;
      const input = new PassThrough();
      const output = new PassThrough();
      const bridge = modelRelayHttpSocket(raw, { input, output });
      raw.on("data", chunk => input.write(chunk));
      output.on("data", chunk => raw.write(chunk));
      output.once("end", () => raw.end());
      server.emit("connection", bridge);
    });
    try {
      await new Promise<void>(resolve => listener.listen(0, "127.0.0.1", resolve));
      const address = listener.address();
      if (!address || typeof address === "string") throw new Error("TCP listener has no port.");
      const client = createConnection({ host: "127.0.0.1", port: address.port });
      const received: Buffer[] = [];
      client.on("data", chunk => received.push(Buffer.from(chunk)));
      const closed = new Promise<void>(resolve => client.once("close", resolve));
      client.end("POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
      await closed;
      expect(Buffer.concat(received).toString()).toContain("received:ok");
      expect(rawSocket?.destroyed).toBe(true);
    } finally {
      listener.close();
      server.close();
    }
  });

  it("closes the HTTP stream when its verified socket is revoked", async () => {
    const raw = new Socket();
    const bridge = modelRelayHttpSocket(raw, { input: new PassThrough(), output: new PassThrough() });
    raw.destroy();
    await vi.waitFor(() => expect(bridge.destroyed).toBe(true));
  });

  it("handles a verified socket that closed while the gate started", async () => {
    const raw = new Socket();
    raw.destroy();
    const bridge = modelRelayHttpSocket(raw, { input: new PassThrough(), output: new PassThrough() });
    await vi.waitFor(() => expect(bridge.destroyed).toBe(true));
  });

  it("closes a truncated HTTP body while the bridge holds a half-closed input open", async () => {
    const server = createServer((req) => {
      const stop = watchModelBodyIdle(req.socket, 30, () => req.destroy());
      req.once("close", stop);
    });
    server.on("clientError", (_error, socket) => socket.destroy());
    let rawSocket: Socket | undefined;
    const listener = createNetServer({ allowHalfOpen: true }, raw => {
      rawSocket = raw;
      const input = new PassThrough();
      const output = new PassThrough();
      const bridge = modelRelayHttpSocket(raw, { input, output });
      raw.on("data", chunk => input.write(chunk));
      output.on("data", chunk => raw.write(chunk));
      server.emit("connection", bridge);
    });
    try {
      await new Promise<void>(resolve => listener.listen(0, "127.0.0.1", resolve));
      const address = listener.address();
      if (!address || typeof address === "string") throw new Error("TCP listener has no port.");
      const client = createConnection({ host: "127.0.0.1", port: address.port });
      const closed = new Promise<void>(resolve => client.once("close", resolve));
      client.end("POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{");
      await closed;
      expect(rawSocket?.destroyed).toBe(true);
    } finally {
      listener.close();
      server.close();
    }
  });

  it("resets the body idle deadline on incoming bytes and cancels it after the body", () => {
    vi.useFakeTimers();
    try {
      const socket = new PassThrough();
      const onIdle = vi.fn();
      const stop = watchModelBodyIdle(socket, 100, onIdle);
      vi.advanceTimersByTime(80);
      socket.write("body");
      vi.advanceTimersByTime(80);
      expect(onIdle).not.toHaveBeenCalled();
      vi.advanceTimersByTime(20);
      expect(onIdle).toHaveBeenCalledOnce();
      stop();
      socket.destroy();

      const completed = new PassThrough();
      const completedIdle = vi.fn();
      const stopCompleted = watchModelBodyIdle(completed, 100, completedIdle);
      vi.advanceTimersByTime(50);
      stopCompleted();
      vi.advanceTimersByTime(100);
      expect(completedIdle).not.toHaveBeenCalled();
      completed.destroy();
    } finally {
      vi.useRealTimers();
    }
  });
});
