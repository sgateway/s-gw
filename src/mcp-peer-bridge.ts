#!/usr/bin/env node
import { connect } from "node:net";
import path from "node:path";

const socketPath = process.argv[2];
if (!socketPath || process.argv.length !== 3 || !path.isAbsolute(socketPath)) {
  process.stderr.write("Usage: s-gw-mcp-peer-bridge <absolute broker socket path>\n");
  process.exitCode = 2;
} else {
  const socket = connect(socketPath);
  socket.setTimeout(35 * 60_000, () => socket.destroy());
  socket.once("connect", () => {
    process.stdin.pipe(socket);
    socket.pipe(process.stdout);
  });
  socket.once("error", () => { process.exitCode = 1; });
  socket.once("close", () => {
    process.stdin.unpipe(socket);
    process.stdin.pause();
    socket.unpipe(process.stdout);
  });
}
