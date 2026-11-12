import { chmodSync, chownSync } from "node:fs";
import { createServer } from "node:net";

const [socketPath, forwarderGid, brokerUid, brokerGid] = process.argv.slice(2);
if (!socketPath || ![forwarderGid, brokerUid, brokerGid].every(value => /^[1-9][0-9]*$/.test(value))) {
  throw new Error("Invalid synthetic bridge broker identity.");
}

let initializes = 0, lists = 0, invalid = false;
const server = createServer(socket => {
  let pending = "";
  socket.on("error", () => {});
  socket.on("data", bytes => {
    pending += bytes.toString();
    while (pending.includes("\n")) {
      const pos = pending.indexOf("\n");
      let message;
      try { message = JSON.parse(pending.slice(0, pos)); }
      catch { invalid = true; socket.destroy(); return; }
      pending = pending.slice(pos + 1);
      if (message.method === "initialize") {
        initializes++;
        socket.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {
          protocolVersion: message.params.protocolVersion, capabilities: { tools: {} },
          serverInfo: { name: "native-bridge-broker", version: "1" }
        } }) + "\n");
      } else if (message.method === "tools/list") {
        lists++;
        socket.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { tools: [] } }) + "\n");
      } else if (message.method !== "notifications/initialized") {
        invalid = true;
        socket.destroy();
      }
    }
  });
});
server.on("error", error => { process.stderr.write(`${error.message}\n`); process.exit(1); });
server.listen(socketPath, () => {
  chownSync(socketPath, 0, Number(forwarderGid));
  chmodSync(socketPath, 0o660);
  process.setgroups([]);
  process.setgid(Number(brokerGid));
  process.setuid(Number(brokerUid));
  process.send?.({ kind: "ready" });
});
process.on("message", message => {
  if (message?.kind === "snapshot") {
    process.send?.({ kind: "snapshot", id: message.id, initializes, lists, invalid });
  }
});
