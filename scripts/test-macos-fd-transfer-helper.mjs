#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";

const dir = await mkdtemp("/private/tmp/sgw-fd-probe-");
const helper = path.join(dir, "probe");
const brokerPath = path.join(dir, "broker.sock");
const rendezvous = path.join(dir, "shared.sock");
let broker;
const socketErrors = [];

function runHelper(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, args, { env: {}, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let errors = "";
    child.stdout.on("data", chunk => { output += String(chunk); });
    child.stderr.on("data", chunk => { errors += String(chunk); });
    child.once("error", reject);
    child.once("close", code => {
      if (code !== 0 || errors) reject(new Error(`Native ${args[0]} helper failed: ${errors || code}`));
      else resolve(output.trim());
    });
  });
}

try {
  execFileSync("/usr/bin/clang", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
    "-o", helper, "scripts/macos-agent-fd-transfer-probe.c"], { stdio: "pipe" });
  execFileSync(helper, ["self-test"], { stdio: "pipe" });
  let accepted = false;
  broker = createServer(socket => {
    let frame = "";
    socket.on("error", error => { socketErrors.push(error); });
    socket.on("data", chunk => {
      frame += String(chunk);
      if (frame === "XFER-START-V1\n") socket.write("XFER-READY-V1\n");
      else if (frame === "XFER-START-V1\nXFER-USE-V1\n") {
        accepted = true;
        socket.end("XFER-ACK-V1\n");
      }
    });
  });
  await new Promise((resolve, reject) => {
    broker.once("error", reject);
    broker.listen(brokerPath, resolve);
  });
  const recipient = runHelper(["recv", rendezvous]);
  const donor = runHelper(["send", rendezvous, brokerPath]);
  const [received, sent] = await Promise.all([recipient, donor]);
  if (received !== "used" || sent !== "sent" || !accepted) {
    throw new Error(`Descriptor transfer failed its local control: donor=${sent}, recipient=${received}.`);
  }
} finally {
  if (broker) await new Promise(resolve => broker.close(resolve));
  await rm(dir, { recursive: true, force: true });
}
const unexpected = socketErrors.find(error => error.code !== "EPIPE");
if (unexpected) throw unexpected;
process.stdout.write("Native SCM_RIGHTS helper passed a connected Unix socket in a local control.\n");
