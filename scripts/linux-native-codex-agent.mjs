import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { startLinuxAgentLocalModelForwarder } from "/usr/libexec/s-gw/agent-local-model-forwarder.js";

const resultPath = "/workspace/codex-result.json";
const placeholder = "synthetic-client-placeholder";
const model = "gpt-5.3-codex";

function directConnect(host, port) {
  return new Promise(resolve => {
    const socket = connect({ host, port });
    const done = allowed => { socket.destroy(); resolve(allowed); };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    socket.setTimeout(1500, () => done(false));
  });
}

async function runCodex(port) {
  const args = ["exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check",
    "--sandbox", "read-only", "--json", "-m", model,
    "-c", 'model_provider="fixture"',
    "-c", 'model_providers.fixture.name="Synthetic Fixture"',
    "-c", `model_providers.fixture.base_url="http://127.0.0.1:${port}/v1"`,
    "-c", 'model_providers.fixture.env_key="OPENAI_API_KEY"',
    "-c", 'model_providers.fixture.wire_api="responses"',
    "-c", "model_providers.fixture.requires_openai_auth=false",
    "-c", "model_providers.fixture.supports_websockets=false",
    "-c", 'web_search="disabled"',
    "-c", "features.multi_agent=false",
    "Reply exactly HELLO."];
  const child = spawn("/usr/bin/codex", args, {
    cwd: "/workspace", stdio: ["ignore", "pipe", "pipe"], env: {
      PATH: "/usr/bin", HOME: "/workspace", CODEX_HOME: "/workspace/codex",
      TMPDIR: "/workspace", LANG: "C.UTF-8", OPENAI_API_KEY: placeholder
    }
  });
  const finished = new Promise((resolve, reject) => {
    let stdout = "", stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 45_000);
    child.stdout.on("data", part => {
      stdout += part;
      if (stdout.length > 2_000_000) child.kill("SIGKILL");
    });
    child.stderr.on("data", part => {
      stderr += part;
      if (stderr.length > 2_000_000) child.kill("SIGKILL");
    });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ pid: child.pid, code, signal, stdout, stderr });
    });
  });
  try {
    await writeFile("/workspace/codex-pid", `${child.pid}\n`, { flag: "wx", mode: 0o600 });
  } catch (error) {
    child.kill("SIGKILL");
    await finished.catch(() => {});
    throw error;
  }
  return finished;
}

let forwarder;
try {
  const modelHost = process.argv[2];
  const canaryHost = process.argv[3];
  const canaryPort = Number(process.argv[4]);
  if (!/^198\.20\.\d{1,3}\.\d{1,3}$/.test(modelHost) ||
      !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(canaryHost) ||
      !Number.isSafeInteger(canaryPort) || canaryPort < 1 || canaryPort > 65535) {
    throw new Error("Invalid native Codex egress probe arguments.");
  }
  const modelDirect = await directConnect(modelHost, 443);
  const canaryDirect = await directConnect(canaryHost, canaryPort);
  if (modelDirect || canaryDirect) throw new Error("Agent reached a broker-only network address.");
  forwarder = await startLinuxAgentLocalModelForwarder();
  const port = Number(new URL(forwarder.address).port);
  await writeFile("/workspace/forwarder-ready", `${port}\n`, { flag: "wx", mode: 0o600 });
  const result = await runCodex(port);
  await writeFile(resultPath, JSON.stringify({ ...result, directDenied: true }) + "\n",
    { flag: "wx", mode: 0o600 });
} catch (error) {
  await writeFile(resultPath, JSON.stringify({ error: String(error) }) + "\n",
    { flag: "wx", mode: 0o600 }).catch(() => {});
} finally {
  await forwarder?.close().catch(() => {});
}

setInterval(() => {}, 60_000);
