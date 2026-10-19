import { chmod, link, mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SecretStore } from "../src/store.js";
import { brokerChildEnvironment, ownedModuleCommand, startSandboxBroker } from "../src/sandbox-broker.js";

let root = "";
const originalEnv = { ...process.env };

afterEach(async () => {
  process.env = { ...originalEnv };
  if (root) await rm(root, { recursive: true, force: true });
  root = "";
});

async function fixture() {
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-broker-env-")));
  const workspace = path.join(root, "workspace");
  const trusted = path.join(root, "trusted");
  const home = path.join(root, "store");
  const recovery = path.join(root, "recovery");
  await mkdir(workspace);
  await mkdir(trusted);
  const ca = path.join(trusted, "corporate-ca.pem");
  const op = path.join(trusted, "op");
  await writeFile(ca, "synthetic CA fixture");
  await writeFile(op, "synthetic CLI fixture");
  await chmod(ca, 0o600);
  await chmod(op, 0o700);
  return { workspace, trusted, home, recovery, ca, op };
}

describe.skipIf(process.platform === "win32")("trusted sandbox broker environment", () => {
  it("keeps the current environment behavior unless strict mode is selected", async () => {
    const { workspace, home } = await fixture();
    const env = brokerChildEnvironment(workspace, home, "Codex", [], { inheritedEnv: {
      PATH: "/usr/bin:/bin",
      npm_config_password: "legacy private registry value",
      NODE_OPTIONS: "--require=/missing/preload.cjs",
      SGW_SANDBOX_BROKER_TOKEN: "agent capability",
      LD_PRELOAD: "/missing/library.so"
    } });

    expect(env.npm_config_password).toBe("legacy private registry value");
    expect(env.NODE_OPTIONS).toBeUndefined();
    expect(env.SGW_SANDBOX_BROKER_TOKEN).toBeUndefined();
    expect(env.LD_PRELOAD).toBeUndefined();
    expect(env.SGW_SANDBOX_AGENT_NAME).toBe("Codex");
    expect(env.SGW_SANDBOX_UPLOAD_WORKSPACE).toBeUndefined();
  });

  it("passes only validated runtime, CA, Keychain, recovery and 1Password settings", async () => {
    const { workspace, home, recovery, ca, op } = await fixture();
    const inherited = {
      HOME: workspace,
      PATH: `${workspace}:/usr/bin:/bin`,
      SGW_RECOVERY_HOME: recovery,
      SGW_MASTER_PASSPHRASE: "synthetic passphrase",
      SGW_SECRET_BACKEND: "local",
      SGW_EXECUTION_ENGINE: "rust",
      SGW_KEYCHAIN_SERVICE: "fixture.keychain.service",
      SGW_KEYCHAIN_ACCOUNT: "fixture account",
      SGW_SECRET_KEYCHAIN_SERVICE: "fixture.secret.service",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_OP_CLI: op,
      OP_SERVICE_ACCOUNT_TOKEN: "synthetic op token",
      OP_CONNECT_HOST: "https://connect.example.test/",
      OP_CONNECT_TOKEN: "synthetic connect token",
      OP_SESSION_fixture: "synthetic op session",
      NODE_EXTRA_CA_CERTS: ca,
      SSL_CERT_FILE: ca,
      SGW_TEST_MODE: "1",
      SGW_ALLOW_NO_CGROUP: "1",
      SGW_SSH_CLI: path.join(workspace, "fake-ssh"),
      SGW_SANDBOX_BROKER_TOKEN: "agent capability",
      NODE_OPTIONS: "--require=/missing/preload.cjs",
      NODE_PATH: workspace,
      DYLD_INSERT_LIBRARIES: "/missing/library.dylib",
      LD_PRELOAD: "/missing/library.so",
      ARBITRARY_AGENT_VALUE: "untrusted"
    };
    const env = brokerChildEnvironment(workspace, home, "Claude Code", [path.join(root, "private")], {
      strictEnv: true, inheritedEnv: inherited
    });

    expect(env.HOME).toBe(os.userInfo().homedir);
    expect(env.PATH).not.toContain(workspace);
    expect(env.SGW_HOME).toBe(home);
    expect(env.SGW_RECOVERY_HOME).toBe(recovery);
    expect(env.SGW_MASTER_PASSPHRASE).toBe(inherited.SGW_MASTER_PASSPHRASE);
    expect(env.SGW_SECRET_BACKEND).toBe("local");
    expect(env.SGW_EXECUTION_ENGINE).toBe("rust");
    expect(env.SGW_KEYCHAIN_SERVICE).toBe(inherited.SGW_KEYCHAIN_SERVICE);
    expect(env.SGW_OP_CLI).toBe(op);
    expect(env.OP_SERVICE_ACCOUNT_TOKEN).toBe(inherited.OP_SERVICE_ACCOUNT_TOKEN);
    expect(env.OP_CONNECT_TOKEN).toBe(inherited.OP_CONNECT_TOKEN);
    expect(env.OP_SESSION_fixture).toBe(inherited.OP_SESSION_fixture);
    expect(env.NODE_EXTRA_CA_CERTS).toBe(ca);
    expect(env.SSL_CERT_FILE).toBe(ca);
    expect(env.SGW_SANDBOX_OPERATIONS_ONLY).toBe("1");
    expect(env.SGW_SANDBOX_AGENT_NAME).toBe("Claude Code");
    expect(JSON.parse(env.SGW_SANDBOX_DENY_READ || "[]")).toEqual([path.join(root, "private")]);
    for (const name of ["SGW_TEST_MODE", "SGW_ALLOW_NO_CGROUP", "SGW_SSH_CLI", "SGW_SANDBOX_BROKER_TOKEN",
      "NODE_OPTIONS", "NODE_PATH", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "ARBITRARY_AGENT_VALUE"]) {
      expect(env[name], name).toBeUndefined();
    }
  });

  it("passes the confined workspace for uploads only when the launcher selects it", async () => {
    const { workspace, home } = await fixture();
    const inheritedEnv = { PATH: "/usr/bin:/bin", SGW_SANDBOX_UPLOAD_WORKSPACE: path.dirname(workspace) };
    const without = brokerChildEnvironment(workspace, home, "Codex", [path.dirname(workspace)], { inheritedEnv });
    expect(without.SGW_SANDBOX_UPLOAD_WORKSPACE).toBeUndefined();
    const selected = brokerChildEnvironment(workspace, home, "Codex", [path.dirname(workspace)], {
      inheritedEnv, uploadWorkspace: workspace
    });
    expect(selected.SGW_SANDBOX_UPLOAD_WORKSPACE).toBe(workspace);
    expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
      inheritedEnv, uploadWorkspace: path.dirname(workspace)
    })).toThrow("must match");
  });

  it("rejects CA files and executable overrides inside the agent workspace", async () => {
    const { workspace, home, ca } = await fixture();
    const workspaceFile = path.join(workspace, "agent-controlled.pem");
    await writeFile(workspaceFile, "synthetic CA fixture");
    const alias = path.join(root, "ca-alias.pem");
    await symlink(workspaceFile, alias);

    for (const value of [workspaceFile, alias]) {
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true, inheritedEnv: { PATH: "/usr/bin", NODE_EXTRA_CA_CERTS: value }
      })).toThrow(/broker path/i);
    }
    expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
      strictEnv: true, inheritedEnv: { PATH: "/usr/bin", SGW_OP_CLI: workspaceFile, SSL_CERT_FILE: ca }
    })).toThrow(/broker path/i);
  });

  it("rejects a trusted file that has a writable hard link", async () => {
    const { workspace, home, ca } = await fixture();
    await link(ca, path.join(workspace, "same-ca.pem"));
    expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
      strictEnv: true,
      inheritedEnv: { NODE_EXTRA_CA_CERTS: ca }
    })).toThrow(/broker path/i);
  });

  it("rejects trusted inputs in additional agent-writable directories", async () => {
    const { workspace, trusted, home, ca, op } = await fixture();
    for (const inheritedEnv of [{ NODE_EXTRA_CA_CERTS: ca }, { SGW_OP_CLI: op }]) {
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        agentWritablePaths: [trusted],
        inheritedEnv
      })).toThrow(/broker path/i);
    }
    const env = brokerChildEnvironment(workspace, home, "Codex", [], {
      strictEnv: true,
      agentWritablePaths: [trusted],
      inheritedEnv: { PATH: `${trusted}:/usr/bin` }
    });
    expect(env.PATH).not.toContain(trusted);
  });

  it("accounts for the sandbox runtime's implicit writable paths", async () => {
    const { workspace, home } = await fixture();
    for (const recovery of [
      "/tmp/claude/recovery",
      path.join(os.userInfo().homedir, ".npm", "_logs", "recovery"),
      path.join(os.userInfo().homedir, ".claude", "debug", "recovery")
    ]) {
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        inheritedEnv: { SGW_RECOVERY_HOME: recovery }
      })).toThrow(/broker path/i);
    }
  });

  it("refuses to run the trusted MCP module from an agent-writable checkout", async () => {
    const { home } = await fixture();
    const modulePath = ownedModuleCommand("mcp-server").args.at(-1);
    expect(modulePath).toBeTruthy();
    await expect(startSandboxBroker(path.dirname(modulePath!), home, "Codex", [], {
      strictEnv: true,
      inheritedEnv: { PATH: process.env.PATH }
    })).rejects.toThrow(/trusted broker module/i);
  });

  it("keeps a local user session bus for Linux credential stores", async () => {
    const { workspace, trusted, home } = await fixture();
    const socketPath = path.join(trusted, "session-bus.sock");
    const fallbackPath = path.join(trusted, "backup-bus.sock");
    const server = createServer();
    const fallback = createServer();
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    await new Promise<void>((resolve, reject) => {
      fallback.once("error", reject);
      fallback.listen(fallbackPath, resolve);
    });
    try {
      const address = `unix:path=${socketPath}`;
      const env = brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        inheritedEnv: { DBUS_SESSION_BUS_ADDRESS: address }
      });
      expect(env.DBUS_SESSION_BUS_ADDRESS).toBe(address);
      const safeFallback = `${address},guid=${"a".repeat(32)};unix:path=${fallbackPath}`;
      expect(brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        inheritedEnv: { DBUS_SESSION_BUS_ADDRESS: safeFallback }
      }).DBUS_SESSION_BUS_ADDRESS).toBe(safeFallback);
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        agentWritablePaths: [trusted],
        inheritedEnv: { DBUS_SESSION_BUS_ADDRESS: address }
      })).toThrow(/session bus/i);
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true,
        inheritedEnv: { DBUS_SESSION_BUS_ADDRESS: "tcp:host=attacker.example.test" }
      })).toThrow(/session bus/i);
      for (const untrusted of [
        `${address},guid=${"a".repeat(32)};tcp:host=attacker.example.test`,
        `${address},path=${fallbackPath}`,
        `${address};unix:path=${workspace}/agent-bus.sock`,
        `${address},guid=${"a".repeat(32)};unix:abstract=agent-bus`
      ]) {
        expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
          strictEnv: true,
          inheritedEnv: { DBUS_SESSION_BUS_ADDRESS: untrusted }
        })).toThrow(/session bus/i);
      }
    } finally {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      await new Promise<void>((resolve, reject) => fallback.close(error => error ? reject(error) : resolve()));
    }
  });

  it("rejects unsafe recovery and malformed authority settings", async () => {
    const { workspace, home } = await fixture();
    for (const inheritedEnv of [
      { SGW_RECOVERY_HOME: workspace },
      { SGW_SECRET_BACKEND: "arbitrary" },
      { SGW_EXECUTION_ENGINE: "untrusted" },
      { OP_CONNECT_HOST: "http://attacker.example.test" },
      { SGW_ONEPASSWORD_TIMEOUT_MS: "-1" }
    ]) {
      expect(() => brokerChildEnvironment(workspace, home, "Codex", [], {
        strictEnv: true, inheritedEnv
      })).toThrow();
    }
  });

  it("serves restricted MCP through a child started with the strict environment", async () => {
    const { workspace, home, recovery } = await fixture();
    const passphrase = "synthetic broker test passphrase";
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = recovery;
    process.env.SGW_MASTER_PASSPHRASE = passphrase;
    process.env.SGW_DISABLE_KEYCHAIN = "1";
    process.env.SGW_ALLOW_NO_CGROUP = "1";
    const store = new SecretStore(home);
    await store.init();

    const broker = await startSandboxBroker(workspace, home, "Codex", [], {
      strictEnv: true,
      inheritedEnv: {
        PATH: process.env.PATH,
        SGW_RECOVERY_HOME: recovery,
        SGW_MASTER_PASSPHRASE: passphrase,
        SGW_DISABLE_KEYCHAIN: "1",
        SGW_TEST_MODE: "1",
        SGW_ALLOW_NO_CGROUP: "1",
        NODE_OPTIONS: "--require=/missing/hostile-preload.cjs",
        LD_PRELOAD: "/missing/hostile-library.so",
        DYLD_INSERT_LIBRARIES: "/missing/hostile-library.dylib"
      }
    });
    const entry = ownedModuleCommand("mcp-server");
    const client = new Client({ name: "Strict environment probe", version: "1" });
    try {
      await client.connect(new StdioClientTransport({ ...entry, env: {
        PATH: process.env.PATH,
        SGW_SANDBOX_BROKER_PORT: String(broker.port),
        SGW_SANDBOX_BROKER_TOKEN: broker.token
      }, stderr: "pipe" }));
      const tools = await client.listTools();
      expect(tools.tools.some((tool) => tool.name === "sgw_request_http")).toBe(true);
      expect(tools.tools.some((tool) => tool.name === "sgw_scan_file")).toBe(false);
    } finally {
      await client.close();
      await broker.close();
    }
  });
});
