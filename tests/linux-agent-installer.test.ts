import { describe, expect, it, vi } from "vitest";
import { buildModelRelayAction } from "../src/model-relay-action.js";
import { LinuxManagedUnitInstaller, assertApprovedLinuxManagedRelay,
  linuxManagedInstallPayloadMaxBytes, linuxManagedApprovalReaderArgs, readRootLinuxManagedInstallPlan,
  type LinuxManagedInstallHost, type LinuxManagedInstallPlan } from "../src/linux-agent-installer.js";
import type { RequestRecord } from "../src/types.js";

const unsafeEnv = "NODE_OPTIONS NODE_PATH NODE_TLS_REJECT_UNAUTHORIZED LD_PRELOAD LD_LIBRARY_PATH " +
  "LD_AUDIT OPENSSL_CONF SSL_CERT_FILE SSL_CERT_DIR GLIBC_TUNABLES MALLOC_CHECK_ MALLOC_PERTURB_ TZDIR";

function setup(sessionId = "agent-one", uid = 230101, gid = 230102): LinuxManagedInstallPlan {
  const plan = { sessionId, uid, gid, brokerUid: 230100,
    rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
    brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
    modelRelaySocket: `/run/s-gw/agents/${sessionId}/model.sock`,
    executable: "/usr/bin/agent", args: [], launchGate: true, activatedSocket: true,
    isolatedSharedMemory: true, serializedLifecycle: true, sealedStdio: true,
    supervisedControlUnit: true, restrictedSocketFamilies: true, requirePtracePolicy: true,
    logicalAgentId: sessionId, identityGeneration: uid.toString(16).padStart(32, "a") };
  const config = { name: `Managed ${sessionId}`, leaseDir: "/run/s-gw/managed-leases", plan,
    relay: { grant: { handle: "s-gw:api-token:fixture", provider: "anthropic" as const,
      routes: ["POST /v1/messages"], ttlMs: 30_000, payloadProfile: "strict" as const } } };
  const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
  return { config, brokerGid: 230103,
    control: { unitFile: "/run/systemd/system/s-gw-agent-control.service",
      runtimeRoot: "/usr/libexec/s-gw", preflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
      node: "/usr/libexec/s-gw/node", entry: "/usr/libexec/s-gw/control/linux-agent-control.js",
      brokerUid: 230100, brokerGid: 230103 },
    record: { plan, brokerUnit, brokerUnitFile: `/run/systemd/system/${brokerUnit}`,
      mcpSocketUnitFile: `/run/systemd/system/s-gw-managed-mcp-${sessionId}.socket`,
      modelRelaySocketUnitFile: `/run/systemd/system/s-gw-managed-model-${sessionId}.socket`,
      brokerEntry: "/usr/libexec/s-gw/dist/linux-managed-mcp.js",
      brokerConfig: `/run/s-gw/${sessionId}.json`,
      brokerNode: "/usr/libexec/s-gw/node", brokerRuntimeRoot: "/usr/libexec/s-gw",
      brokerPreflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
      brokerEnvironmentFile: "/run/s-gw/broker.env", brokerCa: null } };
}

function approved(input: LinuxManagedInstallPlan, requestId = "req_approved"): RequestRecord {
  const now = new Date().toISOString();
  return { id: requestId, handle: input.config.relay!.grant.handle,
    reason: "Managed relay", agentName: input.config.name, agentSource: "managed-peer",
    principalId: `linux:managed:${input.record.plan.identityGeneration}`,
    agentSessionId: input.record.plan.sessionId,
    action: buildModelRelayAction(input.config.relay!.grant), state: "approved",
    approvalSource: "manual", approvedAt: now, createdAt: now, updatedAt: now };
}

interface FakeFile { kind: "file" | "directory" | "socket" | "other"; uid: number; gid: number;
  mode: number; nlink: number; size: number; dev: number; ino: number; text?: string }

class Host implements LinuxManagedInstallHost {
  files = new Map<string, FakeFile>();
  active = new Set<string>();
  actions: string[] = [];
  failStart?: string;
  failStop?: string;
  badRealpath?: string;
  controlProperties = new Map<string, string>();
  controlSocketReadsUntilReady = 0;
  controlSocketMode = 0o660;
  controlReadbacks = 0;
  controlInvocationFlipAfter = Number.POSITIVE_INFINITY;
  nextIno = 10;
  constructor(readonly input: LinuxManagedInstallPlan) {
    for (const dir of ["/", "/run", "/run/systemd", "/run/systemd/system", "/run/s-gw",
      "/usr", "/usr/libexec", "/usr/libexec/s-gw", "/usr/libexec/s-gw/control",
      "/usr/libexec/s-gw/dist", "/var", "/var/lib"]) {
      this.add(dir, "directory", "", 0, 0, 0o755);
    }
    for (const filename of [input.control.node, input.control.entry, input.control.preflight,
      input.record.brokerNode, input.record.brokerEntry, input.record.brokerPreflight]) {
      this.add(filename, "file", "trusted runtime", 0, 0, 0o755);
    }
    this.add(input.record.brokerEnvironmentFile, "file", "SGW_HOME=/trusted\n", 0, 0, 0o600);
  }
  add(filename: string, kind: FakeFile["kind"], text: string, uid: number, gid: number, mode: number) {
    const ino = ++this.nextIno;
    this.files.set(filename, { kind, uid, gid, mode, nlink: 1, size: text.length,
      dev: 1, ino, text });
    return { filename, dev: 1, ino };
  }
  async assertRoot() {}
  async file(filename: string) {
    if (this.active.has("s-gw-agent-control.service") &&
        ["/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock"].includes(filename) &&
        !this.files.has(filename) && this.controlSocketReadsUntilReady > 0) {
      this.controlSocketReadsUntilReady--;
      if (this.controlSocketReadsUntilReady === 0) this.publishControlSockets();
    }
    return this.files.get(filename);
  }
  private publishControlSockets() {
    this.add("/run/s-gw/agent-control.sock", "socket", "", 0,
      this.input.brokerGid, this.controlSocketMode);
    this.add("/run/s-gw/agent-prepare.sock", "socket", "", 0, 0, 0o600);
  }
  async realpath(filename: string) { return filename === this.badRealpath ? "/different" : filename; }
  async read(filename: string) {
    const item = this.files.get(filename);
    if (!item || item.kind !== "file") throw new Error("No fixture file");
    return item.text || "";
  }
  async ensureDirectory(filename: string, uid: number, gid: number, mode: number) {
    if (this.files.has(filename)) return false;
    this.add(filename, "directory", "", uid, gid, mode);
    return true;
  }
  async publish(filename: string, content: string, uid: number, gid: number, mode: number) {
    if (this.files.has(filename)) throw new Error("Fixture destination exists");
    return this.add(filename, "file", content, uid, gid, mode);
  }
  async replace(filename: string, before: { dev: number; ino: number },
    content: string, uid: number, gid: number, mode: number) {
    const old = this.files.get(filename);
    if (!old || old.dev !== before.dev || old.ino !== before.ino) throw new Error("Fixture inode changed");
    return this.add(filename, "file", content, uid, gid, mode);
  }
  async remove(file: { filename: string; dev: number; ino: number }) {
    const old = this.files.get(file.filename);
    if (!old || old.dev !== file.dev || old.ino !== file.ino) throw new Error("Fixture rollback inode changed");
    this.files.delete(file.filename);
  }
  async account(uid: number) {
    return uid === this.input.record.plan.uid
      ? { gid: this.input.record.plan.gid, groups: [this.input.record.plan.gid] }
      : { gid: this.input.brokerGid, groups: [this.input.brokerGid] };
  }
  private socketUnit(unit: string, model: boolean): string[] {
    const { record } = this.input;
    const file = model ? record.modelRelaySocketUnitFile! : record.mcpSocketUnitFile;
    return ["Id=" + unit, `LoadState=${this.files.has(file) ? "loaded" : "not-found"}`,
      `ActiveState=${this.active.has(unit) ? "active" : "inactive"}`, `FragmentPath=${file}`,
      "DropInPaths=", `Triggers=${record.brokerUnit}`, "BindsTo=s-gw-agent-control.service",
      "After=s-gw-agent-control.service", "SocketUser=root", `SocketGroup=${record.plan.gid}`,
      "SocketMode=0660", "DirectoryMode=0711", "PassCredentials=yes", "Accept=no",
      "RemoveOnStop=no", `FileDescriptorName=s-gw-${model ? "model" : "agent"}-${record.plan.sessionId}`];
  }
  private brokerUnit(): string[] {
    const r = this.input.record;
    const unit = r.brokerUnit;
    const args = `${r.brokerRuntimeRoot} ${r.brokerNode} ${r.brokerEntry} ${r.brokerConfig} - ${r.brokerEnvironmentFile}`;
    return [`Id=${unit}`, `LoadState=${this.files.has(r.brokerUnitFile) ? "loaded" : "not-found"}`,
      `ActiveState=${this.active.has(unit) ? "active" : "inactive"}`, `FragmentPath=${r.brokerUnitFile}`,
      "DropInPaths=", `User=${r.plan.brokerUid}`, `Group=${this.input.brokerGid}`,
      "BindsTo=s-gw-agent-control.service", "After=s-gw-agent-control.service",
      `EnvironmentFiles=${r.brokerEnvironmentFile} (ignore_errors=no)`, `UnsetEnvironment=${unsafeEnv}`,
      `ExecStartPre={ path=${r.brokerPreflight} ; argv[]=${r.brokerPreflight} verify ${args} ; ignore_errors=no ; status=0 }`,
      `ExecStart={ path=${r.brokerPreflight} ; argv[]=${r.brokerPreflight} verify-exec ${args} -- ${r.brokerConfig} ; ignore_errors=no ; status=0 }`,
      `MainPID=${this.active.has(unit) ? "421" : "0"}`,
      `ControlGroup=${this.active.has(unit) ? `/system.slice/${unit}` : ""}`,
      `InvocationID=${this.active.has(unit) ? "a".repeat(32) : ""}`];
  }
  private controlUnit(): string[] {
    const c = this.input.control;
    const args = `${c.runtimeRoot} ${c.node} ${c.entry} ${c.unitFile} - -`;
    const unit = "s-gw-agent-control.service";
    if (this.active.has(unit)) this.controlReadbacks++;
    return [`Id=${unit}`, `LoadState=${this.files.has(c.unitFile) ? "loaded" : "not-found"}`,
      `ActiveState=${this.active.has(unit) ? "active" : "inactive"}`, `FragmentPath=${c.unitFile}`,
      "DropInPaths=", "User=root", "Group=root", "EnvironmentFiles=",
      "MainPID=" + (this.active.has(unit) ? "420" : "0"),
      "InvocationID=" + (this.active.has(unit)
        ? (this.controlReadbacks >= this.controlInvocationFlipAfter ? "c" : "b").repeat(32) : ""),
      `UnsetEnvironment=${unsafeEnv} NODE_EXTRA_CA_CERTS`,
      `ExecStartPre={ path=${c.preflight} ; argv[]=${c.preflight} verify ${args} ; ignore_errors=no ; status=0 }`,
      `ExecStart={ path=${c.preflight} ; argv[]=${c.preflight} verify-exec ${args} -- --serve ${c.brokerUid} ${c.brokerGid} ; ignore_errors=no ; status=0 }`];
  }
  async unit(unit: string, _fields: string[]) {
    let lines: string[];
    if (unit === "s-gw-agent-control.service") {
      lines = this.controlUnit().map(line => {
        const key = line.slice(0, line.indexOf("="));
        const override = this.controlProperties.get(key);
        return override === undefined ? line : `${key}=${override}`;
      });
    }
    else if (unit === this.input.record.brokerUnit) lines = this.brokerUnit();
    else if (unit === `s-gw-managed-mcp-${this.input.record.plan.sessionId}.socket`) {
      lines = this.socketUnit(unit, false);
    } else if (unit === `s-gw-managed-model-${this.input.record.plan.sessionId}.socket`) {
      lines = this.socketUnit(unit, true);
    } else lines = [`Id=${unit}`, "LoadState=not-found", "ActiveState=inactive"];
    return lines.join("\n") + "\n";
  }
  async action(action: "daemon-reload" | "start" | "stop", unit?: string) {
    this.actions.push(`${action}:${unit || ""}`);
    if (action === "start" && unit) {
      this.active.add(unit);
      if (unit === "s-gw-agent-control.service" && this.controlSocketReadsUntilReady === 0) {
        this.publishControlSockets();
      }
      if (unit.endsWith(".socket")) {
        const model = unit.includes("managed-model");
        const filename = model ? this.input.record.plan.modelRelaySocket! : this.input.record.plan.brokerSocket;
        this.add(filename, "socket", "", 0, this.input.record.plan.gid, 0o660);
      }
      if (this.failStart === unit) throw new Error(`Fixture start failed: ${unit}`);
    }
    if (action === "stop" && unit) {
      if (this.failStop === unit) throw new Error(`Fixture stop failed: ${unit}`);
      this.active.delete(unit);
      if (unit === "s-gw-agent-control.service") {
        this.files.delete("/run/s-gw/agent-control.sock");
        this.files.delete("/run/s-gw/agent-prepare.sock");
      }
      if (unit.endsWith(".socket")) {
        const filename = unit.includes("managed-model") ? this.input.record.plan.modelRelaySocket! :
          this.input.record.plan.brokerSocket;
        this.files.delete(filename);
      }
    }
  }
}

describe.skipIf(process.platform === "win32")("Linux managed unit installer", () => {
  it("accepts the largest escaped model grant within the approval reader bound", () => {
    const input = setup();
    input.config.relay!.grant = {
      handle: "s-gw:api-token:fixture", provider: "openai", routes: ["POST /v1/responses"],
      ttlMs: 30_000, payloadProfile: "strict",
      allowedModels: Array.from({ length: 64 }, (_, i) => "\ud800".repeat(253) + `-${String(i).padStart(2, "0")}`),
      allowedBetaValues: Array.from({ length: 16 }, (_, i) => "\ud800".repeat(509) + `-${String(i).padStart(2, "0")}`),
      organizationId: "\ud800".repeat(512), projectId: "\ud800".repeat(512)
    };
    const request = approved(input);
    assertApprovedLinuxManagedRelay({ ...input.config,
      relay: { ...input.config.relay!, requestId: request.id } }, request);
    const readerOutput = { ...request, reason: "" };
    expect(Buffer.byteLength(JSON.stringify(readerOutput))).toBeLessThan(linuxManagedInstallPayloadMaxBytes);
    const planText = JSON.stringify(input);
    expect(Buffer.byteLength(planText)).toBeLessThan(linuxManagedInstallPayloadMaxBytes);
    const host = new Host(input);
    host.add("/run/s-gw/max-plan.json", "file", planText, 0, 0, 0o600);
    return expect(readRootLinuxManagedInstallPlan("/run/s-gw/max-plan.json", host)).resolves.toEqual(input);
  });

  it("pins a broker-owned approval reader to the staged runtime and store environment", async () => {
    const input = setup();
    const host = new Host(input);
    host.add("/run/s-gw/install.json", "file", JSON.stringify(input), 0, 0, 0o600);
    expect(await readRootLinuxManagedInstallPlan("/run/s-gw/install.json", host)).toEqual(input);
    const args = linuxManagedApprovalReaderArgs(input, "req_approved",
      `s-gw-approval-${"a".repeat(32)}`);
    expect(args).toContain(`--property=User=${input.record.plan.brokerUid}`);
    expect(args).toContain(`--property=Group=${input.brokerGid}`);
    expect(args).toContain(`--property=EnvironmentFile=${input.record.brokerEnvironmentFile}`);
    expect(args).toContain("--property=PrivateNetwork=yes");
    expect(args.slice(-9)).toEqual([input.record.brokerRuntimeRoot, input.record.brokerNode,
      "/usr/libexec/s-gw/dist/linux-managed-approval-reader.js", input.record.brokerConfig,
      "-", input.record.brokerEnvironmentFile, "--", input.record.brokerConfig, "req_approved"]);
    host.files.get("/run/s-gw/install.json")!.mode = 0o644;
    await expect(readRootLinuxManagedInstallPlan("/run/s-gw/install.json", host))
      .rejects.toThrow(/Untrusted Linux provisioner file/);
  });

  it("waits for both verified root control sockets before staging completes", async () => {
    const input = setup();
    const host = new Host(input);
    host.controlSocketReadsUntilReady = 2;
    await new LinuxManagedUnitInstaller(host).stage(input);
    expect(host.files.get("/run/s-gw/agent-control.sock"))
      .toMatchObject({ kind: "socket", uid: 0, gid: input.brokerGid, mode: 0o660 });
    expect(host.files.get("/run/s-gw/agent-prepare.sock"))
      .toMatchObject({ kind: "socket", uid: 0, gid: 0, mode: 0o600 });
  });

  it("stops control and rolls back when a control socket has unsafe permissions", async () => {
    const input = setup();
    const host = new Host(input);
    host.controlSocketMode = 0o666;
    await expect(new LinuxManagedUnitInstaller(host).stage(input))
      .rejects.toThrow(/untrusted root control socket/);
    expect(host.actions).toContain("stop:s-gw-agent-control.service");
    expect(host.active.size).toBe(0);
    expect(host.files.has(input.control.unitFile)).toBe(false);
    expect(host.files.has("/run/s-gw/agent-control.sock")).toBe(false);
  });

  it("times out and rolls back if root control sockets never appear", async () => {
    const input = setup();
    const host = new Host(input);
    host.controlSocketReadsUntilReady = Number.POSITIVE_INFINITY;
    let now = 0;
    const clock = vi.spyOn(Date, "now").mockImplementation(() => { now += 6000; return now; });
    try {
      await expect(new LinuxManagedUnitInstaller(host).stage(input))
        .rejects.toThrow(/sockets did not become ready/);
    } finally {
      clock.mockRestore();
    }
    expect(host.actions).toContain("stop:s-gw-agent-control.service");
    expect(host.active.size).toBe(0);
    expect(host.files.has(input.control.unitFile)).toBe(false);
    expect(host.files.has(input.record.brokerConfig)).toBe(false);
    expect(host.files.has("/run/s-gw/agent-prepare.sock")).toBe(false);
  });

  it("rejects a restarted root control while waiting for its sockets", async () => {
    const input = setup();
    const host = new Host(input);
    host.controlSocketReadsUntilReady = 2;
    host.controlInvocationFlipAfter = 2;
    await expect(new LinuxManagedUnitInstaller(host).stage(input))
      .rejects.toThrow(/changed while opening its sockets/);
    expect(host.actions).toContain("stop:s-gw-agent-control.service");
    expect(host.files.has(input.control.unitFile)).toBe(false);
  });

  it("stages an unsealed root bundle and activates sockets only after exact approval", async () => {
    const input = setup();
    const host = new Host(input);
    const installer = new LinuxManagedUnitInstaller(host);
    await installer.stage(input);
    expect(host.active.has("s-gw-agent-control.service")).toBe(true);
    expect([...host.active]).toEqual(["s-gw-agent-control.service"]);
    expect(host.files.has(input.record.plan.brokerSocket)).toBe(false);
    expect(await host.read(input.record.brokerConfig)).not.toContain("requestId");
    expect(host.files.get(input.record.brokerConfig)).toMatchObject({ uid: 0,
      gid: input.brokerGid, mode: 0o640, nlink: 1 });
    expect(host.files.get(`/run/s-gw/agent-plans/${input.record.plan.sessionId}.json`))
      .toMatchObject({ uid: 0, mode: 0o600 });
    await installer.activate(input, "req_approved", async () => approved(input));
    expect(JSON.parse(await host.read(input.record.brokerConfig)).relay.requestId).toBe("req_approved");
    expect(host.actions.filter(action => action.startsWith("start:"))).toEqual([
      "start:s-gw-agent-control.service",
      `start:s-gw-managed-mcp-${input.record.plan.sessionId}.socket`,
      `start:s-gw-managed-model-${input.record.plan.sessionId}.socket`,
      `start:${input.record.brokerUnit}`]);
    expect(host.files.get(input.record.plan.modelRelaySocket!)).toMatchObject({ kind: "socket",
      uid: 0, gid: input.record.plan.gid, mode: 0o660 });
  });

  it("rejects pending, mismatched, stale, and nonmanual approvals before a socket starts", async () => {
    const input = setup();
    const host = new Host(input);
    const installer = new LinuxManagedUnitInstaller(host);
    await installer.stage(input);
    const base = approved(input);
    for (const change of [{ state: "pending" as const }, { principalId: "linux:managed:other" },
      { approvalSource: "policy" as const }, { approvedAt: "2020-01-01T00:00:00.000Z" },
      { handle: "s-gw:api-token:other" }]) {
      await expect(installer.activate(input, base.id, async () => ({ ...base, ...change })))
        .rejects.toThrow();
      expect(host.files.has(input.record.plan.brokerSocket)).toBe(false);
      expect(await host.read(input.record.brokerConfig)).not.toContain("requestId");
    }
    expect(host.actions.some(action => action.includes(".socket"))).toBe(false);
    expect(() => assertApprovedLinuxManagedRelay({ ...input.config,
      relay: { ...input.config.relay!, requestId: "req_approved" } }, base)).not.toThrow();
  });

  it("refuses unsafe parent paths and a different existing unit", async () => {
    const input = setup();
    const unsafe = new Host(input);
    unsafe.badRealpath = "/run/systemd/system";
    await expect(new LinuxManagedUnitInstaller(unsafe).stage(input)).rejects.toThrow(/parent/);
    const collision = new Host(input);
    collision.add(input.record.brokerUnitFile, "file", "ExecStart=/bin/sh\n", 0, 0, 0o644);
    await expect(new LinuxManagedUnitInstaller(collision).stage(input))
      .rejects.toThrow(/different content/);
    expect(collision.actions.some(action => action.startsWith("start:"))).toBe(false);
  });

  it("fails closed on a concurrent or stale root install lock", async () => {
    const input = setup();
    const host = new Host(input);
    const installer = new LinuxManagedUnitInstaller(host);
    const lock = "/run/s-gw/managed-install.lock";
    host.add(lock, "file", "another installer\n", 0, 0, 0o600);
    await expect(installer.stage(input)).rejects.toThrow(/destination exists/);
    expect(host.actions).toEqual([]);
    host.files.delete(lock);
    await installer.stage(input);
    host.add(lock, "file", "stale installer\n", 0, 0, 0o600);
    await expect(installer.activate(input, "req_approved", async () => approved(input)))
      .rejects.toThrow(/destination exists/);
    expect(host.files.has(input.record.plan.brokerSocket)).toBe(false);
    expect(await host.read(input.record.brokerConfig)).not.toContain("requestId");
  });

  it("refuses an already-active root control process before publishing units", async () => {
    const input = setup();
    const host = new Host(input);
    host.active.add("s-gw-agent-control.service");
    await expect(new LinuxManagedUnitInstaller(host).stage(input))
      .rejects.toThrow(/active or uncertain unit/);
    expect(host.actions).toEqual([]);
    expect(host.files.has(input.record.brokerUnitFile)).toBe(false);
    expect(host.files.has(`/run/s-gw/agent-plans/${input.record.plan.sessionId}.json`)).toBe(false);
    expect(host.files.has("/run/s-gw/managed-install.lock")).toBe(false);
  });

  it("checks inactive root control properties before allowing systemd to start it", async () => {
    const input = setup();
    for (const [property, value] of [
      ["DropInPaths", "/run/systemd/system/s-gw-agent-control.service.d/evil.conf"],
      ["ExecStart", "{ path=/bin/sh ; argv[]=/bin/sh -c evil ; ignore_errors=no ; status=0 }"]
    ]) {
      const host = new Host(input);
      host.controlProperties.set(property, value);
      await expect(new LinuxManagedUnitInstaller(host).stage(input)).rejects.toThrow();
      expect(host.actions).not.toContain("start:s-gw-agent-control.service");
      expect(host.files.has(input.control.unitFile)).toBe(false);
    }
  });

  it("rejects a valid plan that exceeds the root control record limit before writing", async () => {
    const input = setup();
    input.record.plan.args = Array(9).fill("x".repeat(4096));
    const host = new Host(input);
    await expect(new LinuxManagedUnitInstaller(host).stage(input))
      .rejects.toThrow(/root control frame limit/);
    expect(host.actions).toEqual([]);
    expect(host.files.has(`/var/lib/s-gw/agent-identities/generation-${input.record.plan.identityGeneration}.json`))
      .toBe(false);
    expect(host.files.has(`/run/s-gw/agent-plans/${input.record.plan.sessionId}.json`)).toBe(false);
  });

  it("rolls back a failed socket start and leaves no unsealed listener", async () => {
    const input = setup();
    const host = new Host(input);
    const installer = new LinuxManagedUnitInstaller(host);
    await installer.stage(input);
    host.failStart = `s-gw-managed-model-${input.record.plan.sessionId}.socket`;
    await expect(installer.activate(input, "req_approved", async () => approved(input)))
      .rejects.toThrow(/Fixture start failed/);
    expect([...host.active]).toEqual(["s-gw-agent-control.service"]);
    expect(host.files.has(input.record.plan.brokerSocket)).toBe(false);
    expect(host.files.has(input.record.plan.modelRelaySocket!)).toBe(false);
    expect(await host.read(input.record.brokerConfig)).not.toContain("requestId");
  });

  it("retains a sealed config when uncertain teardown prevents safe rollback", async () => {
    const input = setup();
    const host = new Host(input);
    const installer = new LinuxManagedUnitInstaller(host);
    await installer.stage(input);
    host.failStart = `s-gw-managed-model-${input.record.plan.sessionId}.socket`;
    host.failStop = `s-gw-managed-mcp-${input.record.plan.sessionId}.socket`;
    await expect(installer.activate(input, "req_approved", async () => approved(input)))
      .rejects.toThrow(/teardown is uncertain/);
    expect(JSON.parse(await host.read(input.record.brokerConfig)).relay.requestId).toBe("req_approved");
  });
});
