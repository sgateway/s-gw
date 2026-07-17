import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startConsoleServer, type RunningConsoleServer } from "../src/console-server.js";
import { ReleaseChecker } from "../src/update-check.js";

const CHROME_CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  process.env.SGW_E2E_CHROME || ""
];

function findChrome(): string | undefined {
  return CHROME_CANDIDATES.find((p) => p && existsSync(p));
}

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const chromePath = findChrome();
const hasReactBuild = existsSync(path.join(repoRoot, "dist/console-ui/index.html"));
const describeBrowser = chromePath && hasReactBuild ? describe : describe.skip;

let tmpHome = "";
let profileDir = "";
let running: RunningConsoleServer | undefined;
let chrome: ChildProcess | undefined;
let cdp: Cdp | undefined;
let oldEnv: NodeJS.ProcessEnv;

beforeEach(async () => {
  oldEnv = { ...process.env };
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-react-browser-"));
  profileDir = await mkdtemp(path.join(os.tmpdir(), "sgw-react-chrome-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  delete process.env.SGW_MASTER_PASSPHRASE;
});

afterEach(async () => {
  cdp?.dispose();
  cdp = undefined;
  if (chrome) {
    const exited = new Promise<void>((resolve) => chrome?.once("exit", () => resolve()));
    chrome.kill("SIGKILL");
    await Promise.race([exited, delay(3000)]);
    chrome = undefined;
  }
  if (running) {
    await running.close();
    running = undefined;
  }
  process.env = oldEnv;
  await rm(tmpHome, { recursive: true, force: true }).catch(() => {});
  await rm(`${tmpHome}-recovery`, { recursive: true, force: true }).catch(() => {});
  await rm(profileDir, { recursive: true, force: true }).catch(() => {});
});

describeBrowser("React local console (real headless Chrome)", () => {
  it("adds and completely removes display-only demo data from the native menu", async () => {
    running = await startConsoleServer({ port: 0 });
    const url = new URL("overview", running.url);
    url.searchParams.set("native-shell", "1");
    const launched = await launchChrome(url.toString());
    cdp = launched.cdp;

    await waitFor(() => cdp!.eval<boolean>("Boolean(window.SGW_CONSOLE_LIVE)"), "live console flag");
    await waitFor(
      () => cdp!.eval<boolean>('Boolean(document.querySelector("[data-native-more-actions]"))'),
      "native more actions"
    );
    await clickElement(cdp, "[data-native-more-actions]");
    await waitFor(
      () => cdp!.eval<boolean>('Boolean(document.querySelector("[data-demo-data-toggle]"))'),
      "demo data menu item"
    );
    await clickElement(cdp, "[data-demo-data-toggle]");

    await waitFor(
      () => cdp!.eval<boolean>(`localStorage.getItem("sgw.demo-data") === "1" && document.body.innerText.includes("Demo")`),
      "demo data"
    );
    await cdp.eval('history.pushState({}, "", "/policies?native-shell=1"); window.dispatchEvent(new PopStateEvent("popstate"))');
    await waitFor(
      () => cdp!.eval<boolean>('document.querySelectorAll("[data-policy-row]").length === 17'),
      "demo policies"
    );
    expect(await cdp.eval<boolean>('Array.from(document.querySelectorAll("[data-policy-row] button")).every((button) => button.disabled)')).toBe(true);

    await clickElement(cdp, "[data-native-more-actions]");
    await waitFor(
      () => cdp!.eval<boolean>('document.querySelector("[data-demo-data-toggle]")?.innerText.includes("Remove demo data")'),
      "remove demo data menu item"
    );
    await clickElement(cdp, "[data-demo-data-toggle]");
    await waitFor(
      () => cdp!.eval<boolean>('localStorage.getItem("sgw.demo-data") === null && document.querySelectorAll("[data-policy-row]").length === 0'),
      "removed demo data"
    );
  }, 45_000);

  it("shows a release notification from the public update feed", async () => {
    const installer = process.platform === "darwin"
      ? "s-gw-0.1.1-macos.dmg"
      : process.platform === "win32" ? "s-gw-0.1.1-windows.zip" : "s-gw-0.1.1.tgz";
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpHome, "update.json"),
      currentVersion: "0.1.0",
      enabled: true,
      fetcher: async () => new Response(JSON.stringify([{
        tag_name: "v0.1.1",
        html_url: "https://github.com/sgateway/s-gw/releases/tag/v0.1.1",
        draft: false,
        prerelease: true,
        published_at: "2026-07-04T00:00:00.000Z",
        assets: [
          { name: installer, state: "uploaded" },
          { name: `${installer}.sha256`, state: "uploaded" }
        ]
      }]), { status: 200 })
    });
    await checker.check(true);
    running = await startConsoleServer({ port: 0, updateChecker: checker });
    const launched = await launchChrome(new URL("overview", running.url).toString());
    cdp = launched.cdp;

    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-update-banner]'))"),
      "update banner"
    );
    const banner = await cdp.eval<{ text: string; href: string }>(`(() => {
      const root = document.querySelector('[data-update-banner]');
      return { text: root.innerText, href: root.querySelector('a').href };
    })()`);
    expect(banner.text).toContain("s-gw 0.1.1 is available");
    expect(banner.href).toBe("https://github.com/sgateway/s-gw/releases/tag/v0.1.1");
  }, 45_000);

  it("opens actionable agent configuration and copies the MCP snippet", async () => {
    const binDir = path.join(tmpHome, "bin");
    mkdirSync(binDir, { recursive: true });
    const codexPath = path.join(binDir, "codex");
    writeFileSync(codexPath, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    chmodSync(codexPath, 0o755);
    const mcpPath = path.join(binDir, "s-gw-mcp");
    writeFileSync(mcpPath, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    chmodSync(mcpPath, 0o755);
    running = await startConsoleServer({ port: 0, agentHomeDir: tmpHome, agentPathEnv: binDir });
    const launched = await launchChrome(new URL("agents", running.url).toString());
    cdp = launched.cdp;

    await waitFor(
      () => cdp!.eval<boolean>('Boolean(document.querySelector(\'[data-agent-mcp="codex"]\'))'),
      "Codex MCP action"
    );
    const actionPoint = await cdp.eval<{ x: number; y: number }>(`(() => {
      const rect = document.querySelector('[data-agent-mcp="codex"]').getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    })()`);
    await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x: actionPoint.x, y: actionPoint.y, button: "left", clickCount: 1 });
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: actionPoint.x, y: actionPoint.y, button: "left", clickCount: 1 });

    await waitFor(
      () => cdp!.eval<boolean>('Boolean(document.querySelector(\'[data-agent-detail="codex"]\'))'),
      "Codex configuration sheet"
    );
    await waitFor(
      () => cdp!.eval<boolean>(`Array.from(document.querySelector('[data-agent-detail="codex"]').getAnimations({ subtree: true }))
        .every((animation) => animation.playState === 'finished')`),
      "Codex sheet animation"
    );
    const detailText = await cdp.eval<string>('document.querySelector(\'[data-agent-detail="codex"]\').innerText');
    expect(detailText).toContain("[mcp_servers.s-gw]");
    expect(detailText).toContain("s-gw run codex");
    expect(detailText).toContain("CodeGuard integration");
    expect(detailText).toContain("Connect");
    await cdp.eval('document.querySelector(\'[data-agent-install="codex"]\').click()');
    await waitFor(async () => {
      const state = await api<{ agents: Array<{ id: string; integration: { state: string } }> }>("api/state");
      return state.agents.find((agent) => agent.id === "codex")?.integration.state === "installed";
    }, "Codex managed installation");
    await waitFor(
      () => cdp!.eval<boolean>('!document.querySelector(\'[data-agent-detail="codex"]\')'),
      "Codex sheet closes after install"
    );
    await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x: actionPoint.x, y: actionPoint.y, button: "left", clickCount: 1 });
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: actionPoint.x, y: actionPoint.y, button: "left", clickCount: 1 });
    await waitFor(
      () => cdp!.eval<boolean>('Boolean(document.querySelector(\'[data-agent-uninstall="codex"]\'))'),
      "Codex managed uninstall action"
    );
    await cdp.eval(`(() => {
      Object.defineProperty(navigator, 'clipboard', {
        configurable: true,
        value: { writeText: async (value) => { window.__sgwCopiedSnippet = value; } }
      });
    })()`);

    await cdp.eval('document.querySelector("[data-copy-agent-snippet]").click()');
    await waitFor(
      () => cdp!.eval<boolean>('document.body.innerText.includes("MCP snippet copied")'),
      "MCP snippet copied toast"
    );
  }, 45_000);

  it("loads the shadcn console, shows readiness, and collapses repeated approve clicks to one POST", async () => {
    running = await startConsoleServer({ port: 0 });
    const launched = await launchChrome(new URL("overview", running.url).toString());
    cdp = launched.cdp;

    await waitFor(() => cdp!.eval<boolean>("Boolean(window.SGW_CONSOLE_LIVE)"), "live console flag");
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-readiness-banner]'))"),
      "readiness banner"
    );
    const readiness = await cdp.eval<string>("document.querySelector('[data-readiness-banner]').innerText");
    expect(readiness).toMatch(/s-gw setup/);

    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-browser",
      type: "api-token",
      value: "react-browser-secret-value-1234567890",
      injectEnv: "SGW_REACT_BROWSER_TOKEN",
      allowedCommands: [process.execPath]
    });
    const request = await api<{ id: string; state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_BROWSER_TOKEN",
      reason: "Codex React browser e2e"
    });
    expect(request.state).toBe("pending");

    await cdp.send("Page.navigate", { url: new URL("approvals", running.url).toString() });
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('tbody tr').length > 0 && document.body.innerText.includes('Codex')"),
      "request row"
    );
    await cdp.eval("document.querySelector('tbody tr').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-approve="${request.id}"]'))`),
      "approval sheet button"
    );
    await cdp.eval(`(function () {
      var btn = document.querySelector('[data-approve="${request.id}"]');
      for (var i = 0; i < 3; i++) {
        btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      }
      return true;
    })()`);

    await waitFor(async () => {
      const state = await api<{ requests: Array<{ id: string; state: string }> }>("api/state");
      return state.requests.find((item) => item.id === request.id)?.state === "approved";
    }, "request approved");
    expect(launched.approvePostCount()).toBe(1);
  }, 45_000);

  it("creates a scoped policy from the approval sheet without widening access", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser scoped policy passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-scoped-policy",
      type: "api-token",
      value: "react-scoped-policy-secret-value-1234567890",
      injectEnv: "SGW_REACT_SCOPED_POLICY_TOKEN",
      allowedCommands: [process.execPath]
    });
    const request = await api<{ id: string; state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log('scoped policy')"],
      injectEnv: "SGW_REACT_SCOPED_POLICY_TOKEN",
      workingDir: repoRoot,
      reason: "Scoped policy browser e2e",
      agentName: "Codex"
    });
    expect(request.state).toBe("pending");

    const launched = await launchChrome(new URL("approvals", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('tbody tr').length > 0"),
      "scoped policy request row"
    );
    await cdp.eval("document.querySelector('tbody tr').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-approve="${request.id}"]'))`),
      "scoped policy approval sheet"
    );
    await cdp.eval(`(() => {
      const button = [...document.querySelectorAll('button')]
        .find((item) => item.textContent?.trim().startsWith('Allow for'));
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      return Boolean(button);
    })()`);
    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-approve-policy="${request.id}"]'))`),
      "scoped policy approval action"
    );
    await clickElement(cdp, `[data-approve-policy="${request.id}"]`);

    await waitFor(async () => {
      const state = await api<{
        requests: Array<{ id: string; state: string }>;
        approvalPolicyRules: Array<unknown>;
      }>("api/state");
      return state.requests.find((item) => item.id === request.id)?.state === "approved"
        && state.approvalPolicyRules.length === 1;
    }, "scoped policy approval");

    const state = await api<{
      approvalPolicyRules: Array<{
        id: string;
        decision: string;
        conditions: {
          handles?: string[];
          agents?: string[];
          actionKinds?: string[];
          commands?: string[];
          injectEnvs?: string[];
          workingDirs?: string[];
        };
      }>;
    }>("api/state");
    const rule = state.approvalPolicyRules[0];
    expect(rule).toBeDefined();
    if (!rule) {
      throw new Error("Expected the approval sheet to create one scoped policy rule.");
    }
    expect(rule.decision).toBe("allow");
    expect(rule.conditions).toMatchObject({
      handles: [created.handle],
      agents: ["codex"],
      actionKinds: ["env_command"],
      commands: [process.execPath],
      injectEnvs: ["SGW_REACT_SCOPED_POLICY_TOKEN"],
      workingDirs: [repoRoot]
    });

    const matchingRequest = await api<{
      state: string;
      approvalSource?: string;
      approvalPolicyRuleId?: string;
    }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log('matching scope')"],
      injectEnv: "SGW_REACT_SCOPED_POLICY_TOKEN",
      workingDir: repoRoot,
      reason: "Matching scoped policy browser e2e",
      agentName: "Codex"
    });
    expect(matchingRequest).toMatchObject({
      state: "approved",
      approvalSource: "policy",
      approvalPolicyRuleId: rule.id
    });

    const differentAgent = await api<{ state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log('different agent')"],
      injectEnv: "SGW_REACT_SCOPED_POLICY_TOKEN",
      workingDir: repoRoot,
      reason: "Different agent scoped policy browser e2e",
      agentName: "Claude"
    });
    expect(differentAgent.state).toBe("pending");

    const differentDirectory = await api<{ state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log('different directory')"],
      injectEnv: "SGW_REACT_SCOPED_POLICY_TOKEN",
      workingDir: path.join(repoRoot, "other-directory"),
      reason: "Different directory scoped policy browser e2e",
      agentName: "Codex"
    });
    expect(differentDirectory.state).toBe("pending");

    await cdp.send("Page.navigate", { url: new URL("policies", running.url).toString() });
    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-policy-edit="${rule.id}"]'))`),
      "scoped policy edit action"
    );
    await clickElement(cdp, `[data-policy-edit="${rule.id}"]`);
    await waitFor(
      () => cdp!.eval<boolean>("document.body.innerText.includes('Exact credential bindings')"),
      "exact binding editor notice"
    );
    const lockedFields = await cdp.eval<{ credentialsLocked: boolean; envLocked: boolean }>(`(() => {
      const dialog = document.querySelector('[role="dialog"]');
      return {
        credentialsLocked: Boolean(dialog?.querySelector('[aria-label="Policy credentials"]')?.disabled),
        envLocked: Boolean(dialog?.querySelector('[aria-label="Policy environment variables"]')?.disabled)
      };
    })()`);
    expect(lockedFields).toEqual({ credentialsLocked: true, envLocked: true });

    expect(launched.approvePostCount()).toBe(0);
  }, 45_000);

  it("closes an approval sheet when another surface already approved the request", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser stale approval passphrase";
    running = await startConsoleServer({ port: 0 });
    const created = await api<{ handle: string }>("api/secrets", {
      name: "browser-stale-approval",
      type: "api-token",
      value: "browser-stale-approval-secret-value-1234567890",
      injectEnv: "SGW_BROWSER_STALE_TOKEN",
      allowedCommands: [process.execPath]
    });
    const request = await api<{ id: string; state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_BROWSER_STALE_TOKEN",
      reason: "Codex stale approval browser e2e"
    });
    expect(request.state).toBe("pending");

    const launched = await launchChrome(new URL("approvals", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('tbody tr').length > 0"),
      "pending request row"
    );
    await cdp.eval("document.querySelector('tbody tr').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-approve="${request.id}"]'))`),
      "approval sheet button"
    );

    await api(`api/requests/${request.id}/approve`, {});
    await cdp.eval(`document.querySelector('[data-approve="${request.id}"]').click()`);

    await waitFor(
      () => cdp!.eval<boolean>(`!document.querySelector('[data-approve="${request.id}"]')`),
      "stale approval sheet closes"
    );
    const state = await api<{ requests: Array<{ id: string; state: string }> }>("api/state");
    expect(state.requests.find((item) => item.id === request.id)?.state).toBe("approved");
  }, 45_000);

  it("renders a real d3 Sankey chart and opens a shadcn Sheet for flow drill-in", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-sankey",
      type: "api-token",
      value: "react-sankey-secret-value-1234567890",
      injectEnv: "SGW_REACT_SANKEY_TOKEN",
      allowedCommands: [process.execPath]
    });
    await api("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_SANKEY_TOKEN",
      reason: "Codex React sankey"
    });
    await api("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "2"],
      injectEnv: "SGW_REACT_SANKEY_TOKEN",
      reason: "Claude React sankey"
    });

    const ssh = await api<{ handle: string }>("api/secrets", {
      name: "react-sankey-ssh",
      type: "private-key",
      provider: "ssh",
      value: "react-sankey-ssh-private-key-value-1234567890",
      injectEnv: "SGW_REACT_SSH_KEY",
      allowedCommands: ["/usr/bin/ssh"]
    });
    const sshTargets = ["ubuntu@web-01.internal", "ubuntu@web-02.internal", "ec2-user@db-01.internal"];
    for (const target of sshTargets) {
      await api("api/requests", {
        handle: ssh.handle,
        command: "/usr/bin/ssh",
        args: [target],
        injectEnv: "SGW_REACT_SSH_KEY",
        reason: `Codex SSH access to ${target}`
      });
    }

    const launched = await launchChrome(new URL("usage-flow", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelector('[data-sankey]')?.getAttribute('data-engine') === 'd3-sankey'"),
      "d3 sankey"
    );

    const chart = await cdp.eval<{
      headings: string[];
      headingAnchors: string[];
      headingBounds: Array<{ left: number; right: number; text: string }>;
      links: number;
      nodes: number;
      rawSecretVisible: boolean;
      rows: number;
      svgBounds: { left: number; right: number };
    }>(`({
      headings: [...document.querySelectorAll('.sankey-heading')].map((node) => node.textContent),
      headingAnchors: [...document.querySelectorAll('.sankey-heading')].map((node) => node.getAttribute('text-anchor') || 'start'),
      headingBounds: [...document.querySelectorAll('.sankey-heading')].map((node) => {
        const rect = node.getBoundingClientRect();
        return { left: rect.left, right: rect.right, text: node.textContent };
      }),
      links: document.querySelectorAll('.sankey-link').length,
      nodes: document.querySelectorAll('.sankey-node').length,
      rawSecretVisible: document.body.innerText.includes('react-sankey-secret-value'),
      rows: document.querySelectorAll('tbody tr').length,
      svgBounds: (() => {
        const rect = document.querySelector('[data-sankey]').getBoundingClientRect();
        return { left: rect.left, right: rect.right };
      })()
    })`);
    expect(chart.headings).toEqual(["Agent", "Authentication type", "Target type"]);
    expect(chart.headingAnchors).toEqual(["start", "middle", "end"]);
    expect(chart.headingBounds[2].right).toBeLessThanOrEqual(chart.svgBounds.right);
    expect(chart.links).toBeGreaterThanOrEqual(2);
    expect(chart.nodes).toBeGreaterThanOrEqual(3);
    expect(chart.rows).toBeGreaterThanOrEqual(2);
    expect(chart.rawSecretVisible).toBe(false);

    await cdp.eval("document.querySelector('[data-flow-node=\"auth:ssh-private-key\"]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-slot=\"sheet-title\"]'))"),
      "flow sheet"
    );
    const sheetTitle = await cdp.eval<string>("document.querySelector('[data-slot=\"sheet-title\"]').textContent");
    expect(sheetTitle).toBe("SSH private key");
    const detail = await cdp.eval<{
      hasShadcnHandle: boolean;
      handleX: number;
      handleY: number;
      handleHeight: number;
      panelWidth: number;
      sheetWidth: number;
      entryCount: number;
      entryText: string;
    }>(`(() => {
      const handle = document.querySelector('[data-flow-detail-resize][data-slot="resizable-handle"]');
      const panel = document.querySelector('[data-flow-detail-panel]');
      const sheet = document.querySelector('[data-flow-detail-sheet]');
      const handleRect = handle?.getBoundingClientRect();
      const panelRect = panel?.getBoundingClientRect();
      const sheetRect = sheet?.getBoundingClientRect();
      return {
        hasShadcnHandle: Boolean(handle?.querySelector('div')),
        handleX: Math.round((handleRect?.left || 0) + (handleRect?.width || 0) / 2),
        handleY: Math.round((handleRect?.top || 0) + (handleRect?.height || 0) / 2),
        handleHeight: Math.round(handleRect?.height || 0),
        panelWidth: Math.round(panelRect?.width || 0),
        sheetWidth: Math.round(sheetRect?.width || 0),
        entryCount: document.querySelectorAll('[data-flow-entry]').length,
        entryText: document.querySelector('[data-flow-entries]')?.textContent || ''
      };
    })()`);
    expect(detail.hasShadcnHandle).toBe(true);
    expect(detail.handleHeight).toBeGreaterThan(500);
    expect(detail.panelWidth).toBeGreaterThan(450);
    expect(detail.sheetWidth).toBeGreaterThan(detail.panelWidth);
    expect(detail.entryCount).toBe(sshTargets.length);
    for (const target of sshTargets) expect(detail.entryText).toContain(target);

    await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x: detail.handleX, y: detail.handleY, button: "left", clickCount: 1 });
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: detail.handleX - 120, y: detail.handleY, button: "left", buttons: 1 });
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: detail.handleX - 120, y: detail.handleY, button: "left", clickCount: 1 });
    await waitFor(
      () => cdp!.eval<boolean>(`document.querySelector('[data-flow-detail-panel]').getBoundingClientRect().width > ${detail.panelWidth + 60}`),
      "resized flow sheet"
    );
    expect(await cdp.eval<string>("document.querySelector('[data-slot=\"sheet-title\"]')?.textContent || ''")).toBe("SSH private key");

    await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 20, y: 300, button: "left", clickCount: 1 });
    await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 20, y: 300, button: "left", clickCount: 1 });
    await waitFor(
      () => cdp!.eval<boolean>("!document.querySelector('[data-slot=\"sheet-title\"]')"),
      "flow sheet dismissed outside"
    );
    expect(await cdp.eval<string>("location.pathname")).toBe("/usage-flow");
  }, 45_000);

  it("fits recent activity rows to the available panel height", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-recent-activity",
      type: "api-token",
      value: "react-recent-activity-secret-value-1234567890",
      injectEnv: "SGW_REACT_ACTIVITY_TOKEN",
      allowedCommands: [process.execPath]
    });
    for (let index = 0; index < 14; index++) {
      await api("api/requests", {
        handle: created.handle,
        command: process.execPath,
        args: ["-e", String(index)],
        injectEnv: "SGW_REACT_ACTIVITY_TOKEN",
        reason: `Codex adaptive activity ${index}`
      });
    }

    const launched = await launchChrome(new URL("overview", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-recent-activity-list] [data-overview-event-row]').length > 0"),
      "recent activity rows"
    );

    const resizeActivityPanel = async (height: number) => {
      await cdp!.eval(`(() => {
        const panel = document.querySelector('[data-recent-activity]')?.closest('.react-grid-item');
        if (!panel) return false;
        panel.style.height = '${height}px';
        return true;
      })()`);
      await waitFor(
        () => cdp!.eval<boolean>(`(() => {
          const list = document.querySelector('[data-recent-activity-list]');
          if (!list) return false;
          const panel = list.closest('.react-grid-item');
          const total = Number(list.getAttribute('data-total-rows'));
          const expected = Math.min(total, Math.max(1, Math.floor((list.getBoundingClientRect().height - 38) / 44)));
          const settled = Math.abs(panel.getBoundingClientRect().height - ${height}) < 2;
          return settled && Number(list.getAttribute('data-visible-rows')) === expected;
        })()`),
        `recent activity at ${height}px`
      );
      return cdp!.eval<{ availableHeight: number; contentHeight: number; detailCards: number; hasOldCompactRows: boolean; rows: number }>(`(() => {
        const list = document.querySelector('[data-recent-activity-list]');
        return {
          availableHeight: list.getBoundingClientRect().height,
          contentHeight: list.firstElementChild.getBoundingClientRect().height,
          detailCards: list.querySelectorAll('.sgw-event-flow-card').length,
          hasOldCompactRows: Boolean(list.querySelector('[data-activity-flow]')),
          rows: list.querySelectorAll('[data-overview-event-row]').length
        };
      })()`);
    };

    const shortPanel = await resizeActivityPanel(360);
    const tallPanel = await resizeActivityPanel(620);
    expect(tallPanel.rows).toBeGreaterThan(shortPanel.rows);
    expect(shortPanel.detailCards).toBe(0);
    expect(tallPanel.detailCards).toBe(0);
    expect(shortPanel.hasOldCompactRows).toBe(false);
    expect(tallPanel.hasOldCompactRows).toBe(false);
    expect(await cdp.eval<string>("document.querySelector('.sgw-recent-event-head span')?.textContent || ''")).toBe("Source");
    expect(await cdp.eval<boolean>("Boolean(document.querySelector('[data-overview-event-row] > .sgw-event-source-cell .sgw-agent-icon'))")).toBe(true);
    const recentLayout = await cdp.eval<{ labels: string[]; widths: number[] }>(`(() => ({
      labels: [...document.querySelectorAll('[data-overview-event-row] .sgw-event-type-pill')].map((node) => node.textContent.trim()),
      widths: [...document.querySelectorAll('.sgw-recent-event-head > span')].map((node) => Math.round(node.getBoundingClientRect().width))
    }))()`);
    expect(recentLayout.labels.every((label) => /^\S+$/.test(label))).toBe(true);
    expect(recentLayout.widths[0]).toBeLessThan(recentLayout.widths[3]);
    expect(recentLayout.widths[1]).toBeLessThan(recentLayout.widths[2]);
    expect(shortPanel.contentHeight).toBeLessThanOrEqual(shortPanel.availableHeight + 1);
    expect(tallPanel.contentHeight).toBeLessThanOrEqual(tallPanel.availableHeight + 1);
  }, 45_000);

  it("keeps native-shell navigation and activity surfaces readable in light mode", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser light theme passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-light-theme",
      type: "api-token",
      value: "react-light-theme-secret-value-1234567890",
      injectEnv: "SGW_REACT_LIGHT_THEME_TOKEN",
      allowedCommands: [process.execPath]
    });
    await api("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_LIGHT_THEME_TOKEN",
      reason: "Codex light theme regression"
    });

    const launched = await launchChrome(new URL("overview?native-shell=1", running.url).toString());
    cdp = launched.cdp;
    await cdp.eval("localStorage.setItem('sgw.theme', 'light'); location.reload()");
    await waitFor(
      () => cdp!.eval<boolean>("document.documentElement.classList.contains('light') && Boolean(document.querySelector('[data-recent-activity-list]'))"),
      "light overview"
    );

    const overviewTheme = await cdp.eval<{
      navText: number[][];
      recentBackground: number[];
      recentHeadText: number[];
      recentText: number[];
      recentStatusText: number[];
    }>(`(() => {
      const channels = (value) => (value.match(/[\\d.]+/g) || []).slice(0, 3).map(Number);
      const inactiveNav = [...document.querySelectorAll('.sgw-sidebar-nav-button')]
        .filter((node) => node.getAttribute('data-active') !== 'true');
      const recent = document.querySelector('.sgw-recent-event-list');
      const row = document.querySelector('[data-overview-event-row]');
      return {
        navText: inactiveNav.map((node) => channels(getComputedStyle(node).color)),
        recentBackground: channels(getComputedStyle(recent).backgroundColor),
        recentHeadText: channels(getComputedStyle(document.querySelector('.sgw-recent-event-head')).color),
        recentText: channels(getComputedStyle(row).color),
        recentStatusText: channels(getComputedStyle(row.querySelector('.sgw-event-status')).color)
      };
    })()`);
    expect(overviewTheme.navText.length).toBeGreaterThan(0);
    expect(overviewTheme.navText.every((color) => Math.max(...color) < 100)).toBe(true);
    expect(Math.min(...overviewTheme.recentBackground)).toBeGreaterThan(230);
    expect(Math.max(...overviewTheme.recentHeadText)).toBeLessThan(100);
    expect(Math.max(...overviewTheme.recentText)).toBeLessThan(100);
    expect(Math.max(...overviewTheme.recentStatusText)).toBeLessThan(210);

    await cdp.send("Page.navigate", { url: new URL("activity?native-shell=1", running.url).toString() });
    await waitFor(
      () => cdp!.eval<boolean>("document.documentElement.classList.contains('light') && Boolean(document.querySelector('[data-event-log-card] .sgw-event-flow-card'))"),
      "light activity"
    );
    const activityTheme = await cdp.eval<{
      cardBackground: number[];
      detailBackground: number[];
      detailCardBackground: number[];
      detailTitle: number[];
      queryBackground: number[];
      rowText: number[];
      rowStatusText: number[];
    }>(`(() => {
      const channels = (value) => (value.match(/[\\d.]+/g) || []).slice(0, 3).map(Number);
      return {
        cardBackground: channels(getComputedStyle(document.querySelector('[data-event-log-card]')).backgroundColor),
        detailBackground: channels(getComputedStyle(document.querySelector('.sgw-event-detail-stage')).backgroundColor),
        detailCardBackground: channels(getComputedStyle(document.querySelector('.sgw-event-flow-card')).backgroundColor),
        detailTitle: channels(getComputedStyle(document.querySelector('.sgw-event-flow-title')).color),
        queryBackground: channels(getComputedStyle(document.querySelector('.sgw-event-query')).backgroundColor),
        rowText: channels(getComputedStyle(document.querySelector('[data-event-row]')).color),
        rowStatusText: channels(getComputedStyle(document.querySelector('[data-event-row] .sgw-event-status')).color)
      };
    })()`);
    expect(Math.min(...activityTheme.cardBackground)).toBeGreaterThan(230);
    expect(Math.min(...activityTheme.detailBackground)).toBeGreaterThan(230);
    expect(Math.min(...activityTheme.detailCardBackground)).toBeGreaterThan(230);
    expect(Math.max(...activityTheme.detailTitle)).toBeLessThan(100);
    expect(Math.min(...activityTheme.queryBackground)).toBeGreaterThan(230);
    expect(Math.max(...activityTheme.rowText)).toBeLessThan(100);
    expect(Math.max(...activityTheme.rowStatusText)).toBeLessThan(210);
  }, 45_000);

  it("uses a compact settings switcher and saves readable duration choices", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser settings passphrase";
    running = await startConsoleServer({ port: 0 });

    await api("api/approval", { mode: "per-transaction", durationMs: 42 * 60 * 1000 });
    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-settings-grant",
      type: "api-token",
      value: "react-settings-secret-value-1234567890",
      injectEnv: "SGW_REACT_SETTINGS_TOKEN",
      allowedCommands: [process.execPath]
    });
    const request = await api<{ id: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_SETTINGS_TOKEN",
      reason: "Codex settings reusable grant",
      agentName: "Codex"
    });
    await api(`api/requests/${request.id}/approve`, {
      mode: "timed-session",
      durationMs: 15 * 60 * 1000,
      agentScope: "any-agent"
    });

    const launched = await launchChrome(new URL("settings?native-shell=1", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-settings-panel=\"approvals\"]'))"),
      "settings approval panel"
    );

    const desktop = await cdp.eval<{
      durationDisabled: boolean;
      nav: { bottom: number; height: number; left: number; width: number };
      panel: { left: number; top: number; width: number };
      rawMillisecondsVisible: boolean;
      selected: string[];
      tabTops: number[];
      tabs: number;
      warning: string;
    }>(`(() => {
      const nav = document.querySelector('[data-settings-nav]').getBoundingClientRect();
      const panelNode = document.querySelector('[data-settings-panel="approvals"]');
      const panel = panelNode.getBoundingClientRect();
      const tabs = [...document.querySelectorAll('[data-settings-tab]')];
      return {
        durationDisabled: document.querySelector('[data-settings-duration]').disabled,
        nav: { bottom: nav.bottom, height: nav.height, left: nav.left, width: nav.width },
        panel: { left: panel.left, top: panel.top, width: panel.width },
        rawMillisecondsVisible: document.body.innerText.includes(String(42 * 60 * 1000)),
        selected: tabs.filter((tab) => tab.getAttribute('aria-selected') === 'true').map((tab) => tab.getAttribute('data-settings-tab')),
        tabTops: tabs.map((tab) => Math.round(tab.getBoundingClientRect().top)),
        tabs: tabs.length,
        warning: panelNode.querySelector('[data-slot="card-footer"]').innerText
      };
    })()`);
    expect(desktop.tabs).toBe(3);
    expect(new Set(desktop.tabTops).size).toBe(1);
    expect(desktop.nav.height).toBeLessThan(100);
    expect(desktop.panel.top).toBeGreaterThan(desktop.nav.bottom);
    expect(Math.abs(desktop.panel.left - desktop.nav.left)).toBeLessThan(2);
    expect(Math.abs(desktop.panel.width - desktop.nav.width)).toBeLessThan(2);
    expect(desktop.durationDisabled).toBe(true);
    expect(desktop.rawMillisecondsVisible).toBe(false);
    expect(desktop.selected).toEqual(["approvals"]);
    expect(desktop.warning).toContain("Saving clears 1 active reusable grant");

    await clickElement(cdp, '[data-settings-tab="grants"]');
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-settings-panel=\"grants\"]'))"),
      "settings grants panel"
    );
    expect(await cdp.eval<string>("document.querySelector('[data-settings-tab=\"grants\"]').getAttribute('aria-selected')")).toBe("true");
    const grantsText = await cdp.eval<string>("document.querySelector('[data-settings-panel=\"grants\"]').innerText");
    expect(grantsText).toContain("1 active");
    expect(grantsText).toContain("Reuse for a time window");

    await clickElement(cdp, '[data-settings-tab="about"]');
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-settings-panel=\"about\"]'))"),
      "settings about panel"
    );
    expect(await cdp.eval<string>("document.querySelector('[data-settings-panel=\"about\"]').innerText")).toContain("Store location");

    await clickElement(cdp, '[data-settings-tab="approvals"]');
    await waitFor(
      () => cdp!.eval<boolean>("Boolean(document.querySelector('[data-settings-panel=\"approvals\"]'))"),
      "settings approval panel restored"
    );
    await chooseSelectOption(cdp, "[data-settings-mode]", "Reuse for a time window");
    await waitFor(
      () => cdp!.eval<boolean>("!document.querySelector('[data-settings-duration]').disabled"),
      "settings duration enabled"
    );
    await chooseSelectOption(cdp, "[data-settings-duration]", "1 hour");
    await chooseSelectOption(cdp, "[data-settings-duration]", "Current setting · 42 minutes");
    expect(await cdp.eval<string>("document.querySelector('[data-settings-duration]').innerText.trim()")).toBe("Current setting · 42 minutes");
    await chooseSelectOption(cdp, "[data-settings-duration]", "1 hour");
    await chooseSelectOption(cdp, "[data-settings-mode]", "Reuse for this login session");
    expect(await cdp.eval<boolean>("document.querySelector('[data-settings-duration]').disabled")).toBe(true);
    expect(await cdp.eval<string>("document.querySelector('[data-settings-duration]').innerText.trim()")).toBe("1 hour");
    await chooseSelectOption(cdp, "[data-settings-mode]", "Reuse for a time window");
    expect(await cdp.eval<boolean>("document.querySelector('[data-settings-duration]').disabled")).toBe(false);
    expect(await cdp.eval<string>("document.querySelector('[data-settings-duration]').innerText.trim()")).toBe("1 hour");

    await clickElement(cdp, "[data-settings-save]");
    await waitFor(async () => {
      const saved = await api<{
        approvalGrants: unknown[];
        approvalSettings: { durationMs: number; mode: string };
      }>("api/state");
      return saved.approvalSettings.mode === "timed-session"
        && saved.approvalSettings.durationMs === 60 * 60 * 1000
        && saved.approvalGrants.length === 0;
    }, "settings saved");

    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: false
    });
    await waitFor(
      () => cdp!.eval<boolean>("document.documentElement.clientWidth === 390"),
      "settings mobile viewport"
    );
    const mobile = await cdp.eval<{ descriptionsHidden: boolean; navHeight: number; overflow: number; tabTops: number[] }>(`(() => {
      const nav = document.querySelector('[data-settings-nav]');
      const tabs = [...document.querySelectorAll('[data-settings-tab]')];
      const descriptions = tabs.map((tab) => tab.querySelector('.text-xs'));
      return {
        descriptionsHidden: descriptions.every((node) => getComputedStyle(node).display === 'none'),
        navHeight: nav.getBoundingClientRect().height,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        tabTops: tabs.map((tab) => Math.round(tab.getBoundingClientRect().top))
      };
    })()`);
    expect(new Set(mobile.tabTops).size).toBe(1);
    expect(mobile.navHeight).toBeLessThan(130);
    expect(mobile.descriptionsHidden).toBe(true);
    expect(mobile.overflow).toBeLessThanOrEqual(1);
  }, 45_000);

  it("sorts, searches, and filters activity and audit columns", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-event-controls",
      type: "api-token",
      value: "react-event-controls-secret-value-1234567890",
      injectEnv: "SGW_REACT_EVENT_TOKEN",
      allowedCommands: [process.execPath]
    });
    await api("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_EVENT_TOKEN",
      reason: "Activity controls alpha",
      agentName: "Codex"
    });
    await api("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "2"],
      injectEnv: "SGW_REACT_EVENT_TOKEN",
      reason: "Activity controls beta",
      agentName: "Claude"
    });

    const launched = await launchChrome(new URL("activity", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-event-row]').length >= 2"),
      "activity event rows"
    );

    const activityTable = await cdp.eval<{
      firstHeader: string;
      firstCellHasIcon: boolean;
      sortButtons: number;
    }>(`(() => ({
      firstHeader: document.querySelector('[data-sort-column]')?.textContent?.trim() || '',
      firstCellHasIcon: Boolean(document.querySelector('[data-event-row] td:first-child .sgw-agent-icon')),
      sortButtons: document.querySelectorAll('[data-sort-column]').length
    }))()`);
    expect(activityTable.firstHeader).toContain("Source");
    expect(activityTable.firstCellHasIcon).toBe(true);
    expect(activityTable.sortButtons).toBe(8);

    await setEventSearch(cdp, "Claude");
    await waitFor(
      () => cdp!.eval<boolean>(`(() => {
        const rows = [...document.querySelectorAll('[data-event-row]')];
        return rows.length > 0 && rows.every((row) => row.querySelector('td')?.textContent?.includes('Claude'));
      })()`),
      "activity global search"
    );
    await setEventSearch(cdp, "");

    await cdp.eval("document.querySelector('.sgw-event-filter-button').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(() => cdp!.eval<boolean>("Boolean(document.querySelector('[data-event-filter-row]'))"), "activity filter row");
    await cdp.eval(`(() => {
      const input = document.querySelector('[data-event-filter-row] input');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'Codex');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      const apply = [...document.querySelectorAll('[data-event-filter-row] button')].find((button) => button.textContent.includes('Apply filter'));
      apply.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    })()`);
    await waitFor(
      () => cdp!.eval<boolean>(`(() => {
        const rows = [...document.querySelectorAll('[data-event-row]')];
        return rows.length > 0 && rows.every((row) => row.querySelector('td')?.textContent?.includes('Codex'));
      })()`),
      "activity source filter"
    );
    await cdp.eval("document.querySelector('.sgw-event-reset').dispatchEvent(new MouseEvent('click', { bubbles: true }))");

    await cdp.eval("document.querySelector('[data-sort-column=\"source\"]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    expect(await cdp.eval<string>("document.querySelector('[data-sort-column=\"source\"]').closest('th').getAttribute('aria-sort')")).toBe("ascending");
    await cdp.eval("document.querySelector('[data-sort-column=\"source\"]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    expect(await cdp.eval<string>("document.querySelector('[data-sort-column=\"source\"]').closest('th').getAttribute('aria-sort')")).toBe("descending");

    await cdp.send("Page.navigate", { url: new URL("audit", running.url).toString() });
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-event-row]').length >= 2"),
      "audit event rows"
    );
    expect(await cdp.eval<string>("document.querySelector('[data-sort-column]')?.textContent?.trim() || ''")).toContain("Event type");
    await cdp.eval("document.querySelector('.sgw-event-filter-button').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(() => cdp!.eval<boolean>("Boolean(document.querySelector('[data-event-filter-row]'))"), "audit filter row");
    await cdp.eval(`(() => {
      const input = document.querySelector('[data-event-filter-row] input');
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(input, 'Request');
      input.dispatchEvent(new Event('input', { bubbles: true }));
      const apply = [...document.querySelectorAll('[data-event-filter-row] button')].find((button) => button.textContent.includes('Apply filter'));
      apply.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    })()`);
    await waitFor(
      () => cdp!.eval<boolean>(`(() => {
        const rows = [...document.querySelectorAll('[data-event-row]')];
        return rows.length > 0 && rows.every((row) => row.querySelector('td')?.textContent?.includes('Request'));
      })()`),
      "audit event type filter"
    );
  }, 45_000);

  it("shows newest credentials first and supports credential search and sorting", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    await api("api/secrets", {
      name: "Alpha older credential",
      type: "api-token",
      value: "alpha-credential-value-1234567890",
      injectEnv: "SGW_ALPHA_TOKEN",
      allowedCommands: [process.execPath]
    });
    await delay(10);
    await api("api/secrets", {
      name: "Zulu newest credential",
      type: "api-token",
      value: "zulu-credential-value-1234567890",
      injectEnv: "SGW_ZULU_TOKEN",
      allowedCommands: [process.execPath]
    });

    const launched = await launchChrome(new URL("credentials", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-credential-row]').length === 2"),
      "credential rows"
    );

    expect(await cdp.eval<string>("document.querySelector('[data-credential-sort=\"updated\"]').closest('th').getAttribute('aria-sort')")).toBe("descending");
    expect(await firstCredentialName(cdp)).toBe("Zulu newest credential");

    await setCredentialSearch(cdp, "Alpha");
    await waitFor(
      async () => (await credentialNames(cdp!)).join(",") === "Alpha older credential",
      "credential search"
    );
    await setCredentialSearch(cdp, "");
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-credential-row]').length === 2"),
      "cleared credential search"
    );

    await cdp.eval("document.querySelector('[data-credential-sort=\"name\"]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(async () => (await firstCredentialName(cdp!)) === "Alpha older credential", "ascending credential name sort");
    expect(await cdp.eval<string>("document.querySelector('[data-credential-sort=\"name\"]').closest('th').getAttribute('aria-sort')")).toBe("ascending");

    await cdp.eval("document.querySelector('[data-credential-sort=\"name\"]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(async () => (await firstCredentialName(cdp!)) === "Zulu newest credential", "descending credential name sort");
    expect(await cdp.eval<string>("document.querySelector('[data-credential-sort=\"name\"]').closest('th').getAttribute('aria-sort')")).toBe("descending");
  }, 45_000);

  it("uses one policy status control and toggles its state", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    await api("api/approval/policies", {
      name: "Single status control",
      enabled: true,
      priority: 10,
      decision: "ask",
      agents: ["Codex"]
    });

    const launched = await launchChrome(new URL("policies", running.url).toString());
    cdp = launched.cdp;
    await waitFor(
      () => cdp!.eval<boolean>("document.querySelectorAll('[data-policy-status]').length === 1"),
      "policy status control"
    );

    const enabledState = await cdp.eval<{ checked: string | null; icons: number; switches: number; text: string }>(`(() => {
      const control = document.querySelector('[data-policy-status]');
      return {
        checked: control.getAttribute('aria-checked'),
        icons: control.querySelectorAll('svg').length,
        switches: document.querySelectorAll('[data-slot="switch"]').length,
        text: control.textContent.trim()
      };
    })()`);
    expect(enabledState).toEqual({ checked: "true", icons: 1, switches: 0, text: "Enabled" });

    await cdp.eval("document.querySelector('[data-policy-status]').dispatchEvent(new MouseEvent('click', { bubbles: true }))");
    await waitFor(async () => {
      const state = await api<{ approvalPolicyRules: Array<{ enabled: boolean }> }>("api/state");
      return state.approvalPolicyRules[0]?.enabled === false;
    }, "disabled policy state");
    await waitFor(
      () => cdp!.eval<boolean>(`(() => {
        const control = document.querySelector('[data-policy-status]');
        return control?.getAttribute('aria-checked') === 'false' && control.textContent.trim() === 'Disabled';
      })()`),
      "disabled policy control"
    );
  }, 45_000);

  it("serves the compact menubar React route", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "browser react passphrase";
    running = await startConsoleServer({ port: 0 });

    const created = await api<{ handle: string }>("api/secrets", {
      name: "react-menubar",
      type: "api-token",
      value: "react-menubar-secret-value-1234567890",
      injectEnv: "SGW_REACT_MENUBAR_TOKEN",
      allowedCommands: [process.execPath]
    });
    const request = await api<{ id: string; state: string }>("api/requests", {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "1"],
      injectEnv: "SGW_REACT_MENUBAR_TOKEN",
      reason: "Codex React menubar"
    });
    expect(request.state).toBe("pending");

    const launched = await launchChrome(new URL("menubar", running.url).toString());
    cdp = launched.cdp;
    await waitFor(() => cdp!.eval<boolean>("document.body.innerText.includes('Approval queue')"), "menubar route");

    const text = await cdp.eval<string>("document.body.innerText");
    expect(text).toContain("Pending");
    expect(text).toContain("Handles");
    expect(text).toContain("Agents");

    await waitFor(
      () => cdp!.eval<boolean>(`Boolean(document.querySelector('[data-menubar-approve="${request.id}"]'))`),
      "menubar approve button"
    );
    await cdp.eval(`(function () {
      var btn = document.querySelector('[data-menubar-approve="${request.id}"]');
      for (var i = 0; i < 3; i++) {
        btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      }
      return true;
    })()`);

    await waitFor(async () => {
      const state = await api<{ requests: Array<{ id: string; state: string }> }>("api/state");
      return state.requests.find((item) => item.id === request.id)?.state === "approved";
    }, "menubar request approved");
    expect(launched.approvePostCount()).toBe(1);
  }, 30_000);
});

async function launchChrome(url: string): Promise<{ cdp: Cdp; approvePostCount: () => number }> {
  chrome = spawn(
    chromePath as string,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      "--remote-debugging-port=0",
      "--window-size=1500,950",
      `--user-data-dir=${profileDir}`,
      url
    ],
    { stdio: ["ignore", "ignore", "pipe"] }
  );

  const wsUrl = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timeout waiting for DevTools endpoint")), 30_000);
    let buf = "";
    chrome!.stderr?.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      const match = buf.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    chrome!.on("exit", () => {
      clearTimeout(timer);
      reject(new Error("chrome exited before announcing DevTools endpoint"));
    });
  });

  const httpBase = wsUrl.replace(/^ws:\/\/([^/]+)\/.*$/, "http://$1");
  let target: { type: string; webSocketDebuggerUrl?: string } | undefined;
  await waitFor(async () => {
    const list = (await fetch(`${httpBase}/json`).then((r) => r.json()).catch(() => [])) as Array<{
      type: string;
      webSocketDebuggerUrl?: string;
    }>;
    target = list.find((item) => item.type === "page" && item.webSocketDebuggerUrl);
    return Boolean(target);
  }, "chrome page target");

  const client = await Cdp.attach(target!.webSocketDebuggerUrl as string);
  await client.send("Page.enable", {});
  await client.send("Runtime.enable", {});
  await client.send("Network.enable", {});
  await client.send("Page.navigate", { url });

  let approvePosts = 0;
  client.on((msg) => {
    if (msg.method === "Network.requestWillBeSent") {
      const req = msg.params.request as { method: string; url: string };
      if (req.method === "POST" && /\/api\/requests\/[^/]+\/approve$/.test(req.url)) {
        approvePosts++;
      }
    }
  });

  return { cdp: client, approvePostCount: () => approvePosts };
}

async function api<T = unknown>(pathName: string, body?: unknown): Promise<T> {
  const response = await fetch(new URL(pathName, running!.url).toString(), {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "X-SGW-Console-Token": running!.token
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error((payload as { error?: string }).error || `HTTP ${response.status}`);
  }
  return payload as T;
}

async function clickElement(client: Cdp, selector: string): Promise<void> {
  const point = await client.eval<{ x: number; y: number }>(`(() => {
    const rect = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  })()`);
  await client.send("Input.dispatchMouseEvent", {
    type: "mousePressed",
    x: point.x,
    y: point.y,
    button: "left",
    clickCount: 1
  });
  await client.send("Input.dispatchMouseEvent", {
    type: "mouseReleased",
    x: point.x,
    y: point.y,
    button: "left",
    clickCount: 1
  });
}

async function chooseSelectOption(client: Cdp, triggerSelector: string, label: string): Promise<void> {
  await clickElement(client, triggerSelector);

  await waitFor(
    () => client.eval<boolean>(`[...document.querySelectorAll('[role="option"]')]
      .some((option) => option.textContent.trim() === ${JSON.stringify(label)})`),
    `select option ${label}`
  );
  const optionPoint = await client.eval<{ x: number; y: number }>(`(() => {
    const option = [...document.querySelectorAll('[role="option"]')]
      .find((node) => node.textContent.trim() === ${JSON.stringify(label)});
    const rect = option.getBoundingClientRect();
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  })()`);
  await client.send("Input.dispatchMouseEvent", {
    type: "mousePressed",
    x: optionPoint.x,
    y: optionPoint.y,
    button: "left",
    clickCount: 1
  });
  await client.send("Input.dispatchMouseEvent", {
    type: "mouseReleased",
    x: optionPoint.x,
    y: optionPoint.y,
    button: "left",
    clickCount: 1
  });
  await waitFor(
    () => client.eval<boolean>(`document.querySelector(${JSON.stringify(triggerSelector)}).innerText.trim() === ${JSON.stringify(label)}`),
    `selected ${label}`
  );
}

async function setEventSearch(client: Cdp, value: string): Promise<void> {
  await client.eval(`(() => {
    const input = document.querySelector('input[placeholder="Search every column"]');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
}

async function setCredentialSearch(client: Cdp, value: string): Promise<void> {
  await client.eval(`(() => {
    const input = document.querySelector('input[placeholder="Search credentials"]');
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
}

async function credentialNames(client: Cdp): Promise<string[]> {
  return client.eval<string[]>("[...document.querySelectorAll('[data-credential-name]')].map((node) => node.textContent.trim())");
}

async function firstCredentialName(client: Cdp): Promise<string> {
  return client.eval<string>("document.querySelector('[data-credential-name]')?.textContent?.trim() || ''");
}

async function waitFor(cond: () => Promise<unknown> | unknown, label: string, ms = 12_000): Promise<void> {
  const start = performance.now();
  for (;;) {
    try {
      if (await cond()) return;
    } catch {
      // keep polling while Chrome and the local daemon settle
    }
    if (performance.now() - start > ms) throw new Error(`timeout waiting for ${label}`);
    await delay(60);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface CdpMessage {
  id?: number;
  method?: string;
  params?: Record<string, unknown> & { request?: unknown };
  result?: unknown;
  error?: { message: string };
}

class Cdp {
  private nextId = 0;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private readonly listeners: Array<(msg: CdpMessage) => void> = [];

  private constructor(private readonly ws: CdpSocket) {
    ws.onmessage = (event) => {
      const msg = JSON.parse(String(event.data)) as CdpMessage;
      if (msg.id && this.pending.has(msg.id)) {
        const entry = this.pending.get(msg.id)!;
        this.pending.delete(msg.id);
        if (msg.error) entry.reject(new Error(msg.error.message));
        else entry.resolve(msg.result);
      } else if (msg.method) {
        for (const fn of this.listeners) fn(msg);
      }
    };
  }

  static async attach(wsUrl: string): Promise<Cdp> {
    const ws = await openSocket(wsUrl);
    await new Promise<void>((resolve, reject) => {
      ws.onopen = () => resolve();
      ws.onerror = () => reject(new Error("failed to open CDP websocket"));
    });
    return new Cdp(ws);
  }

  send(method: string, params: Record<string, unknown> = {}): Promise<unknown> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  on(fn: (msg: CdpMessage) => void): void {
    this.listeners.push(fn);
  }

  async eval<T = unknown>(expression: string): Promise<T> {
    const result = (await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true
    })) as { result: { value: T }; exceptionDetails?: { text: string } };
    if (result.exceptionDetails) throw new Error(`eval failed: ${result.exceptionDetails.text}`);
    return result.result.value;
  }

  dispose(): void {
    try {
      this.ws.close();
    } catch {
      // ignore
    }
  }
}

interface CdpSocket {
  onopen: (() => void) | null;
  onerror: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  send(data: string): void;
  close(): void;
}

async function openSocket(wsUrl: string): Promise<CdpSocket> {
  if (globalThis.WebSocket) {
    return new globalThis.WebSocket(wsUrl) as CdpSocket;
  }

  const { WebSocket: NodeWebSocket } = await import("ws");
  return new NodeWebSocket(wsUrl) as CdpSocket;
}
