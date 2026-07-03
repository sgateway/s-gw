import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

describe("React console source contracts", () => {
  it("builds as a separate Vite console app with shadcn components", async () => {
    const [pkgRaw, viteConfig, components] = await Promise.all([
      readFile(path.join(repoRoot, "package.json"), "utf8"),
      readFile(path.join(repoRoot, "vite.console.config.ts"), "utf8"),
      readFile(path.join(repoRoot, "components.json"), "utf8")
    ]);
    const pkg = JSON.parse(pkgRaw);

    expect(pkg.scripts["build:console-ui"]).toBe("vite build --config vite.console.config.ts");
    expect(pkg.scripts.check).toContain("tsconfig.console.json");
    expect(viteConfig).toContain('root: "src/console-ui"');
    expect(viteConfig).toContain('outDir: "../../dist/console-ui"');
    expect(components).toContain('"style": "radix-nova"');
    expect(components).toContain('"css": "src/console-ui/src/index.css"');
  });

  it("keeps API calls token-protected and dashboard layout persisted", async () => {
    const [api, layout, logo] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/lib/api.ts"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/lib/layout.ts"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/SgwLogo.tsx"), "utf8")
    ]);

    expect(api).toContain('"X-SGW-Console-Token"');
    expect(api).toContain("window.SGW_CONSOLE_TOKEN");
    expect(api).toContain("approveRequest");
    expect(api).toContain("denyRequest");
    expect(layout).toContain('sgw.dashboard.layout.v1');
    expect(layout).toContain("normalizeLayouts");
    expect(layout).toContain("panelIds");
    expect(logo).toContain("@/assets/s-gw-64.png");
  });

  it("uses provider logos and normalized secure-storage names", async () => {
    const [app, providerIdentity, presentation] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/ProviderIdentity.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/lib/credential-presentation.ts"), "utf8")
    ]);

    expect(app).toContain("<ProviderIdentity provider={handle.provider} backend={handle.backend} />");
    expect(app).toContain("credentialBackendLabel(handle.backend)");
    expect(app).toContain('className="table-fixed md:min-w-[900px]"');
    expect(app.indexOf('<TableHead className="w-[30%] md:w-[150px]">Provider</TableHead>')).toBeLessThan(
      app.indexOf('<TableHead className="w-[30%] md:w-[165px]">Backend</TableHead>')
    );
    expect(app).toContain('className="hidden w-[210px] md:table-cell"');
    expect(providerIdentity).toContain('@/assets/providers/1password.svg');
    expect(providerIdentity).toContain('@/assets/s-gw-64.png');
    expect(presentation).toContain('label: "1Password"');
    expect(presentation).toContain('label: "s-gw Local"');
    expect(presentation).toContain('return "macOS Keychain"');
    expect(presentation).toContain('return "Windows Credential Manager"');
  });

  it("keeps the static console demo dashboard aligned with the public usage map", async () => {
    const sampleData = await readFile(path.join(repoRoot, "src/console-ui/src/lib/sample-data.ts"), "utf8");
    const routeCounts = [...sampleData.matchAll(/usageFlowRow\([^,\n]+,\s*[^,\n]+,\s*[^,\n]+,\s*(\d+),/g)]
      .map((match) => Number(match[1]));
    const totalRequests = routeCounts.reduce((total, count) => total + count, 0);

    expect(totalRequests).toBe(630);
    expect(sampleData).toContain('provider: "ssh", label: "SSH"');
    expect(sampleData).toContain('sampleAgent("codex", "Codex"');
    expect(sampleData).toContain('sampleAgent("windsurf", "Windsurf"');
    expect(sampleData).toContain('"s-gw:private-key:web-prod-01"');
    expect(sampleData).toContain('"s-gw:api-token:registry-publish"');
    expect(sampleData).not.toMatch(/AgentSec|QNAP|XDR|private repos|aws-prod-deploy|nas-admin|local admin/i);
  });

  it("shows persistent policy enabled status beside the policy control", async () => {
    const app = await readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8");

    expect(app).toContain("function PolicyEnabledStatus");
    expect(app).toContain('<CheckCircle2 className="h-4 w-4" aria-hidden="true" />');
    expect(app).toContain('{enabled ? "Enabled" : "Disabled"}');
    expect(app).toContain('aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.name}`}');
    expect(app).toContain("<PolicyEnabledStatus enabled={rule.enabled} />");
  });

  it("makes agent integration cards actionable", async () => {
    const [app, server] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-server.ts"), "utf8")
    ]);

    expect(app).toContain("function AgentConfigurationSheet");
    expect(app).toContain("data-agent-mcp={agent.id}");
    expect(app).toContain("data-copy-agent-snippet");
    expect(app).toContain("Copy snippet");
    expect(app).toContain("document.execCommand(\"copy\")");
    expect(app).toContain("Guard mode");
    expect(app).toContain("CodeGuard integration");
    expect(server).toContain("renderAgentMcpSnippet(profile.id)");
    expect(server).toContain("getAgentCodeGuardPlan(profile.id)");
  });

  it("serves the React console by default with SPA fallback while preserving the legacy static console", async () => {
    const server = await readFile(path.join(repoRoot, "src/console-server.ts"), "utf8");

    expect(server).toContain("isBuiltReactUi");
    expect(server).toContain('path.resolve(here, "console-ui")');
    expect(server).toContain('path.resolve(here, "..", "dist", "console-ui")');
    expect(server).toContain("shouldServeSpaFallback");
    expect(server).toContain('path.basename(target) === "index.html"');
    expect(server).toContain('return path.resolve(here, "..", "docs", "ui")');
  });

  it("keeps the console sidebar branded, grouped, and icon-collapsible", async () => {
    const [app, css, sidebar] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/index.css"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/ui/sidebar.tsx"), "utf8")
    ]);

    expect(app).toContain("function ConsoleSidebar");
    expect(app).toContain('const navGroups: Array<{ label: string; items: ViewId[] }>');
    expect(app).toContain('<Sidebar collapsible="icon"');
    expect(app).toContain("sgw-sidebar-titlebar");
    expect(app).toContain("sgw-sidebar-expand-button");
    expect(app).toContain("sgw-sidebar-nav-button");
    expect(app).toContain("sgw-sidebar-footer-brand");
    expect(app).toContain("PanelRightOpen className=\"h-4 w-4\"");
    expect(css).toContain(".sgw-sidebar-footer-brand img");
    expect(css).toContain(".sgw-sidebar-expand-button");
    expect(css).toContain(".sgw-sidebar-nav-button[data-active=\"true\"]");
    expect(css).toContain('[data-slot="sidebar"][data-state="collapsed"] [data-sidebar="menu-button"]');
    expect(css).toContain('html[data-native-shell="1"] [data-slot="sidebar"][data-state="collapsed"] [data-slot="sidebar-header"]');
    expect(sidebar).toContain('const SIDEBAR_WIDTH_ICON = "3.75rem"');
    expect(sidebar).toContain("group-data-[collapsible=icon]:size-10!");
    expect(app).toContain("nativeShell ? \"min-h-screen pt-6\"");
    expect(app).toContain("text-2xl font-semibold");
    expect(app).toContain("tooltip={item.label}");
    expect(app).toContain("SidebarMenuBadge");
    expect(app).toContain("group-data-[collapsible=icon]:justify-center");
    expect(app).toContain("Collapse sidebar");
    expect(app).toContain("Expand sidebar");
  });

  it("keeps the mock-site-inspired console visual system", async () => {
    const [css, app, usageFlow] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/index.css"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/UsageFlowSankey.tsx"), "utf8")
    ]);

    expect(css).toContain("--background: #05080d");
    expect(css).toContain("--primary: #56e6ad");
    expect(css).toContain("--sidebar-primary: #3eb7ff");
    expect(css).toContain("--sidebar-accent: rgb(213 235 255 / 0.058)");
    expect(css).toContain("--chart-3: #2b9cff");
    expect(css).toContain("rgb(33 210 182 / 0.12)");
    expect(css).toContain("[data-slot=\"button\"][data-variant=\"default\"]");
    expect(css).toContain(".sgw-glass-panel");
    expect(css).toContain(".sgw-native-actions");
    expect(css).toContain('.sgw-native-action-button[data-size="icon"]');
    expect(css).toContain('html[data-native-shell="1"] [data-slot="sidebar-header"]');
    expect(app).toContain("sgw-topbar");
    expect(app).toContain("function ConsoleTopbar");
    expect(app).toContain("function NativeWindowActions");
    expect(app).toContain("onResetLayout={resetOverviewLayout}");
    expect(app).toContain('view === "overview"');
    expect(app).toContain("Reset layout</span>");
    expect(app).toContain("CommandIcon className=\"h-4 w-4\"");
    expect(app).toContain("setCommandOpen(true)} className=\"sgw-native-action-button\"");
    expect(app).toContain("ctx.loading ? <Loader2");
    expect(app).toContain("<AddCredentialDialog compact");
    expect(app).toContain('triggerClassName="sgw-native-action-button');
    expect(app).toContain("sgw-page-bg");
    expect(app).toContain("isNativeShellRoute");
    expect(app).toContain("sgw-policy-pie-motion");
    expect(app).toContain('data-policy-pie-motion={reduceMotion ? "static" : "animated"}');
    expect(app).toContain("isAnimationActive={!reduceMotion}");
    expect(app).toContain("animationBegin={400}");
    expect(app).toContain("animationDuration={1500}");
    expect(app).toContain('animationEasing="ease-out"');
    expect(css).toContain("border-radius: 0;");
    expect(css).toContain(".sgw-native-actions [data-slot=\"button\"]");
    expect(css).not.toContain(".sankey-flow-dots");
    expect(css).toContain("@media (prefers-reduced-motion: reduce)");
    expect(usageFlow).toContain('agent: "#5f78ff"');
    expect(usageFlow).toContain('auth: "#21d2b6"');
  });

  it("renders activity logs as truthful agent-to-action-to-target flows", async () => {
    const [app, activity, agentIcon, css] = await Promise.all([
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/ActivityFlowRow.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/components/AgentIcon.tsx"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/index.css"), "utf8")
    ]);

    expect(app).toContain('{ id: "audit", label: "Audit Log"');
    expect(app).toContain('["overview", "approvals", "credentials", "usage-flow", "activity", "audit"]');
    expect(app).toContain("function AuditLogView");
    expect(app).toContain("state.audit.filter((event) => isAgentActivityEvent(event, state))");
    expect(app).toContain('description="Complete local record of agent and s-gw security events."');
    expect(app).toContain("<EventLogTable");
    expect(app).toContain('mode="activity"');
    expect(app).toContain('mode="audit"');
    expect(app).toContain("describeEventFlow(event, state)");
    expect(app).toContain("<EventFlowDiagram flow={row.flow} />");
    expect(app).toContain('type EventColumnId = "source"');
    expect(app).toContain("const ACTIVITY_EVENT_COLUMN_ORDER");
    expect(app).toContain('"source", "eventType", "status"');
    expect(app).toContain("const AUDIT_EVENT_COLUMN_ORDER");
    expect(app).toContain('placeholder="Search every column"');
    expect(app).toContain("rowMatchesEventSearch(row, columns, search)");
    expect(app).toContain("rowMatchesColumnFilters(row, columns, columnFilters)");
    expect(app).toContain("compareEventRows(left, right, sortColumn, sortDirection)");
    expect(app).toContain("data-sort-column={column.id}");
    expect(app).toContain("data-event-filter-row");
    expect(app).toContain('<span className="sgw-event-source-cell">');
    expect(app).toContain('<AgentIcon name={row.flow.sourceLabel} className="h-6 w-6" />');
    expect(app).toContain("sgw-recent-event-panel");
    expect(app).toContain("data-overview-event-row");
    expect(app).toContain("RECENT_ACTIVITY_TABLE_HEADER_HEIGHT");
    expect(app).not.toContain("RECENT_ACTIVITY_DETAIL_HEIGHT");
    expect(app).not.toContain("<EventFlowDiagram flow={flow} compact />");
    expect(app).toContain('<AgentIcon name={flow.sourceLabel} className="h-6 w-6" />');
    expect(app).toContain("function recentEventKind(eventType: string)");
    expect(app).toContain('return "Grant"');
    expect(app).toContain("{recentEventKind(event.type)}");
    expect(activity).toContain("const lookupCache = new WeakMap<ConsoleState, ActivityLookups>()");
    expect(activity).toContain("new Map(state.requests.map");
    expect(activity).toContain('request?.action.kind === "ssh_session"');
    expect(activity).toContain('request.action.ssh.target.split("@")');
    expect(activity).toContain("function FlowConnector");
    expect(activity).toContain("export function describeEventFlow");
    expect(activity).toContain("export function EventFlowDiagram");
    expect(activity).toContain("badge: \"Security Controls\"");
    expect(activity).toContain("badge: \"Destination\"");
    expect(activity).toContain("export function isAgentActivityEvent");
    expect(activity).toContain("return request !== undefined");
    expect(activity).toContain('const agentName = request?.agentName || "s-gw"');
    expect(activity).not.toContain("agentFromMessage");
    expect(activity).toContain("<AgentIcon name={node.agentName}");
    expect(agentIcon).toContain('@/assets/agents/codex.png');
    expect(agentIcon).toContain('@/assets/agents/cursor.png');
    expect(agentIcon).toContain('@/assets/agents/claude.svg');
    expect(agentIcon).toContain('@/assets/agents/openclaw.png');
    expect(agentIcon).toContain('@/assets/agents/zeptoclaw.png');
    expect(agentIcon).toContain('@/assets/agents/hermes.png');
    expect(agentIcon).toContain('@/assets/agents/openhands.svg');
    expect(agentIcon).toContain('@/assets/agents/antigravity.png');
    expect(agentIcon).toContain('@/assets/agents/omnigent.png');
    expect(agentIcon).toContain('data-agent-icon-kind="app"');
    expect(app.match(/<AgentIcon/g)?.length || 0).toBeGreaterThanOrEqual(7);
    expect(app).not.toContain("<TerminalSquare");
    expect(css).toContain(".sgw-agent-icon-mark-image");
    expect(css).toContain(".sgw-activity-flow-path");
    expect(css).toContain(".sgw-activity-node-icon");
    expect(css).toContain(".sgw-activity-node-copy");
    expect(css).toContain(".sgw-event-log-card");
    expect(css).toContain(".sgw-event-filter-row");
    expect(css).toContain(".sgw-event-sort-button");
    expect(css).toContain(".sgw-event-column-filter-chip");
    expect(css).toContain(".sgw-event-source-cell");
    expect(css).toContain(".sgw-event-table");
    expect(css).toContain(".sgw-event-detail-stage");
    expect(css).toContain(".sgw-event-flow-card");
    expect(css).toContain(".sgw-recent-event-panel");
    expect(css).toContain(".sgw-recent-event-table");
    expect(css).not.toContain(".sgw-recent-event-detail");
    expect(css).toContain("minmax(8rem, 0.7fr) minmax(5.5rem, 0.5fr)");
    expect(css).toContain("white-space: nowrap;");
    expect(css).toContain(".sgw-event-detail-stage.is-compact");
    expect(css).toContain("max-width: 100%");
    expect(css).toContain(".sgw-activity-flow-row.is-compact .sgw-activity-node-detail");
    expect(css).toContain("grid-template-columns: minmax(0, 1fr) auto;");
    expect(app).toContain("data-recent-activity-list");
    expect(app).toContain("Math.floor(availableForRows / RECENT_ACTIVITY_ROW_HEIGHT)");
    expect(app).toContain("activityRows.slice(0, visibleCount)");
    expect(css).toContain("height: 44px;");
  });
});
