import * as React from "react";
import { Responsive, type Layout, type LayoutItem, type ResponsiveLayouts as Layouts } from "react-grid-layout";
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Ban,
  Bell,
  CheckCircle2,
  ChevronDown,
  Circle,
  Clock3,
  Command as CommandIcon,
  Copy,
  Download,
  ExternalLink,
  FileKey2,
  Gauge,
  GripHorizontal,
  Info,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  Loader2,
  LockKeyhole,
  MoreVertical,
  Network,
  PanelRightOpen,
  Pencil,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  ScrollText,
  Trash2,
  UsersRound,
  Wand2,
  X
} from "lucide-react";
import { Cell, Pie, PieChart } from "recharts";
import { toast } from "sonner";

import { SgwLogo } from "@/components/SgwLogo";
import { AgentIcon } from "@/components/AgentIcon";
import { ProviderIdentity } from "@/components/ProviderIdentity";
import { EventFlowDiagram, describeEventFlow, isAgentActivityEvent } from "@/components/ActivityFlowRow";
import { UsageFlowSankey } from "@/components/UsageFlowSankey";
import { MultiSelectField, type MultiSelectOption } from "@/components/MultiSelectField";
import { useElementSize } from "@/hooks/use-element-size";
import { useReducedMotion } from "@/hooks/use-reduced-motion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut
} from "@/components/ui/command";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle
} from "@/components/ui/sheet";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar
} from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import {
  addPolicy,
  approveRequest,
  approveRequestWithScopedPolicy,
  arrangePolicies,
  auditCsvUrl,
  clearGrants,
  createSecret,
  deletePolicy,
  deleteSecret,
  denyRequest,
  fetchConsoleState,
  installAgentIntegration,
  saveApprovalSettings,
  setPolicyEnabled,
  updatePolicy,
  uninstallAgentIntegration
} from "@/lib/api";
import type { PolicyInput } from "@/lib/api";
import {
  DASHBOARD_LAYOUT_KEY,
  defaultLayouts,
  normalizeLayouts,
  panelIds,
  readSavedLayouts,
  resetLayouts,
  saveLayouts,
  type PanelId
} from "@/lib/layout";
import { credentialBackendLabel, credentialProviderPresentation } from "@/lib/credential-presentation";
import { addDemoData, DEMO_DATA_STORAGE_KEY } from "@/lib/demo-data";
import { findShadowingPolicyRule } from "../../policy-order";
import {
  commandName,
  durationLabel,
  policyConditionSummary,
  relativeTime,
  requestTarget,
  severityRank,
  shortHandle,
  titleCase
} from "@/lib/format";
import type {
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyDecision,
  ApprovalPolicyRuleRecord,
  AgentSummary,
  ConsoleState,
  HandleSummary,
  RequestRecord,
  SecretSeverity,
  UsageFlowRow
} from "@/lib/types";
import { cn } from "@/lib/utils";

const ResponsiveGridLayout = Responsive;

type ViewId = "overview" | "approvals" | "credentials" | "usage-flow" | "policies" | "agents" | "activity" | "audit" | "settings";

type NavItem = {
  id: ViewId;
  label: string;
  detail: string;
  icon: React.ComponentType<{ className?: string }>;
  dataNav?: string;
};

const navItems: NavItem[] = [
  { id: "overview", label: "Overview", detail: "System posture", icon: LayoutDashboard },
  { id: "approvals", label: "Approvals", detail: "Requests waiting", icon: Bell },
  { id: "credentials", label: "Credentials", detail: "Local handles", icon: KeyRound },
  { id: "usage-flow", label: "Usage Flow", detail: "Credential paths", icon: Network, dataNav: "flow" },
  { id: "policies", label: "Policies", detail: "Reusable rules", icon: ShieldCheck },
  { id: "agents", label: "Agents", detail: "Integration profiles", icon: UsersRound },
  { id: "activity", label: "Activity", detail: "Agent operations", icon: Activity },
  { id: "audit", label: "Audit Log", detail: "Complete record", icon: ScrollText },
  { id: "settings", label: "Settings", detail: "App preferences", icon: Settings }
];

const navGroups: Array<{ label: string; items: ViewId[] }> = [
  { label: "Operate", items: ["overview", "approvals", "credentials", "usage-flow", "activity", "audit"] },
  { label: "Configure", items: ["policies", "agents", "settings"] }
];

const panelTitles: Record<PanelId, string> = {
  readiness: "Operational readiness",
  approvals: "Pending approvals",
  credentials: "Credential handles",
  usageFlow: "Usage Flow",
  policy: "Policy coverage",
  agents: "Agents",
  activity: "Recent activity"
};

const panelIcons: Record<PanelId, React.ComponentType<{ className?: string }>> = {
  readiness: ShieldCheck,
  approvals: Clock3,
  credentials: KeyRound,
  usageFlow: Network,
  policy: Shield,
  agents: UsersRound,
  activity: Activity
};

const RECENT_ACTIVITY_ROW_HEIGHT = 44;
const RECENT_ACTIVITY_TABLE_HEADER_HEIGHT = 38;

function App() {
  const [theme, setTheme] = React.useState(() => localStorage.getItem("sgw.theme") || "dark");
  const nativeShell = isNativeShellRoute();
  const embedView = embeddedView();
  const menuBar = window.location.pathname === "/menubar";

  React.useEffect(() => {
    document.documentElement.classList.toggle("light", theme === "light");
    document.documentElement.classList.toggle("dark", theme !== "light");
    localStorage.setItem("sgw.theme", theme);
  }, [theme]);

  React.useEffect(() => {
    document.documentElement.dataset.nativeShell = nativeShell ? "1" : "0";
    return () => {
      delete document.documentElement.dataset.nativeShell;
    };
  }, [nativeShell]);

  if (embedView) {
    return (
      <TooltipProvider>
        <ConsoleProvider>
          {(ctx) => <EmbeddedSurface ctx={ctx} compact={embedView.compact} />}
        </ConsoleProvider>
        <Toaster richColors theme={theme === "light" ? "light" : "dark"} />
      </TooltipProvider>
    );
  }

  if (menuBar) {
    return (
      <TooltipProvider>
        <ConsoleProvider>
          {(ctx) => <MenubarSurface ctx={ctx} />}
        </ConsoleProvider>
        <Toaster richColors theme={theme === "light" ? "light" : "dark"} />
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <ConsoleProvider>
        {(ctx) => <ConsoleShell ctx={ctx} theme={theme} setTheme={setTheme} />}
      </ConsoleProvider>
      <Toaster richColors theme={theme === "light" ? "light" : "dark"} />
    </TooltipProvider>
  );
}

function ConsoleProvider({ children }: { children: (ctx: ConsoleContext) => React.ReactNode }) {
  const [state, setState] = React.useState<ConsoleState | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const refresh = React.useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const next = await fetchConsoleState();
      setState(next);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(true), 5000);
    return () => window.clearInterval(id);
  }, [refresh]);

  const ctx = React.useMemo(() => ({ state, loading, error, refresh }), [state, loading, error, refresh]);
  return <>{children(ctx)}</>;
}

interface ConsoleContext {
  state: ConsoleState | null;
  loading: boolean;
  error: string | null;
  refresh: (quiet?: boolean) => Promise<void>;
}

function ConsoleShell({ ctx, theme, setTheme }: { ctx: ConsoleContext; theme: string; setTheme: (value: string) => void }) {
  const [view, setViewState] = React.useState<ViewId>(() => viewFromLocation());
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [approval, setApproval] = React.useState<RequestRecord | null>(null);
  const [credential, setCredential] = React.useState<HandleSummary | null>(null);
  const [overviewLayouts, setOverviewLayouts] = React.useState<Layouts>(() => readSavedLayouts());
  const [demoEnabled, setDemoEnabled] = React.useState(() => localStorage.getItem(DEMO_DATA_STORAGE_KEY) === "1");
  const nativeShell = isNativeShellRoute();

  React.useEffect(() => {
    const onPop = () => setViewState(viewFromLocation());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  React.useEffect(() => {
    if (!approval || approval.demo || !ctx.state) return;
    const current = ctx.state.requests.find((request) => request.id === approval.id);
    if (current?.state === "pending") {
      if (current !== approval) setApproval(current);
      return;
    }

    setApproval(null);
    if (current?.state === "approved" || current?.state === "executing" || current?.state === "executed") {
      toast.success("Request already approved");
      return;
    }
    toast.info(current ? `Request is already ${current.state}` : "Request is no longer pending");
  }, [approval, ctx.state]);

  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const setView = React.useCallback((next: ViewId) => {
    setViewState(next);
    const path = next === "overview" ? "/overview" : `/${next}`;
    const shellQuery = isNativeShellRoute() ? "?native-shell=1" : "";
    window.history.pushState({}, "", `${path}${shellQuery}`);
  }, []);

  const state = React.useMemo(
    () => ctx.state && demoEnabled ? addDemoData(ctx.state) : ctx.state,
    [ctx.state, demoEnabled]
  );
  const displayCtx = React.useMemo(() => ({ ...ctx, state }), [ctx, state]);
  const toggleDemoData = React.useCallback(() => {
    setDemoEnabled((current) => {
      const next = !current;
      if (next) localStorage.setItem(DEMO_DATA_STORAGE_KEY, "1");
      else localStorage.removeItem(DEMO_DATA_STORAGE_KEY);
      toast.success(next ? "Demo data added" : "Demo data removed");
      return next;
    });
  }, []);
  const resetOverviewLayout = React.useCallback(() => {
    const next = resetLayouts();
    setOverviewLayouts(next);
    toast.success("Dashboard layout reset");
  }, []);

  return (
    <SidebarProvider className="sgw-console-shell">
      <ConsoleSidebar state={state} view={view} setView={setView} />

      <SidebarInset className="sgw-console-main min-w-0 bg-transparent">
        {nativeShell ? (
          <NativeWindowActions
            ctx={displayCtx}
            state={state}
            theme={theme}
            setTheme={setTheme}
            setView={setView}
            view={view}
            onResetLayout={resetOverviewLayout}
            setCommandOpen={setCommandOpen}
            demoEnabled={demoEnabled}
            onToggleDemoData={toggleDemoData}
          />
        ) : (
          <ConsoleTopbar
            ctx={displayCtx}
            state={state}
            theme={theme}
            setTheme={setTheme}
            setView={setView}
            search={search}
            setSearch={setSearch}
            setCommandOpen={setCommandOpen}
          />
        )}

        <main className={cn("sgw-page-bg bg-transparent", nativeShell ? "min-h-screen pt-6" : "min-h-[calc(100vh-4rem)]")}>
          {ctx.error ? (
            <Alert variant="destructive" className="m-4">
              <AlertTriangle className="h-4 w-4" />
              <AlertTitle>Console connection issue</AlertTitle>
              <AlertDescription>{ctx.error}</AlertDescription>
            </Alert>
          ) : null}
          {!nativeShell && state?.update?.available && state.update.latestVersion && state.update.releaseUrl ? (
            <Alert data-update-banner className="m-4 mb-0 border-primary/35 bg-primary/5">
              <Download className="h-4 w-4" />
              <AlertTitle>s-gw {state.update.latestVersion} is available</AlertTitle>
              <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
                <span>Installed {state.version}. Review the release before upgrading.</span>
                <Button asChild size="sm" variant="outline">
                  <a href={state.update.releaseUrl} target="_blank" rel="noreferrer">
                    View release
                    <ExternalLink className="h-4 w-4" />
                  </a>
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}
          <ViewContent
            ctx={displayCtx}
            view={view}
            setView={setView}
            setApproval={setApproval}
            setCredential={setCredential}
            nativeShell={nativeShell}
            layouts={overviewLayouts}
            setLayouts={setOverviewLayouts}
            onResetLayout={resetOverviewLayout}
            search={search}
            setSearch={setSearch}
          />
        </main>
      </SidebarInset>

      <ApprovalSheet request={approval} state={state} onOpenChange={(open) => !open && setApproval(null)} onDone={() => void ctx.refresh()} />
      <CredentialSheet credential={credential} onOpenChange={(open) => !open && setCredential(null)} onDone={() => void ctx.refresh()} />
      <CommandPalette open={commandOpen} onOpenChange={setCommandOpen} setView={setView} state={state} />
    </SidebarProvider>
  );
}

function ConsoleTopbar({
  ctx,
  state,
  theme,
  setTheme,
  setView,
  search,
  setSearch,
  setCommandOpen
}: {
  ctx: ConsoleContext;
  state: ConsoleState | null;
  theme: string;
  setTheme: (value: string) => void;
  setView: (view: ViewId) => void;
  search: string;
  setSearch: (value: string) => void;
  setCommandOpen: (open: boolean) => void;
}) {
  return (
    <header className="sgw-topbar sticky top-0 z-30 flex h-16 items-center gap-2 overflow-hidden border-b bg-transparent px-3 backdrop-blur sm:gap-3 sm:px-4">
      <SidebarTrigger />
      <div className="relative hidden min-w-0 flex-1 md:block md:max-w-md">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search or run a command..."
          className="pl-9"
          onFocus={() => setCommandOpen(true)}
        />
      </div>
      <StatusPill ok={state?.status.daemonRunning} label="Local daemon running" />
      <StatusPill ok={state?.status.unlock.activeSource !== "none"} label="Credential store unlocked" />
      <Button variant="outline" onClick={() => setView("approvals")} className="gap-2 px-2 sm:px-3">
        <Bell className="h-4 w-4" />
        <span className="sr-only sm:not-sr-only">Approve Queue</span>
        {state?.metrics.pendingApprovals ? <Badge>{state.metrics.pendingApprovals}</Badge> : null}
      </Button>
      <AddCredentialDialog onDone={() => void ctx.refresh()} />
      <Button variant="outline" size="icon" onClick={() => void ctx.refresh()}>
        {ctx.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
      </Button>
      <Select value={theme} onValueChange={setTheme}>
        <SelectTrigger className="hidden w-28 sm:flex">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="dark">Dark</SelectItem>
          <SelectItem value="light">Light</SelectItem>
        </SelectContent>
      </Select>
    </header>
  );
}

function NativeWindowActions({
  ctx,
  state,
  theme,
  setTheme,
  setView,
  view,
  onResetLayout,
  setCommandOpen,
  demoEnabled,
  onToggleDemoData
}: {
  ctx: ConsoleContext;
  state: ConsoleState | null;
  theme: string;
  setTheme: (value: string) => void;
  setView: (view: ViewId) => void;
  view: ViewId;
  onResetLayout: () => void;
  setCommandOpen: (open: boolean) => void;
  demoEnabled: boolean;
  onToggleDemoData: () => void;
}) {
  const pendingCount = state?.metrics.pendingApprovals || 0;
  const nextTheme = theme === "light" ? "dark" : "light";

  return (
    <div className="sgw-native-actions">
      <Button variant="outline" size="icon" onClick={() => setCommandOpen(true)} className="sgw-native-action-button">
        <CommandIcon className="h-4 w-4" />
        <span className="sr-only">Command Palette</span>
      </Button>
      <Button variant="outline" onClick={() => setView("approvals")} className="sgw-native-action-button gap-2 px-2.5">
        <Bell className="h-4 w-4" />
        <span className="hidden md:inline">Approve Queue</span>
        {pendingCount ? <Badge>{pendingCount}</Badge> : null}
      </Button>
      {view === "overview" ? (
        <Button variant="outline" onClick={onResetLayout} className="sgw-native-action-button gap-2 px-2.5">
          <RotateCcw className="h-4 w-4" />
          <span className="hidden md:inline">Reset layout</span>
        </Button>
      ) : null}
      <AddCredentialDialog compact triggerClassName="sgw-native-action-button sgw-native-action-add" onDone={() => void ctx.refresh()} />
      <Button variant="outline" size="icon" onClick={() => void ctx.refresh()} className="sgw-native-action-button">
        {ctx.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
        <span className="sr-only">Refresh</span>
      </Button>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" className="sgw-native-action-button" data-native-more-actions>
            <MoreVertical className="h-4 w-4" />
            <span className="sr-only">More actions</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>s-gw</DropdownMenuLabel>
          <DropdownMenuItem onSelect={() => setView("settings")}>Settings</DropdownMenuItem>
          <DropdownMenuItem onSelect={onToggleDemoData} data-demo-data-toggle>
            {demoEnabled ? "Remove demo data" : "Demo data"}
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setTheme(nextTheme)}>
            Use {nextTheme} theme
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setView("activity")}>Activity</DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setView("audit")}>Audit Log</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

function ConsoleSidebar({
  state,
  view,
  setView
}: {
  state: ConsoleState | null;
  view: ViewId;
  setView: (view: ViewId) => void;
}) {
  const { setOpen } = useSidebar();
  const navById = React.useMemo(() => new Map(navItems.map((item) => [item.id, item])), []);

  const itemCount = (id: ViewId) => {
    if (!state) return 0;
    if (id === "approvals") return state.metrics.pendingApprovals;
    if (id === "credentials") return state.metrics.localSecrets;
    if (id === "agents") return state.metrics.activeAgents;
    return 0;
  };

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border/80">
      <SidebarHeader className="sgw-sidebar-header h-14 justify-center px-3 group-data-[collapsible=icon]:px-2">
        <div className="sgw-sidebar-titlebar flex w-full items-center justify-end gap-2 group-data-[collapsible=icon]:justify-center">
          <Tooltip>
            <TooltipTrigger asChild>
              <SidebarTrigger className="sgw-sidebar-titlebar-trigger h-8 w-8 shrink-0 rounded-md text-sidebar-foreground hover:bg-sidebar-accent group-data-[collapsible=icon]:hidden" />
            </TooltipTrigger>
            <TooltipContent side="right">Collapse sidebar</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setOpen(true)}
                className="sgw-sidebar-expand-button hidden shrink-0 rounded-lg text-sidebar-foreground hover:bg-sidebar-accent group-data-[collapsible=icon]:inline-flex"
              >
                <PanelRightOpen className="h-4 w-4" />
                <span className="sr-only">Expand sidebar</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent side="right">Expand sidebar</TooltipContent>
          </Tooltip>
        </div>
      </SidebarHeader>

      <SidebarContent className="gap-2 px-2 pb-2">
        {navGroups.map((group) => (
          <SidebarGroup key={group.label} className="p-0">
            <SidebarGroupLabel className="px-2 text-[0.68rem] font-semibold uppercase tracking-normal text-sidebar-foreground/45">
              {group.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu className="gap-1">
                {group.items.map((id) => {
                  const item = navById.get(id);
                  if (!item) return null;
                  const Icon = item.icon;
                  const count = itemCount(item.id);
                  const active = view === item.id;

                  return (
                    <SidebarMenuItem key={item.id} className="overflow-hidden rounded-lg">
                      <span
                        className={cn(
                          "pointer-events-none absolute left-0 top-1/2 h-6 w-1 -translate-y-1/2 rounded-r-full bg-sidebar-primary transition-opacity",
                          active ? "opacity-100" : "opacity-0"
                        )}
                      />
                      <SidebarMenuButton
                        data-nav={item.dataNav || item.id}
                        isActive={active}
                        size="lg"
                        tooltip={item.label}
                        onClick={() => setView(item.id)}
                        className={cn(
                          "sgw-sidebar-nav-button h-11 rounded-lg border px-2.5",
                          "group-data-[collapsible=icon]:mx-auto group-data-[collapsible=icon]:h-9 group-data-[collapsible=icon]:w-9 group-data-[collapsible=icon]:justify-center"
                        )}
                      >
                        <Icon className="h-4.5 w-4.5" />
                        <span className="min-w-0 flex-1 group-data-[collapsible=icon]:hidden">
                          <span className="block truncate text-sm leading-4">{item.label}</span>
                          <span className="block truncate text-[0.72rem] leading-4 text-sidebar-foreground/55 group-data-[active=true]/menu-button:text-sidebar-foreground/68">
                            {item.detail}
                          </span>
                        </span>
                      </SidebarMenuButton>
                      {count > 0 ? (
                        <SidebarMenuBadge className="right-2 top-3 bg-sidebar-primary/16 text-sidebar-primary">
                          {count > 99 ? "99+" : count}
                        </SidebarMenuBadge>
                      ) : null}
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter className="gap-3 p-3 group-data-[collapsible=icon]:items-center group-data-[collapsible=icon]:px-2">
        <div className="sgw-glass-panel w-full rounded-lg border border-sidebar-border/70 bg-sidebar-accent/35 p-3 text-xs shadow-sm group-data-[collapsible=icon]:flex group-data-[collapsible=icon]:h-10 group-data-[collapsible=icon]:w-10 group-data-[collapsible=icon]:items-center group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:rounded-lg group-data-[collapsible=icon]:border-transparent group-data-[collapsible=icon]:bg-transparent group-data-[collapsible=icon]:p-0">
          <div className="flex items-center gap-2 font-medium">
            <span className={cn("h-2.5 w-2.5 rounded-full", state?.ready ? "bg-emerald-400" : "bg-amber-400")} />
            <span className="group-data-[collapsible=icon]:hidden">Local profile</span>
          </div>
          <div className="mt-3 flex items-center gap-3 text-sidebar-foreground/70 group-data-[collapsible=icon]:hidden">
            <SgwLogo className="sgw-sidebar-footer-brand min-w-0 shrink-0" />
            <div className="min-w-0">
              <div className="text-[0.66rem] uppercase tracking-normal">Version</div>
              <div className="truncate font-medium text-sidebar-foreground">v{state?.version || "0.1.0"}</div>
            </div>
            <div className="ml-auto text-right">
              <div className="text-[0.66rem] uppercase tracking-normal">Queue</div>
              <div className="font-medium text-sidebar-foreground">{state?.metrics.pendingApprovals || 0}</div>
            </div>
          </div>
        </div>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}

function ViewContent({
  ctx,
  view,
  setView,
  setApproval,
  setCredential,
  nativeShell,
  layouts,
  setLayouts,
  onResetLayout,
  search,
  setSearch
}: {
  ctx: ConsoleContext;
  view: ViewId;
  setView: (view: ViewId) => void;
  setApproval: (request: RequestRecord) => void;
  setCredential: (credential: HandleSummary) => void;
  nativeShell: boolean;
  layouts: Layouts;
  setLayouts: (layouts: Layouts) => void;
  onResetLayout: () => void;
  search: string;
  setSearch: (value: string) => void;
}) {
  if (ctx.loading && !ctx.state) return <LoadingDashboard />;
  if (!ctx.state) return null;

  switch (view) {
    case "approvals":
      return <ApprovalsView state={ctx.state} setApproval={setApproval} search={search} />;
    case "credentials":
      return <CredentialsView state={ctx.state} setCredential={setCredential} search={search} setSearch={setSearch} />;
    case "usage-flow":
      return <UsageFlowView state={ctx.state} />;
    case "policies":
      return <PoliciesView state={ctx.state} onDone={() => void ctx.refresh()} search={search} />;
    case "agents":
      return <AgentsView state={ctx.state} search={search} onDone={() => ctx.refresh(true)} />;
    case "activity":
      return <ActivityView state={ctx.state} search={search} setSearch={setSearch} />;
    case "audit":
      return <AuditLogView state={ctx.state} search={search} setSearch={setSearch} />;
    case "settings":
      return <SettingsView state={ctx.state} onDone={() => ctx.refresh()} />;
    default:
      return (
        <OverviewDashboard
          state={ctx.state}
          setView={setView}
          setApproval={setApproval}
          setCredential={setCredential}
          nativeShell={nativeShell}
          layouts={layouts}
          setLayouts={setLayouts}
          onResetLayout={onResetLayout}
        />
      );
  }
}

function OverviewDashboard({
  state,
  setView,
  setApproval,
  setCredential,
  nativeShell,
  layouts,
  setLayouts,
  onResetLayout
}: {
  state: ConsoleState;
  setView: (view: ViewId) => void;
  setApproval: (request: RequestRecord) => void;
  setCredential: (credential: HandleSummary) => void;
  nativeShell: boolean;
  layouts: Layouts;
  setLayouts: (layouts: Layouts) => void;
  onResetLayout: () => void;
}) {
  const [gridRef, gridSize] = useElementSize<HTMLDivElement>();

  const onLayoutChange = (_layout: Layout, allLayouts: Layouts) => {
    const normalized = normalizeLayouts(allLayouts);
    setLayouts(normalized);
    saveLayouts(normalized);
  };

  const panelBody = (id: PanelId) => {
    switch (id) {
      case "readiness":
        return <ReadinessPanel state={state} />;
      case "approvals":
        return <PendingApprovalsPanel state={state} setApproval={setApproval} setView={setView} />;
      case "credentials":
        return <CredentialHandlesPanel state={state} setView={setView} setCredential={setCredential} />;
      case "usageFlow":
        return <UsageFlowPanel state={state} setView={setView} />;
      case "policy":
        return <PolicyCoveragePanel state={state} setView={setView} />;
      case "agents":
        return <AgentsPanel state={state} setView={setView} />;
      case "activity":
        return <RecentActivityPanel state={state} setView={setView} />;
    }
  };

  return (
    <div className="sgw-page-frame space-y-4 p-4 lg:p-5">
      <PageHeading title="Overview" description="Real-time security posture and usage overview" />
      {!state.ready ? <ReadinessAlert state={state} /> : null}
      {!nativeShell ? (
        <div className="flex justify-end">
          <Button
            variant="outline"
            onClick={onResetLayout}
          >
            Reset layout
          </Button>
        </div>
      ) : null}
      <div ref={gridRef}>
        {gridSize.width > 0 ? (
          <ResponsiveGridLayout
            className="layout"
            width={gridSize.width}
            layouts={layouts}
            breakpoints={{ lg: 1100, md: 760, sm: 0 }}
            cols={{ lg: 12, md: 8, sm: 1 }}
            rowHeight={82}
            margin={[16, 16]}
            containerPadding={[0, 0]}
            dragConfig={{ enabled: true, bounded: false, handle: ".sgw-drag-handle", cancel: "button,a,input,textarea,[role=button]", threshold: 3 }}
            resizeConfig={{ enabled: true, handles: ["se"] }}
            onLayoutChange={onLayoutChange}
          >
            {panelIds.map((id) => (
              <div key={id}>
                <DashboardCard panelId={id} layouts={layouts} setLayouts={setLayouts}>
                  {panelBody(id)}
                </DashboardCard>
              </div>
            ))}
          </ResponsiveGridLayout>
        ) : null}
      </div>
    </div>
  );
}

function DashboardCard({
  panelId,
  layouts,
  setLayouts,
  children
}: {
  panelId: PanelId;
  layouts: Layouts;
  setLayouts: (layouts: Layouts) => void;
  children: React.ReactNode;
}) {
  const Icon = panelIcons[panelId];
  const apply = (fn: (item: LayoutItem) => LayoutItem) => {
    const next: Layouts = {};
    for (const [breakpoint, layout] of Object.entries(layouts)) {
      const current = (layout || []) as Layout;
      next[breakpoint] = current.map((item) => (item.i === panelId ? fn(item) : item));
    }
    const normalized = normalizeLayouts(next);
    setLayouts(normalized);
    saveLayouts(normalized);
  };

  return (
    <Card className="flex h-full min-h-0 flex-col overflow-hidden border-border/70 bg-card/80 shadow-sm">
      <CardHeader className="sgw-drag-handle flex cursor-move flex-row items-center justify-between space-y-0 px-4 py-3">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <Icon className="h-4 w-4 text-primary" />
          {panelTitles[panelId]}
        </CardTitle>
        <div className="flex items-center gap-1">
          <GripHorizontal className="h-4 w-4 text-muted-foreground" />
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon-sm" className="h-7 w-7">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Panel layout</DropdownMenuLabel>
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, y: Math.max(0, item.y - 3) }))}>Move earlier</DropdownMenuItem>
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, y: item.y + 3 }))}>Move later</DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, w: Math.max(item.minW || 2, 3), h: Math.max(item.minH || 2, 3) }))}>Size small</DropdownMenuItem>
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, w: Math.max(item.minW || 3, 6), h: Math.max(item.minH || 3, 4) }))}>Size medium</DropdownMenuItem>
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, w: 12, h: Math.max(item.h, 4) }))}>Size wide</DropdownMenuItem>
              <DropdownMenuItem onClick={() => apply((item) => ({ ...item, h: item.h + 2 }))}>Size tall</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </CardHeader>
      <CardContent className="min-h-0 flex-1 overflow-hidden px-4 pb-4">{children}</CardContent>
    </Card>
  );
}

function ReadinessPanel({ state }: { state: ConsoleState }) {
  const rows = [
    ["Local daemon", state.status.daemonRunning ? "Running" : "Stopped", state.status.daemonRunning],
    ["Credential store", state.status.unlock.activeSource !== "none" ? "Unlocked" : "Locked", state.status.unlock.activeSource !== "none"],
    ["Policy engine", "Active", true],
    ["Audit logging", "Enabled", true]
  ] as const;
  return (
    <div className="grid gap-3">
      {rows.map(([label, value, ok]) => (
        <div key={label} className="flex items-center justify-between gap-3 text-sm">
          <span className="flex items-center gap-2">
            {ok ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <AlertTriangle className="h-4 w-4 text-amber-400" />}
            {label}
          </span>
          <span className="text-muted-foreground">{value}</span>
        </div>
      ))}
    </div>
  );
}

function PendingApprovalsPanel({ state, setApproval, setView }: { state: ConsoleState; setApproval: (request: RequestRecord) => void; setView: (view: ViewId) => void }) {
  const first = state.pendingRequests[0];
  return (
    <div className="flex h-full flex-col justify-between gap-3">
      <div>
        <div className="text-4xl font-semibold">{state.metrics.pendingApprovals}</div>
        <div className="mt-1 text-sm text-amber-700 dark:text-amber-300">{state.metrics.pendingApprovals ? "Approval needed" : "No pending approvals"}</div>
      </div>
      {first ? (
        <div className="rounded-md border bg-muted/25 p-3 text-sm">
          <div className="flex items-center gap-2 font-medium">
            <AgentIcon name={first.agentName} className="h-7 w-7" />
            <span>{first.agentName || "Agent"}</span>
          </div>
          <div className="text-muted-foreground">{commandName(first)} · {requestTarget(first)}</div>
          <Button className="mt-3 w-full" onClick={() => setApproval(first)} data-approve={first.id}>Review request</Button>
        </div>
      ) : (
        <Button variant="outline" onClick={() => setView("approvals")}>Open approvals</Button>
      )}
    </div>
  );
}

function CredentialHandlesPanel({
  state,
  setView,
  setCredential
}: {
  state: ConsoleState;
  setView: (view: ViewId) => void;
  setCredential: (credential: HandleSummary) => void;
}) {
  return (
    <div className="min-h-0">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Provider</TableHead>
            <TableHead className="text-right">Secrets</TableHead>
            <TableHead>Severity</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {state.credentials.slice(0, 5).map((item) => (
            <TableRow key={item.provider} className="cursor-pointer" onClick={() => setView("credentials")}>
              <TableCell className="font-medium">
                <span className="flex items-center gap-2">
                  {item.demo ? item.label : <ProviderIdentity provider={item.provider} />}
                  {item.demo ? <DemoBadge /> : null}
                </span>
              </TableCell>
              <TableCell className="text-right">{item.secrets}</TableCell>
              <TableCell><SeverityBadge severity={item.severity} /></TableCell>
            </TableRow>
          ))}
          {state.credentials.length === 0 ? (
            <TableRow>
              <TableCell colSpan={3} className="text-muted-foreground">No credentials yet</TableCell>
            </TableRow>
          ) : null}
        </TableBody>
      </Table>
      {state.handles[0] ? (
        <Button variant="link" className="mt-2 px-0" onClick={() => setCredential(state.handles[0])}>Inspect newest handle</Button>
      ) : null}
    </div>
  );
}

function UsageFlowPanel({ state, setView }: { state: ConsoleState; setView: (view: ViewId) => void }) {
  return (
    <UsageFlowSankey
      flow={state.usageFlow}
      compact
      className="h-full min-h-0"
      onExpand={() => setView("usage-flow")}
    />
  );
}

function PolicyCoveragePanel({ state, setView }: { state: ConsoleState; setView: (view: ViewId) => void }) {
  const reduceMotion = useReducedMotion();
  const allowed = state.approvalPolicyRules.filter((rule) => rule.enabled && rule.decision === "allow").length;
  const ask = state.approvalPolicyRules.filter((rule) => rule.enabled && rule.decision === "ask").length;
  const denied = state.approvalPolicyRules.filter((rule) => rule.enabled && rule.decision === "deny").length;
  const data = [
    { name: "Allowed", value: Math.max(allowed, 1), fill: "var(--color-allowed)" },
    { name: "Ask", value: Math.max(ask, 1), fill: "var(--color-ask)" },
    { name: "Denied", value: Math.max(denied, 1), fill: "var(--color-denied)" }
  ];
  const chartConfig = {
    allowed: { label: "Allowed", color: "oklch(0.72 0.18 145)" },
    ask: { label: "Ask", color: "oklch(0.76 0.18 75)" },
    denied: { label: "Denied", color: "oklch(0.64 0.205 28)" }
  } satisfies ChartConfig;

  return (
    <div className="grid h-full grid-cols-[1fr_auto] items-center gap-2">
      <ChartContainer
        config={chartConfig}
        className="sgw-policy-pie-motion mx-auto aspect-square h-full max-h-44"
        data-policy-pie-motion={reduceMotion ? "static" : "animated"}
      >
        <PieChart margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
          <ChartTooltip content={<ChartTooltipContent hideLabel />} />
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={42}
            outerRadius={66}
            startAngle={90}
            endAngle={-270}
            paddingAngle={2}
            cornerRadius={4}
            stroke="var(--card)"
            strokeWidth={3}
            isAnimationActive={!reduceMotion}
            animationBegin={400}
            animationDuration={1500}
            animationEasing="ease-out"
          >
            {data.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}
          </Pie>
        </PieChart>
      </ChartContainer>
      <div className="space-y-2 text-sm">
        <div className="text-3xl font-semibold">{state.approvalPolicyRules.filter((rule) => rule.enabled).length}</div>
        <div className="text-muted-foreground">Enabled rules</div>
        <Button variant="outline" size="sm" onClick={() => setView("policies")}>Manage policies</Button>
      </div>
    </div>
  );
}

function AgentsPanel({ state, setView }: { state: ConsoleState; setView: (view: ViewId) => void }) {
  return (
    <div className="grid gap-2">
      {state.agents.slice(0, 6).map((agent) => (
        <div key={agent.id} className="flex items-center justify-between rounded-md border bg-muted/20 px-3 py-2 text-sm">
          <span className="flex min-w-0 items-center gap-2">
            <AgentIcon name={agent.name} className="h-6 w-6" />
            <span className="truncate">{agent.name}</span>
          </span>
          <Badge variant="outline">{agent.status}</Badge>
        </div>
      ))}
      <Button variant="link" className="justify-start px-0" onClick={() => setView("agents")}>View agent catalog</Button>
    </div>
  );
}

function RecentActivityPanel({ state, setView }: { state: ConsoleState; setView: (view: ViewId) => void }) {
  const [listRef, listSize] = useElementSize<HTMLDivElement>();
  const activityRows = state.audit.filter((event) => isAgentActivityEvent(event, state));
  const availableForRows = Math.max(
    RECENT_ACTIVITY_ROW_HEIGHT,
    listSize.height - RECENT_ACTIVITY_TABLE_HEADER_HEIGHT
  );
  const visibleCount = listSize.height > 0
    ? Math.max(1, Math.floor(availableForRows / RECENT_ACTIVITY_ROW_HEIGHT))
    : 3;
  const rows = activityRows.slice(0, visibleCount);

  return (
    <div className="sgw-recent-event-panel flex h-full min-h-0 flex-col" data-recent-activity>
      <div className="sgw-recent-event-summary">
        <span className="sgw-event-chip">Agent Activity Events</span>
        <span>{activityRows.length.toLocaleString()} results</span>
      </div>
      <div
        ref={listRef}
        className="sgw-recent-event-list min-h-0 flex-1 overflow-hidden"
        data-recent-activity-list
        data-total-rows={activityRows.length}
        data-visible-rows={rows.length}
      >
        <div className="sgw-recent-event-table">
          {rows.length > 0 ? (
            <div className="sgw-recent-event-head">
              <span>Source</span>
              <span>Event type</span>
              <span>Status</span>
              <span>Destination</span>
            </div>
          ) : null}
          {rows.map((event, index) => {
            const flow = describeEventFlow(event, state);
            return (
              <div className="sgw-recent-event-row" data-overview-event-row key={eventRowKey(event, index)}>
                <span className="sgw-event-source-cell">
                  <AgentIcon name={flow.sourceLabel} className="h-6 w-6" />
                  <span>{flow.sourceLabel}</span>
                  {event.demo ? <DemoBadge /> : null}
                </span>
                <span className="sgw-event-type-pill">{recentEventKind(event.type)}</span>
                <EventStatusLabel tone={flow.tone} status={flow.status} />
                <span className="truncate">{flow.destinationLabel}</span>
              </div>
            );
          })}
          {activityRows.length === 0 ? <EmptyEventRows message="No agent activity yet." /> : null}
        </div>
      </div>
      <Button variant="link" className="h-7 shrink-0 self-start px-0 text-xs" onClick={() => setView("activity")}>View all activity</Button>
    </div>
  );
}

function recentEventKind(eventType: string): string {
  const parts = eventType.split(".").filter(Boolean);
  if (parts[0] === "approval" && parts[1] === "grant") return "Grant";
  return titleCase(parts[0] || "event");
}

function ApprovalsView({ state, setApproval, search }: { state: ConsoleState; setApproval: (request: RequestRecord) => void; search: string }) {
  const rows = filterText(state.requests, search, (request) => `${request.id} ${request.agentName} ${request.reason} ${request.handle} ${requestTarget(request)}`);
  return (
    <PageFrame title="Approvals" description="Review credential-backed actions before s-gw executes them locally.">
      <DataCard>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Agent</TableHead>
              <TableHead>Command</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>State</TableHead>
              <TableHead className="hidden text-right sm:table-cell">Requested</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((request) => (
              <TableRow key={request.id} className="cursor-pointer" onClick={() => setApproval(request)}>
                <TableCell className="font-medium">
                  <span className="flex items-center gap-2">
                    <AgentIcon name={request.agentName} className="h-7 w-7" />
                    <span>{request.agentName || "Agent"}</span>
                    {request.demo ? <DemoBadge /> : null}
                  </span>
                </TableCell>
                <TableCell>{commandName(request)}</TableCell>
                <TableCell className="max-w-[340px] truncate">{requestTarget(request)}</TableCell>
                <TableCell><RequestStateBadge state={request.state} /></TableCell>
                <TableCell className="hidden text-right text-muted-foreground sm:table-cell">{relativeTime(request.updatedAt)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </DataCard>
    </PageFrame>
  );
}

type CredentialColumnId = "name" | "provider" | "backend" | "handle" | "severity" | "updated";
type CredentialSortDirection = "asc" | "desc";

interface CredentialRow {
  handle: HandleSummary;
  originalIndex: number;
}

const CREDENTIAL_COLUMNS: Array<{ id: CredentialColumnId; label: string; className?: string }> = [
  { id: "name", label: "Name", className: "w-[28%]" },
  { id: "provider", label: "Provider", className: "w-[150px]" },
  { id: "backend", label: "Backend", className: "w-[165px]" },
  { id: "handle", label: "Handle", className: "w-[210px]" },
  { id: "severity", label: "Severity", className: "w-[100px]" },
  { id: "updated", label: "Updated", className: "w-[110px] text-right" }
];

function CredentialsView({
  state,
  setCredential,
  search,
  setSearch
}: {
  state: ConsoleState;
  setCredential: (credential: HandleSummary) => void;
  search: string;
  setSearch: (value: string) => void;
}) {
  const [sortColumn, setSortColumn] = React.useState<CredentialColumnId>("updated");
  const [sortDirection, setSortDirection] = React.useState<CredentialSortDirection>("desc");
  const rows = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    const filtered = state.handles
      .map((handle, originalIndex) => ({ handle, originalIndex }))
      .filter((row) => credentialMatchesSearch(row.handle, needle));

    return filtered.sort((left, right) => compareCredentialRows(left, right, sortColumn, sortDirection));
  }, [search, sortColumn, sortDirection, state.handles]);
  const countLabel = search.trim()
    ? `${rows.length.toLocaleString()} of ${state.handles.length.toLocaleString()} credentials`
    : `${state.handles.length.toLocaleString()} credentials`;

  function toggleSort(column: CredentialColumnId) {
    if (sortColumn === column) {
      setSortDirection((current) => current === "asc" ? "desc" : "asc");
      return;
    }
    setSortColumn(column);
    setSortDirection("asc");
  }

  return (
    <PageFrame title="Credentials" description="Local handles, detector metadata, storage backend, and allowed command policy.">
      <div className="sgw-event-log-card" data-credential-table>
        <div className="sgw-event-log-toolbar">
          <div className="sgw-event-query">
            <Search className="h-4 w-4" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search credentials"
              className="sgw-event-query-input"
            />
          </div>
          <div className="sgw-event-count">{countLabel}</div>
        </div>

        <div className="sgw-event-table-wrap">
          <Table className="sgw-event-table sgw-credential-table">
            <TableHeader>
              <TableRow>
                {CREDENTIAL_COLUMNS.map((column) => (
                  <TableHead
                    key={column.id}
                    className={column.className}
                    data-credential-column={column.id}
                    aria-sort={sortColumn === column.id ? (sortDirection === "asc" ? "ascending" : "descending") : "none"}
                  >
                    <button
                      type="button"
                      className={cn(
                        "sgw-event-sort-button",
                        column.id === "updated" && "ml-auto",
                        sortColumn === column.id && "is-active"
                      )}
                      data-credential-sort={column.id}
                      onClick={() => toggleSort(column.id)}
                    >
                      {column.label}
                      <ArrowUpDown className={cn("h-3 w-3", sortColumn === column.id && sortDirection === "desc" && "is-desc")} />
                    </button>
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ handle }) => (
                <TableRow
                  key={handle.handle}
                  className="sgw-event-row"
                  data-credential-row
                  onClick={() => setCredential(handle)}
                >
                  <TableCell className="font-medium" data-credential-column="name" data-credential-name title={handle.name}>
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="truncate">{handle.name}</span>
                      {handle.demo ? <DemoBadge /> : null}
                    </span>
                  </TableCell>
                  <TableCell data-credential-column="provider"><ProviderIdentity provider={handle.provider} backend={handle.backend} /></TableCell>
                  <TableCell className="text-xs sm:text-sm" data-credential-column="backend">{credentialBackendLabel(handle.backend)}</TableCell>
                  <TableCell className="truncate font-mono text-xs" data-credential-column="handle" title={handle.handle}>{shortHandle(handle.handle)}</TableCell>
                  <TableCell data-credential-column="severity"><SeverityBadge severity={handle.severity || "low"} /></TableCell>
                  <TableCell className="text-right text-muted-foreground" data-credential-column="updated">{relativeTime(handle.updatedAt)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {rows.length === 0 ? <EmptyEventRows message="No credentials match your search." /> : null}
        </div>
      </div>
    </PageFrame>
  );
}

function credentialMatchesSearch(handle: HandleSummary, needle: string): boolean {
  if (!needle) return true;
  const values = CREDENTIAL_COLUMNS.map((column) => credentialColumnValue(handle, column.id));
  values.push(handle.type, handle.policy.injectEnv || "", handle.source || "");
  return values.some((value) => value.toLowerCase().includes(needle));
}

function credentialColumnValue(handle: HandleSummary, column: CredentialColumnId): string {
  if (column === "name") return handle.name;
  if (column === "provider") return credentialProviderPresentation(handle.provider, handle.backend).label;
  if (column === "backend") return credentialBackendLabel(handle.backend);
  if (column === "handle") return handle.handle;
  if (column === "severity") return handle.severity || "low";
  return formatEventTimestamp(handle.updatedAt);
}

function compareCredentialRows(
  left: CredentialRow,
  right: CredentialRow,
  column: CredentialColumnId,
  direction: CredentialSortDirection
): number {
  let comparison: number;
  if (column === "updated") {
    comparison = timestampValue(left.handle.updatedAt) - timestampValue(right.handle.updatedAt);
    if (comparison === 0) {
      comparison = timestampValue(left.handle.createdAt) - timestampValue(right.handle.createdAt);
    }
  } else if (column === "severity") {
    comparison = credentialSeverityRank(left.handle.severity) - credentialSeverityRank(right.handle.severity);
  } else {
    comparison = credentialColumnValue(left.handle, column).localeCompare(
      credentialColumnValue(right.handle, column),
      undefined,
      { numeric: true, sensitivity: "base" }
    );
  }

  if (comparison === 0) comparison = left.originalIndex - right.originalIndex;
  return direction === "asc" ? comparison : -comparison;
}

function timestampValue(value: string): number {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function credentialSeverityRank(severity?: string): number {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}

function UsageFlowView({ state }: { state: ConsoleState }) {
  return (
    <PageFrame title="Usage Flow" description="Agent credential use classified by agent, authentication type, and target type.">
      <ResizablePanelGroup orientation="horizontal" className="min-h-[680px] rounded-lg border bg-card/70">
        <ResizablePanel defaultSize={68} minSize={45}>
          <div className="h-full p-4">
            <UsageFlowSankey flow={state.usageFlow} className="h-full min-h-[620px]" />
          </div>
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel defaultSize={32} minSize={24}>
          <div className="h-full overflow-auto p-4">
            <h3 className="mb-3 text-base font-semibold">Flow details</h3>
            <FlowRowsTable rows={state.usageFlow.rows} />
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
    </PageFrame>
  );
}

function PoliciesView({ state, onDone, search }: { state: ConsoleState; onDone: () => void; search: string }) {
  const [editing, setEditing] = React.useState<ApprovalPolicyRuleRecord | null>(null);
  const [adding, setAdding] = React.useState(false);
  const [deleting, setDeleting] = React.useState<ApprovalPolicyRuleRecord | null>(null);
  const [arranging, setArranging] = React.useState(false);
  const rows = filterText(state.approvalPolicyRules, search, (rule) => `${rule.name} ${rule.decision} ${policyConditionSummary(rule.conditions)}`);
  const shadowedBy = React.useMemo(() => {
    const matches = new Map<string, ApprovalPolicyRuleRecord>();
    for (const rule of state.approvalPolicyRules) {
      if (!rule.enabled || (rule.expiresAt && rule.expiresAt <= new Date().toISOString())) continue;
      const shadow = findShadowingPolicyRule(state.approvalPolicyRules, rule);
      if (shadow) matches.set(rule.id, shadow);
    }
    return matches;
  }, [state.approvalPolicyRules]);
  const shadowedCount = shadowedBy.size;

  async function arrange() {
    if (arranging) return;
    setArranging(true);
    try {
      const result = await arrangePolicies();
      toast.success(result.reordered ? `Reordered ${result.reordered} rule${result.reordered === 1 ? "" : "s"}` : "Rules already use a safe order");
      onDone();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not arrange policies");
    } finally {
      setArranging(false);
    }
  }

  async function deleteRule() {
    if (!deleting) return;
    try {
      await deletePolicy(deleting.id);
      toast.success("Policy deleted");
      setDeleting(null);
      onDone();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not delete policy");
    }
  }

  return (
    <PageFrame title="Policies" description="Define when agents may use credentials without interrupting you, and when s-gw should always ask or deny.">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-3xl text-sm text-muted-foreground">
          Rules run in priority order. Auto-arrange moves narrower rules ahead of broader ask and allow rules; deny rules stay ahead as guardrails.
        </p>
        <div className="flex gap-2">
          <Button variant="outline" disabled={arranging} onClick={() => void arrange()} data-policy-arrange>
            {arranging ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Wand2 className="mr-2 h-4 w-4" />}
            Auto-arrange
          </Button>
          <Button onClick={() => setAdding(true)} data-policy-add>
            <Plus className="mr-2 h-4 w-4" />Add policy rule
          </Button>
        </div>
      </div>
      {shadowedCount ? (
        <div className="flex items-center gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-700 dark:text-amber-300" data-policy-shadow-summary>
          <AlertTriangle className="h-4 w-4" />
          {shadowedCount} rule{shadowedCount === 1 ? " is" : "s are"} unreachable until the earlier rule is changed or auto-arranged.
        </div>
      ) : null}
      <DataCard>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Status</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Decision</TableHead>
              <TableHead>Conditions</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                  No policy rules yet. Add a scoped rule or use Always allow from an approval.
                </TableCell>
              </TableRow>
            ) : null}
            {rows.map((rule) => (
              <TableRow key={rule.id} data-policy-row={rule.id} className={cn(shadowedBy.has(rule.id) && "bg-amber-500/5")}>
                <TableCell>
                  <PolicyStatusControl rule={rule} onDone={onDone} />
                </TableCell>
                <TableCell className="font-medium">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate">{rule.name}</span>
                    {rule.demo ? <DemoBadge /> : null}
                    {shadowedBy.get(rule.id) ? (
                      <Badge variant="secondary" className="shrink-0 text-amber-700 dark:text-amber-300" title={`Covered by ${shadowedBy.get(rule.id)?.name}`}>
                        Shadowed
                      </Badge>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell><DecisionBadge decision={rule.decision} /></TableCell>
                <TableCell className="max-w-[560px] truncate">{policyConditionSummary(rule.conditions)}</TableCell>
                <TableCell className="text-right whitespace-nowrap">
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Edit ${rule.name}`}
                    onClick={() => setEditing(rule)}
                    disabled={rule.demo}
                    data-policy-edit={rule.id}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    aria-label={`Delete ${rule.name}`}
                    onClick={() => setDeleting(rule)}
                    disabled={rule.demo}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </DataCard>
      <PolicyEditorDialog open={adding} state={state} onOpenChange={setAdding} onDone={onDone} />
      <PolicyEditorDialog
        open={Boolean(editing)}
        rule={editing}
        state={state}
        onOpenChange={(open) => !open && setEditing(null)}
        onDone={() => {
          setEditing(null);
          onDone();
        }}
      />
      <AlertDialog open={Boolean(deleting)} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete policy rule?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleting ? `Delete “${deleting.name}”? Future matching requests will no longer use it.` : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => void deleteRule()}>Delete rule</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PageFrame>
  );
}

function PolicyStatusControl({
  rule,
  onDone
}: {
  rule: ApprovalPolicyRuleRecord;
  onDone: () => void;
}) {
  const [busy, setBusy] = React.useState(false);
  const enabled = rule.enabled;

  async function togglePolicy() {
    if (busy || rule.demo) return;
    const nextEnabled = !enabled;
    setBusy(true);
    try {
      await setPolicyEnabled(rule.id, nextEnabled);
      toast.success(nextEnabled ? "Policy enabled" : "Policy disabled");
      onDone();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not update policy");
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      aria-label={`${enabled ? "Disable" : "Enable"} ${rule.name}`}
      disabled={busy || rule.demo}
      onClick={() => void togglePolicy()}
      data-policy-status
      className={cn(
        "inline-flex min-w-[92px] items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium outline-none transition-colors",
        "hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring/60 disabled:cursor-default disabled:opacity-65",
        enabled ? "text-emerald-700 dark:text-emerald-300" : "text-muted-foreground hover:text-foreground"
      )}
    >
      {busy ? (
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      ) : enabled ? (
        <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
      ) : (
        <Circle className="h-4 w-4" aria-hidden="true" />
      )}
      {busy ? "Updating" : enabled ? "Enabled" : "Disabled"}
    </button>
  );
}

function AgentsView({ state, search, onDone }: { state: ConsoleState; search: string; onDone: () => Promise<void> }) {
  const [selectedAgent, setSelectedAgent] = React.useState<AgentSummary | null>(null);
  const rows = filterText(state.agents, search, (agent) => `${agent.name} ${agent.id} ${agent.status} ${agent.integration.state}`);
  const connected = state.agents.filter((agent) => agent.integration.mcp.state === "installed" || agent.integration.mcp.state === "existing").length;
  const hookAware = state.agents.filter((agent) => agent.hooks.supported).length;

  return (
    <PageFrame title="Agents" description="Connect coding agents to s-gw, copy verified configuration, and inspect supported protection surfaces.">
      <div className="mb-4 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="outline">{state.agents.length} profiles</Badge>
        <Badge variant="outline">{connected} connected</Badge>
        <Badge variant="outline">{hookAware} hook-aware</Badge>
      </div>
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {rows.map((agent) => (
          <Card key={agent.id} className="flex min-h-[184px] flex-col">
            <CardHeader className="pb-3">
              <div className="flex items-start justify-between gap-3">
                <CardTitle className="flex min-w-0 items-center gap-2 text-base">
                  <AgentIcon name={agent.name} className="h-9 w-9 shrink-0" />
                  <span className="truncate">{agent.name}</span>
                </CardTitle>
                <AgentIntegrationBadge state={agent.integration.state} />
              </div>
              <CardDescription className="truncate font-mono text-xs">
                {agent.integration.mcp.path || agent.mcp.configPaths[0] || "No MCP configuration path"}
              </CardDescription>
            </CardHeader>
            <CardContent className="mt-auto space-y-3">
              <div className="flex flex-wrap gap-1.5">
                <Badge variant="secondary">MCP {agent.mcp.supported ? agent.mcp.format.toUpperCase() : "unavailable"}</Badge>
                <Badge variant="secondary">Hooks {agent.hooks.supported ? agent.hooks.kind : "none"}</Badge>
                {agent.skills.supported ? <Badge variant="secondary">Skills</Badge> : null}
              </div>
              <Button
                variant={agent.integration.state === "conflict" ? "destructive" : "outline"}
                size="sm"
                className="w-full"
                onClick={() => setSelectedAgent(agent)}
                data-agent-mcp={agent.id}
              >
                {agent.integration.state === "installed" ? "Manage connection" : agent.integration.state === "manual" ? "Manual setup" : agent.integration.state === "conflict" ? "Review conflict" : "Connection details"}
              </Button>
            </CardContent>
          </Card>
        ))}
      </div>
      <AgentConfigurationSheet
        agent={selectedAgent}
        onDone={onDone}
        onOpenChange={(open) => !open && setSelectedAgent(null)}
      />
    </PageFrame>
  );
}

function AgentSupportBadge({ status }: { status: string }) {
  const label = status === "supported" ? "Supported" : status === "manual" ? "Manual setup" : titleCase(status);
  return <Badge variant={status === "supported" ? "outline" : "secondary"}>{label}</Badge>;
}

function AgentIntegrationBadge({ state }: { state: AgentSummary["integration"]["state"] }) {
  const label = state === "not-detected" ? "Not detected" : titleCase(state);
  const variant = state === "conflict" ? "destructive" : state === "installed" ? "outline" : "secondary";
  return <Badge variant={variant}>{label}</Badge>;
}

function AgentConfigurationSheet({
  agent,
  onDone,
  onOpenChange
}: {
  agent: AgentSummary | null;
  onDone: () => Promise<void>;
  onOpenChange: (open: boolean) => void;
}) {
  const [busy, setBusy] = React.useState(false);
  if (!agent) return null;

  const copy = async (value: string, label: string) => {
    try {
      await copyText(value);
      toast.success(`${label} copied`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Copy failed");
    }
  };

  const updateConnection = async (action: "install" | "uninstall") => {
    setBusy(true);
    try {
      const response = action === "install"
        ? await installAgentIntegration(agent.id)
        : await uninstallAgentIntegration(agent.id);
      if (response.result.state === "conflict") {
        toast.error(response.result.reason || `${agent.name} configuration has a conflict`);
        return;
      }
      toast.success(action === "install" ? `${agent.name} connected` : `${agent.name} disconnected`);
      await onDone();
      onOpenChange(false);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Agent connection update failed");
    } finally {
      setBusy(false);
    }
  };

  const canInstall = agent.integration.detected && agent.integration.eligible && agent.integration.state !== "installed" && agent.integration.state !== "conflict";
  const canUninstall = agent.integration.mcp.owned || agent.integration.skill.owned;

  return (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent
        className="w-[min(620px,calc(100vw-16px))] overflow-y-auto sm:max-w-none"
        data-agent-detail={agent.id}
      >
        <SheetHeader>
          <SheetTitle className="flex items-center gap-3">
            <AgentIcon name={agent.name} className="h-10 w-10" />
            <span>{agent.name}</span>
            <AgentIntegrationBadge state={agent.integration.state} />
          </SheetTitle>
          <SheetDescription>
            Configure s-gw locally for this agent. Raw credentials remain outside the agent configuration.
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-6 px-4 pb-6">
          <section className="space-y-3 rounded-md border bg-muted/20 p-4" data-agent-installation={agent.integration.state}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold">s-gw connection</h3>
                <p className="text-xs text-muted-foreground">
                  {agent.integration.detected ? "Agent detected on this computer." : "Agent was not detected on this computer."}
                </p>
              </div>
              <div className="flex gap-2">
                {canInstall ? (
                  <Button size="sm" disabled={busy} onClick={() => void updateConnection("install")} data-agent-install={agent.id}>
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                    Connect
                  </Button>
                ) : null}
                {canUninstall ? (
                  <Button variant="outline" size="sm" disabled={busy} onClick={() => void updateConnection("uninstall")} data-agent-uninstall={agent.id}>
                    {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                    Disconnect
                  </Button>
                ) : null}
              </div>
            </div>
            <div className="grid gap-2 text-sm sm:grid-cols-2">
              <AgentCapability label="MCP registration" value={titleCase(agent.integration.mcp.state)} />
              <AgentCapability label="s-gw skill" value={titleCase(agent.integration.skill.state)} />
            </div>
            {agent.integration.reason ? <p className="text-xs text-amber-700 dark:text-amber-300">{agent.integration.reason}</p> : null}
          </section>

          <section className="grid gap-2 text-sm sm:grid-cols-2">
            <AgentCapability label="MCP" value={agent.mcp.supported ? `${agent.mcp.format.toUpperCase()} · ${agent.mcp.writeMode}` : "Not available"} />
            <AgentCapability label="Profile support" value={agent.status === "supported" ? "Supported" : titleCase(agent.status)} />
            <AgentCapability label="Guard mode" value="Available" />
            <AgentCapability label="Hooks" value={agent.hooks.supported ? `${agent.hooks.kind} · ${agent.hooks.events.length} events` : "Not available"} />
            <AgentCapability label="CodeGuard" value={agent.codeGuard.supported ? titleCase(agent.codeGuard.route) : "Not available"} />
          </section>

          {agent.mcp.snippet ? (
            <section className="space-y-3 border-t pt-5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold">MCP configuration</h3>
                  <p className="text-xs text-muted-foreground">Paste this into one of the supported configuration files.</p>
                </div>
                <Button size="sm" onClick={() => void copy(agent.mcp.snippet || "", "MCP snippet")} data-copy-agent-snippet>
                  <Copy className="h-4 w-4" />
                  Copy snippet
                </Button>
              </div>
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/70 p-3 font-mono text-xs leading-5 text-foreground"><code>{agent.mcp.snippet}</code></pre>
              <AgentPathList label="Configuration paths" paths={agent.mcp.configPaths} />
              {agent.mcp.notes.map((note) => <p key={note} className="text-xs text-muted-foreground">{note}</p>)}
              <CopyCommand value={agent.snippetCommand} label="Generate from CLI" onCopy={copy} />
            </section>
          ) : (
            <section className="space-y-2 border-t pt-5">
              <h3 className="text-sm font-semibold">MCP configuration</h3>
              <p className="text-sm text-muted-foreground">This profile does not have a supported s-gw MCP configuration yet.</p>
            </section>
          )}

          <section className="space-y-3 border-t pt-5">
            <div>
              <h3 className="text-sm font-semibold">Guard mode</h3>
              <p className="text-xs text-muted-foreground">Launch the agent with credential-looking environment values replaced by local s-gw handles.</p>
            </div>
            <CopyCommand value={agent.guardCommand} label="Launch command" onCopy={copy} />
          </section>

          {agent.hooks.supported ? (
            <section className="space-y-3 border-t pt-5">
              <h3 className="text-sm font-semibold">Hook surface</h3>
              <div className="flex flex-wrap gap-1.5">
                {agent.hooks.events.map((event) => <Badge key={event} variant="secondary">{event}</Badge>)}
              </div>
              <AgentPathList label="Hook configuration" paths={agent.hooks.configPaths} />
            </section>
          ) : null}

          {agent.codeGuard.supported ? (
            <section className="space-y-3 border-t pt-5">
              <div className="flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold">CodeGuard integration</h3>
                <Button variant="ghost" size="sm" asChild>
                  <a href={agent.codeGuard.sourceRepo} target="_blank" rel="noreferrer">
                    Project source <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </Button>
              </div>
              <AgentPathList label="Install paths" paths={agent.codeGuard.installPaths} />
              {agent.codeGuard.commands.length > 0 ? (
                <CopyCommand value={agent.codeGuard.commands.join("\n")} label="Setup steps" onCopy={copy} />
              ) : null}
            </section>
          ) : null}

          {agent.limitations.length > 0 ? (
            <section className="space-y-2 border-t pt-5">
              <h3 className="text-sm font-semibold">Current limits</h3>
              {agent.limitations.map((item) => <p key={item} className="text-xs text-muted-foreground">{item}</p>)}
            </section>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  );
}

function AgentCapability({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b py-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}

function AgentPathList({ label, paths }: { label: string; paths: string[] }) {
  if (paths.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      {paths.map((path) => <code key={path} className="block break-all font-mono text-xs text-foreground/80">{path}</code>)}
    </div>
  );
}

function CopyCommand({
  value,
  label,
  onCopy
}: {
  value: string;
  label: string;
  onCopy: (value: string, label: string) => Promise<void>;
}) {
  return (
    <div className="flex items-center gap-2 rounded-md border bg-muted/60 p-2">
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-xs">{value}</code>
      <Button variant="ghost" size="icon-sm" onClick={() => void onCopy(value, label)} aria-label={`Copy ${label.toLowerCase()}`}>
        <Copy className="h-4 w-4" />
      </Button>
    </div>
  );
}

function copyText(value: string): Promise<void> {
  const area = document.createElement("textarea");
  area.value = value;
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  const copied = document.execCommand("copy");
  area.remove();
  if (copied) return Promise.resolve();

  if (navigator.clipboard?.writeText) {
    return navigator.clipboard.writeText(value);
  }
  return Promise.reject(new Error("Could not copy to the clipboard"));
}

function ActivityView({
  state,
  search,
  setSearch
}: {
  state: ConsoleState;
  search: string;
  setSearch: (value: string) => void;
}) {
  const agentEvents = state.audit.filter((event) => isAgentActivityEvent(event, state));
  return (
    <PageFrame title="Activity" description="Agent-initiated credential operations, controls, and destinations.">
      <EventLogTable
        mode="activity"
        rows={agentEvents}
        totalRows={agentEvents.length}
        state={state}
        search={search}
        setSearch={setSearch}
        emptyMessage="No agent activity matches this view."
      />
    </PageFrame>
  );
}

function AuditLogView({
  state,
  search,
  setSearch
}: {
  state: ConsoleState;
  search: string;
  setSearch: (value: string) => void;
}) {
  return (
    <PageFrame title="Audit Log" description="Complete local record of agent and s-gw security events.">
      <EventLogTable
        mode="audit"
        rows={state.audit}
        totalRows={state.audit.length}
        state={state}
        search={search}
        setSearch={setSearch}
        emptyMessage="No audit events match this view."
      />
    </PageFrame>
  );
}

type EventColumnId = "source" | "eventType" | "status" | "eventId" | "destination" | "reasonCode" | "ruleName" | "timestamp";
type EventSortDirection = "asc" | "desc";

interface EventLogRow {
  event: ConsoleState["audit"][number];
  flow: ReturnType<typeof describeEventFlow>;
  rowKey: string;
  originalIndex: number;
}

interface EventColumn {
  id: EventColumnId;
  label: string;
}

const EVENT_COLUMN_LABELS: Record<EventColumnId, string> = {
  source: "Source",
  eventType: "Event type",
  status: "Status",
  eventId: "Event ID",
  destination: "Destination",
  reasonCode: "Reason code",
  ruleName: "Rule name",
  timestamp: "Date & Time"
};

const ACTIVITY_EVENT_COLUMN_ORDER: EventColumnId[] = [
  "source", "eventType", "status", "eventId", "destination", "reasonCode", "ruleName", "timestamp"
];

const AUDIT_EVENT_COLUMN_ORDER: EventColumnId[] = [
  "eventType", "status", "eventId", "source", "destination", "reasonCode", "ruleName", "timestamp"
];

function EventLogTable({
  mode,
  rows,
  totalRows,
  state,
  search,
  setSearch,
  emptyMessage
}: {
  mode: "activity" | "audit";
  rows: ConsoleState["audit"];
  totalRows: number;
  state: ConsoleState;
  search: string;
  setSearch: (value: string) => void;
  emptyMessage: string;
}) {
  const [expandedKey, setExpandedKey] = React.useState<string | null>(null);
  const [filtersOpen, setFiltersOpen] = React.useState(false);
  const [filterColumn, setFilterColumn] = React.useState<EventColumnId>(mode === "activity" ? "source" : "eventType");
  const [filterDraft, setFilterDraft] = React.useState("");
  const [columnFilters, setColumnFilters] = React.useState<Partial<Record<EventColumnId, string>>>({});
  const [sortColumn, setSortColumn] = React.useState<EventColumnId>("timestamp");
  const [sortDirection, setSortDirection] = React.useState<EventSortDirection>("desc");
  const columns = React.useMemo(() => eventColumnsForMode(mode), [mode]);
  const tableRows = React.useMemo(() => rows.map((event, index) => ({
    event,
    flow: describeEventFlow(event, state),
    rowKey: eventRowKey(event, index),
    originalIndex: index
  })), [rows, state]);
  const visibleRows = React.useMemo(() => {
    const filtered = tableRows.filter((row) => (
      rowMatchesEventSearch(row, columns, search) && rowMatchesColumnFilters(row, columns, columnFilters)
    ));
    return filtered.sort((left, right) => compareEventRows(left, right, sortColumn, sortDirection));
  }, [columnFilters, columns, search, sortColumn, sortDirection, tableRows]);
  const firstKey = visibleRows[0]?.rowKey || null;

  React.useEffect(() => {
    if (!firstKey) {
      setExpandedKey(null);
      return;
    }

    const hasExpanded = visibleRows.some((row) => row.rowKey === expandedKey);
    if (!expandedKey || !hasExpanded) setExpandedKey(firstKey);
  }, [expandedKey, firstKey, visibleRows]);

  const label = mode === "activity" ? "Agent Activity Events" : "Complete Audit Events";
  const hasColumnFilters = Object.values(columnFilters).some(Boolean);
  const hasActiveFilters = Boolean(search.trim()) || hasColumnFilters;
  const countLabel = hasActiveFilters
    ? `${visibleRows.length.toLocaleString()} of ${totalRows.toLocaleString()} results`
    : `${totalRows.toLocaleString()} results`;
  const selectedFilterLabel = EVENT_COLUMN_LABELS[filterColumn];

  function toggleSort(column: EventColumnId) {
    if (sortColumn === column) {
      setSortDirection((current) => current === "asc" ? "desc" : "asc");
      return;
    }
    setSortColumn(column);
    setSortDirection("asc");
  }

  function applyColumnFilter() {
    const value = filterDraft.trim();
    setColumnFilters((current) => {
      const next = { ...current };
      if (value) next[filterColumn] = value;
      else delete next[filterColumn];
      return next;
    });
    setFilterDraft("");
  }

  function removeColumnFilter(column: EventColumnId) {
    setColumnFilters((current) => {
      const next = { ...current };
      delete next[column];
      return next;
    });
  }

  function resetFilters() {
    setSearch("");
    setColumnFilters({});
    setFilterDraft("");
  }

  return (
    <div className="sgw-event-log-card" data-event-log-card>
      <div className="sgw-event-log-toolbar">
        <div className="sgw-event-mode-toggle" aria-label="Event presentation mode">
          <button type="button">Classic</button>
          <button type="button" className="is-active">AI Assistant</button>
        </div>
        <div className="sgw-event-query">
          <Search className="h-4 w-4" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search every column"
            className="sgw-event-query-input"
          />
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="sgw-event-filter-button"
          aria-expanded={filtersOpen}
          onClick={() => setFiltersOpen((current) => !current)}
        >
          <SlidersHorizontal className="h-4 w-4" />
          Filters
        </Button>
        <Select defaultValue="24h">
          <SelectTrigger className="sgw-event-range">
            <Clock3 className="h-4 w-4" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="24h">Last 24 hours</SelectItem>
            <SelectItem value="7d">Last 7 days</SelectItem>
            <SelectItem value="30d">Last 30 days</SelectItem>
          </SelectContent>
        </Select>
        <div className="sgw-event-count">{countLabel}</div>
        {mode === "audit" ? (
          <Button asChild variant="outline" size="sm" className="sgw-event-export">
            <a href={auditCsvUrl()} download>
              <Download className="h-4 w-4" />
              Export CSV
            </a>
          </Button>
        ) : null}
      </div>

      {filtersOpen ? (
        <div className="sgw-event-filter-row" data-event-filter-row>
          <Select
            value={filterColumn}
            onValueChange={(value) => {
              const column = value as EventColumnId;
              setFilterColumn(column);
              setFilterDraft(columnFilters[column] || "");
            }}
          >
            <SelectTrigger className="sgw-event-filter-select" aria-label="Filter column">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {columns.map((column) => (
                <SelectItem key={column.id} value={column.id}>{column.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={filterDraft}
            onChange={(event) => setFilterDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") applyColumnFilter();
            }}
            placeholder={`Filter ${selectedFilterLabel.toLowerCase()}`}
            aria-label={`Filter ${selectedFilterLabel}`}
            className="sgw-event-filter-input"
          />
          <Button type="button" size="sm" onClick={applyColumnFilter} disabled={!filterDraft.trim()}>
            Apply filter
          </Button>
        </div>
      ) : null}

      <div className="sgw-event-chip-row">
        <span className="sgw-event-chip">{label}</span>
        {search ? (
          <span className="sgw-event-chip sgw-event-column-filter-chip">
            Search: {search}
            <button type="button" aria-label="Clear search" onClick={() => setSearch("")}><X className="h-3 w-3" /></button>
          </span>
        ) : null}
        {columns.map((column) => columnFilters[column.id] ? (
          <span className="sgw-event-chip sgw-event-column-filter-chip" key={column.id}>
            {column.label}: {columnFilters[column.id]}
            <button
              type="button"
              aria-label={`Clear ${column.label} filter`}
              onClick={() => removeColumnFilter(column.id)}
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ) : null)}
        {hasActiveFilters ? (
          <button type="button" className="sgw-event-reset" onClick={resetFilters}>Reset all</button>
        ) : null}
      </div>

      <div className="sgw-event-table-wrap">
        <Table className="sgw-event-table">
          <TableHeader>
            <TableRow>
              {columns.map((column) => (
                <TableHead
                  key={column.id}
                  aria-sort={sortColumn === column.id ? (sortDirection === "asc" ? "ascending" : "descending") : "none"}
                >
                  <button
                    type="button"
                    className={cn("sgw-event-sort-button", sortColumn === column.id && "is-active")}
                    data-sort-column={column.id}
                    onClick={() => toggleSort(column.id)}
                  >
                    {column.label}
                    <ArrowUpDown className={cn("h-3 w-3", sortColumn === column.id && sortDirection === "desc" && "is-desc")} />
                  </button>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {visibleRows.map((row) => {
              const expanded = row.rowKey === expandedKey;

              return (
                <React.Fragment key={row.rowKey}>
                  <TableRow
                    aria-expanded={expanded}
                    className="sgw-event-row"
                    onClick={() => setExpandedKey(expanded ? null : row.rowKey)}
                    data-event-row
                  >
                    {columns.map((column) => (
                      <TableCell key={column.id} className={eventColumnClassName(column.id)}>
                        {renderEventColumn(row, column.id, mode)}
                      </TableCell>
                    ))}
                  </TableRow>
                  {expanded ? (
                    <TableRow className="sgw-event-expanded-row">
                      <TableCell colSpan={columns.length}>
                        <EventFlowDiagram flow={row.flow} />
                      </TableCell>
                    </TableRow>
                  ) : null}
                </React.Fragment>
              );
            })}
          </TableBody>
        </Table>
        {visibleRows.length === 0 ? <EmptyEventRows message={emptyMessage} /> : null}
      </div>
    </div>
  );
}

function eventColumnsForMode(mode: "activity" | "audit"): EventColumn[] {
  const order = mode === "activity" ? ACTIVITY_EVENT_COLUMN_ORDER : AUDIT_EVENT_COLUMN_ORDER;
  return order.map((id) => ({ id, label: EVENT_COLUMN_LABELS[id] }));
}

function eventColumnValue(row: EventLogRow, column: EventColumnId): string {
  if (column === "source") return row.flow.sourceLabel;
  if (column === "eventType") return row.flow.eventType;
  if (column === "status") return row.flow.status;
  if (column === "eventId") return row.flow.eventId;
  if (column === "destination") return row.flow.destinationLabel;
  if (column === "reasonCode") return row.flow.reasonCode;
  if (column === "ruleName") return row.flow.ruleName;
  return formatEventTimestamp(row.event.ts);
}

function renderEventColumn(row: EventLogRow, column: EventColumnId, mode: "activity" | "audit"): React.ReactNode {
  if (column === "source" && mode === "activity") {
    return (
      <span className="sgw-event-source-cell">
        <AgentIcon name={row.flow.sourceLabel} className="h-6 w-6" />
        <span>{row.flow.sourceLabel}</span>
      </span>
    );
  }
  if (column === "eventType") return (
    <span className="flex items-center gap-1.5">
      <span className="sgw-event-type-pill">{row.flow.eventType}</span>
      {row.event.demo ? <DemoBadge /> : null}
    </span>
  );
  if (column === "status") return <EventStatusLabel tone={row.flow.tone} status={row.flow.status} />;
  return eventColumnValue(row, column);
}

function eventColumnClassName(column: EventColumnId): string {
  if (column === "eventId") return "max-w-[180px] truncate font-mono text-xs text-muted-foreground";
  if (column === "timestamp") return "whitespace-nowrap text-muted-foreground";
  if (column === "ruleName") return "max-w-[240px] truncate";
  return "max-w-[220px] truncate";
}

function rowMatchesEventSearch(row: EventLogRow, columns: EventColumn[], search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (!needle) return true;

  const rawValues = [row.event.type, row.event.message, row.event.handle || "", row.event.requestId || ""];
  if (rawValues.some((value) => value.toLowerCase().includes(needle))) return true;
  return columns.some((column) => eventColumnValue(row, column.id).toLowerCase().includes(needle));
}

function rowMatchesColumnFilters(
  row: EventLogRow,
  columns: EventColumn[],
  filters: Partial<Record<EventColumnId, string>>
): boolean {
  for (const column of columns) {
    const filter = filters[column.id]?.trim().toLowerCase();
    if (!filter) continue;
    if (!eventColumnValue(row, column.id).toLowerCase().includes(filter)) return false;
  }
  return true;
}

function compareEventRows(
  left: EventLogRow,
  right: EventLogRow,
  column: EventColumnId,
  direction: EventSortDirection
): number {
  let comparison = 0;
  if (column === "timestamp") {
    comparison = new Date(left.event.ts).getTime() - new Date(right.event.ts).getTime();
  } else {
    comparison = eventColumnValue(left, column).localeCompare(eventColumnValue(right, column), undefined, {
      numeric: true,
      sensitivity: "base"
    });
  }

  if (comparison === 0) comparison = left.originalIndex - right.originalIndex;
  return direction === "asc" ? comparison : -comparison;
}

function EventStatusLabel({ tone, status }: { tone: "success" | "pending" | "failure" | "neutral"; status: string }) {
  return (
    <span className={cn("sgw-event-status", `is-${tone}`)}>
      <span />
      {status}
    </span>
  );
}

function eventRowKey(event: ConsoleState["audit"][number], index: number): string {
  return event.id || `${event.ts}-${event.type}-${event.requestId || event.handle || index}`;
}

function formatEventTimestamp(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value || "-";
  return new Intl.DateTimeFormat(undefined, {
    month: "2-digit",
    day: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  }).format(date);
}

function EmptyEventRows({ message }: { message: string }) {
  return <div className="py-8 text-center text-sm text-muted-foreground">{message}</div>;
}

const approvalModePresentation: Record<ApprovalMode, { label: string; detail: string }> = {
  "per-transaction": {
    label: "Ask every time",
    detail: "Require approval for each credential operation."
  },
  "timed-session": {
    label: "Reuse for a time window",
    detail: "Reuse a matching approval for a limited period."
  },
  "login-session": {
    label: "Reuse for this login session",
    detail: "Reuse a matching approval until you sign out."
  },
  always: {
    label: "Reuse until revoked",
    detail: "Keep a matching approval active until you clear it."
  }
};

const commonApprovalDurations = [
  { value: 15 * 60 * 1000, label: "15 minutes" },
  { value: 60 * 60 * 1000, label: "1 hour" },
  { value: 8 * 60 * 60 * 1000, label: "8 hours" },
  { value: 24 * 60 * 60 * 1000, label: "1 day" },
  { value: 7 * 24 * 60 * 60 * 1000, label: "7 days" },
  { value: 30 * 24 * 60 * 60 * 1000, label: "30 days" }
];

function approvalDurationChoices(savedMs: number): Array<{ value: number; label: string }> {
  if (commonApprovalDurations.some((choice) => choice.value === savedMs)) {
    return commonApprovalDurations;
  }
  return [{ value: savedMs, label: `Current setting · ${durationLabel(savedMs)}` }, ...commonApprovalDurations];
}

function SettingsView({ state, onDone }: { state: ConsoleState; onDone: () => Promise<void> }) {
  const [mode, setMode] = React.useState<ApprovalMode>(state.approvalSettings.mode);
  const [durationMs, setDurationMs] = React.useState(state.approvalSettings.durationMs);
  const [saving, setSaving] = React.useState(false);
  const [clearing, setClearing] = React.useState(false);
  const durationChoices = approvalDurationChoices(state.approvalSettings.durationMs);
  const durationEnabled = mode === "timed-session";
  const isDirty = mode !== state.approvalSettings.mode || durationMs !== state.approvalSettings.durationMs;
  const versionLabel = state.version.startsWith("v") ? state.version : `v${state.version}`;

  const saveSettings = async () => {
    if (saving) return;
    setSaving(true);
    try {
      await saveApprovalSettings({ mode, durationMs });
      toast.success("Approval settings updated");
      await onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not update approval settings");
    } finally {
      setSaving(false);
    }
  };

  const clearReusableGrants = async () => {
    if (clearing) return;
    setClearing(true);
    try {
      await clearGrants();
      toast.success("Reusable approvals cleared");
      await onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not clear reusable approvals");
    } finally {
      setClearing(false);
    }
  };

  return (
    <PageFrame title="Settings" description="Approval behavior, reusable grants, and local console preferences.">
      <Tabs defaultValue="approvals" className="max-w-5xl gap-4">
        <TabsList
          aria-label="Settings sections"
          data-settings-nav
          className="grid h-auto! w-full grid-cols-3 items-stretch gap-2 rounded-xl border bg-card/70 p-2"
        >
          <TabsTrigger
            value="approvals"
            data-settings-tab="approvals"
            className="h-auto min-h-14 flex-col gap-1.5 whitespace-normal px-2 py-2 text-center shadow-none after:hidden sm:min-h-16 sm:flex-row sm:justify-start sm:gap-3 sm:px-3 sm:text-left data-[state=active]:border-primary/50 data-[state=active]:bg-primary/10"
          >
            <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary sm:size-8">
              <ShieldCheck className="size-4" aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium leading-tight text-foreground">Approval defaults</span>
              <span className="mt-1 hidden text-xs font-normal leading-tight text-muted-foreground md:block">
                Set default request behavior
              </span>
            </span>
          </TabsTrigger>
          <TabsTrigger
            value="grants"
            data-settings-tab="grants"
            className="h-auto min-h-14 flex-col gap-1.5 whitespace-normal px-2 py-2 text-center shadow-none after:hidden sm:min-h-16 sm:flex-row sm:justify-start sm:gap-3 sm:px-3 sm:text-left data-[state=active]:border-primary/50 data-[state=active]:bg-primary/10"
          >
            <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary sm:size-8">
              <Clock3 className="size-4" aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium leading-tight text-foreground">Reusable grants</span>
              <span className="mt-1 hidden text-xs font-normal leading-tight text-muted-foreground md:block">
                Review reusable access
              </span>
            </span>
          </TabsTrigger>
          <TabsTrigger
            value="about"
            data-settings-tab="about"
            className="h-auto min-h-14 flex-col gap-1.5 whitespace-normal px-2 py-2 text-center shadow-none after:hidden sm:min-h-16 sm:flex-row sm:justify-start sm:gap-3 sm:px-3 sm:text-left data-[state=active]:border-primary/50 data-[state=active]:bg-primary/10"
          >
            <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary sm:size-8">
              <Info className="size-4" aria-hidden="true" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-medium leading-tight text-foreground">About</span>
              <span className="mt-1 hidden text-xs font-normal leading-tight text-muted-foreground md:block">
                Version and local storage
              </span>
            </span>
          </TabsTrigger>
        </TabsList>
        <TabsContent value="approvals" className="m-0">
          <Card data-settings-panel="approvals">
            <CardHeader className="border-b">
              <CardTitle>Default approval behavior</CardTitle>
              <CardDescription>Each approval is still scoped by handle, action, agent, and target context.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-6 md:grid-cols-2">
              <div className="space-y-2">
                <label htmlFor="approval-mode" className="text-sm font-medium">Approval mode</label>
                <Select value={mode} onValueChange={(value) => setMode(value as ApprovalMode)}>
                  <SelectTrigger
                    id="approval-mode"
                    data-settings-mode
                    aria-describedby="approval-mode-help"
                    className="h-10 w-full"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(Object.keys(approvalModePresentation) as ApprovalMode[]).map((value) => (
                      <SelectItem key={value} value={value}>{approvalModePresentation[value].label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p id="approval-mode-help" className="text-xs leading-relaxed text-muted-foreground">
                  {approvalModePresentation[mode].detail}
                </p>
              </div>
              <div className="space-y-2">
                <label htmlFor="approval-duration" className="text-sm font-medium">Reusable duration</label>
                <Select
                  value={String(durationMs)}
                  onValueChange={(value) => setDurationMs(Number(value))}
                  disabled={!durationEnabled}
                >
                  <SelectTrigger
                    id="approval-duration"
                    data-settings-duration
                    aria-describedby="approval-duration-help"
                    className="h-10 w-full"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {durationChoices.map((choice) => (
                      <SelectItem key={choice.value} value={String(choice.value)}>{choice.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p id="approval-duration-help" className="text-xs leading-relaxed text-muted-foreground">
                  {durationEnabled
                    ? "Matching approvals expire after this window."
                    : "Available when approval mode uses a time window."}
                </p>
              </div>
            </CardContent>
            <CardFooter className="flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-center">
              <div className="flex items-start gap-2 text-xs text-muted-foreground">
                {state.approvalGrants.length > 0 ? (
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-500" aria-hidden="true" />
                ) : null}
                <p>
                  {state.approvalGrants.length > 0
                    ? `Saving clears ${state.approvalGrants.length} active reusable ${state.approvalGrants.length === 1 ? "grant" : "grants"}, so matching requests ask again.`
                    : "Changes apply to new approvals."}
                </p>
              </div>
              <Button
                data-settings-save
                className="w-full sm:w-auto"
                disabled={!isDirty || saving}
                onClick={() => void saveSettings()}
              >
                {saving ? <Loader2 className="size-4 animate-spin" aria-hidden="true" /> : null}
                Save changes
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        <TabsContent value="grants" className="m-0">
          <Card data-settings-panel="grants">
            <CardHeader className="border-b">
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <CardTitle>Reusable grants</CardTitle>
                  <CardDescription>Approvals that can be reused without prompting again.</CardDescription>
                </div>
                <Badge variant="secondary">{state.approvalGrants.length} active</Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {state.approvalGrants.length === 0 ? (
                <div data-settings-grants-empty className="grid min-h-56 place-items-center px-6 py-10 text-center">
                  <div>
                    <span className="mx-auto grid size-10 place-items-center rounded-full bg-muted text-muted-foreground">
                      <Clock3 className="size-5" aria-hidden="true" />
                    </span>
                    <h3 className="mt-3 font-medium">No reusable grants</h3>
                    <p className="mt-1 max-w-sm text-sm text-muted-foreground">
                      Time-window, login-session, and until-revoked approvals will appear here.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table className="min-w-[640px]">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Handle</TableHead>
                        <TableHead>Mode</TableHead>
                        <TableHead>Agent</TableHead>
                        <TableHead>Expires</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {state.approvalGrants.map((grant) => (
                        <TableRow key={grant.id}>
                          <TableCell className="font-mono text-xs">{shortHandle(grant.handle)}</TableCell>
                          <TableCell>{approvalModePresentation[grant.mode].label}</TableCell>
                          <TableCell>
                            {grant.agentName ? (
                              <span className="flex items-center gap-2">
                                <AgentIcon name={grant.agentName} className="h-6 w-6" />
                                <span>{grant.agentName}</span>
                              </span>
                            ) : "Any agent"}
                          </TableCell>
                          <TableCell>{grant.expiresAt ? relativeTime(grant.expiresAt) : "No expiry"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
            {state.approvalGrants.length > 0 ? (
              <CardFooter className="flex-col items-stretch justify-between gap-3 sm:flex-row sm:items-center">
                <p className="text-xs text-muted-foreground">Clearing grants makes matching requests ask for approval again.</p>
                <Button
                  variant="destructive"
                  className="w-full sm:w-auto"
                  disabled={clearing}
                  onClick={() => void clearReusableGrants()}
                >
                  {clearing ? <Loader2 className="size-4 animate-spin" aria-hidden="true" /> : <Trash2 className="size-4" aria-hidden="true" />}
                  Clear all grants
                </Button>
              </CardFooter>
            ) : null}
          </Card>
        </TabsContent>
        <TabsContent value="about" className="m-0">
          <Card data-settings-panel="about">
            <CardHeader className="border-b">
              <div className="flex items-center gap-3">
                <SgwLogo showText={false} />
                <div>
                  <CardTitle>s-gw</CardTitle>
                  <CardDescription>Local credential gateway for AI coding agents.</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <dl className="divide-y overflow-hidden rounded-lg border">
                <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
                  <dt className="text-sm text-muted-foreground">Version</dt>
                  <dd className="text-sm font-medium">{versionLabel}</dd>
                </div>
                <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-6">
                  <dt className="shrink-0 text-sm text-muted-foreground">Store location</dt>
                  <dd className="break-all font-mono text-xs sm:text-right">{state.status.storePath}</dd>
                </div>
                <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
                  <dt className="text-sm text-muted-foreground">Control plane</dt>
                  <dd className="text-sm font-medium">Runs locally</dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </PageFrame>
  );
}

function EmbeddedSurface({ ctx, compact }: { ctx: ConsoleContext; compact: boolean }) {
  React.useEffect(() => {
    document.documentElement.dataset.embed = "usage-flow";
    document.documentElement.dataset.embedDensity = compact ? "compact" : "full";
    return () => {
      delete document.documentElement.dataset.embed;
      delete document.documentElement.dataset.embedDensity;
    };
  }, [compact]);

  if (!ctx.state) {
    return <div className="grid h-screen place-items-center bg-background"><Skeleton className="h-72 w-[80vw]" /></div>;
  }
  return (
    <div className={cn("h-screen overflow-hidden bg-background p-2", compact ? "p-0" : "")}>
      <UsageFlowSankey flow={ctx.state.usageFlow} compact={compact} className="h-full" />
    </div>
  );
}

function MenubarSurface({ ctx }: { ctx: ConsoleContext }) {
  const state = ctx.state;
  const [decidingId, setDecidingId] = React.useState<string | null>(null);
  const decidingRef = React.useRef(false);

  const decide = React.useCallback(async (request: RequestRecord, approving: boolean) => {
    if (decidingRef.current) return;
    decidingRef.current = true;
    setDecidingId(request.id);
    try {
      if (approving) {
        await approveRequest(request, { mode: "per-transaction", agentScope: "same-agent" });
        toast.success("Request approved");
      } else {
        await denyRequest(request);
        toast.success("Request denied");
      }
      await ctx.refresh(true);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      decidingRef.current = false;
      setDecidingId(null);
    }
  }, [ctx]);

  if (!state) {
    return <div className="grid h-screen place-items-center bg-background p-4"><Skeleton className="h-56 w-full" /></div>;
  }
  return (
    <div className="h-screen overflow-hidden bg-background p-3 text-sm">
      <div className="mb-3 flex items-center justify-between">
        <SgwLogo showText={false} />
        <Badge variant={state.ready ? "outline" : "secondary"}>{state.ready ? "Ready" : "Needs setup"}</Badge>
      </div>
      <div className="grid grid-cols-3 gap-2">
        <MiniMetric label="Pending" value={state.metrics.pendingApprovals} />
        <MiniMetric label="Handles" value={state.metrics.localSecrets} />
        <MiniMetric label="Agents" value={state.metrics.activeAgents} />
      </div>
      <Separator className="my-3" />
      <div className="space-y-2">
        <div className="font-medium">Approval queue</div>
        {state.pendingRequests.slice(0, 3).map((request) => (
          <div key={request.id} className="rounded-md border bg-card p-2">
            <div className="flex items-center justify-between gap-2">
              <span className="flex min-w-0 items-center gap-2 font-medium">
                <AgentIcon name={request.agentName} className="h-7 w-7" />
                <span className="truncate">{request.agentName || "Agent"}</span>
              </span>
              <Badge variant="secondary">{relativeTime(request.updatedAt)}</Badge>
            </div>
            <div className="mt-1 truncate text-muted-foreground">{commandName(request)} · {requestTarget(request)}</div>
            <div className="mt-2 grid grid-cols-2 gap-2">
              <Button
                size="sm"
                onClick={() => void decide(request, true)}
                disabled={decidingId !== null}
                data-menubar-approve={request.id}
              >
                {decidingId === request.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                Approve once
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void decide(request, false)}
                disabled={decidingId !== null}
                data-menubar-deny={request.id}
              >
                Deny
              </Button>
            </div>
          </div>
        ))}
        {state.pendingRequests.length === 0 ? <div className="text-muted-foreground">No pending approvals.</div> : null}
      </div>
      <div className="mt-4 flex gap-2">
        <Button className="flex-1" onClick={() => window.location.assign("/approvals")}>Open app</Button>
        <Button variant="outline" size="icon" onClick={() => void ctx.refresh()}>
          <RefreshCw className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border bg-card p-2 text-center">
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
    </div>
  );
}

function DemoBadge() {
  return <Badge variant="outline" className="h-4 px-1 text-[9px] font-medium uppercase tracking-wide">Demo</Badge>;
}

function ApprovalSheet({
  request,
  state,
  onOpenChange,
  onDone
}: {
  request: RequestRecord | null;
  state: ConsoleState | null;
  onOpenChange: (open: boolean) => void;
  onDone: () => void;
}) {
  const [busy, setBusy] = React.useState(false);
  const busyRef = React.useRef(false);
  const handle = state?.handles.find((item) => item.handle === request?.handle);

  const approve = async (choice: { mode?: ApprovalMode; durationMs?: number; agentScope?: ApprovalAgentScope }) => {
    if (!request) return;
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await approveRequest(request, choice);
      toast.success("Request approved");
      onOpenChange(false);
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  const alwaysAllow = async () => {
    if (!request || busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      const result = await approveRequestWithScopedPolicy(request);
      toast.success(result.created ? "Created a scoped allow rule and approved this request" : "Approved this request with an existing allow rule");
      onOpenChange(false);
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Could not create a policy rule");
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  const deny = async () => {
    if (!request) return;
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    try {
      await denyRequest(request);
      toast.success("Request denied");
      onOpenChange(false);
      onDone();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : String(err));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  };

  return (
    <Sheet open={Boolean(request)} onOpenChange={onOpenChange}>
      <SheetContent className="w-[min(520px,calc(100vw-24px))] sm:max-w-none">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            <AgentIcon name={request?.agentName} className="h-9 w-9" />
            Approval needed
            {request?.demo ? <DemoBadge /> : null}
          </SheetTitle>
          <SheetDescription>{request?.agentName || "Agent"} wants to use a local credential handle.</SheetDescription>
        </SheetHeader>
        {request ? (
          <div className="space-y-5 px-4">
            <DetailGrid
              rows={[
                ["Agent", (
                  <span className="flex items-center gap-2">
                    <AgentIcon name={request.agentName} className="h-6 w-6" />
                    <span>{request.agentName || "Agent"}</span>
                  </span>
                )],
                ["Action", commandName(request)],
                ["Target", requestTarget(request)],
                ["Authentication", handle?.name || request.handle],
                ["Handle", shortHandle(request.handle)],
                ["Working dir", request.action.workingDir || "-"],
                ["Risk", handle?.severity || "unknown"],
                ["Policy", "User approval required"]
              ]}
            />
            <Textarea placeholder="Optional note for this decision..." />
          </div>
        ) : null}
        {request?.demo ? (
          <div className="mx-4 rounded-md border border-primary/25 bg-primary/5 p-3 text-sm text-muted-foreground">
            Demo requests are read-only and cannot be approved, denied, or executed.
          </div>
        ) : null}
        {!request?.demo ? <SheetFooter>
          <Button disabled={busy} onClick={() => approve({ mode: "per-transaction", agentScope: "same-agent" })} data-approve={request?.id}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Approve once
          </Button>
          <Popover>
            <PopoverTrigger asChild>
              <Button disabled={busy} variant="outline">
                Allow for...
                <ChevronDown className="ml-2 h-4 w-4" />
              </Button>
            </PopoverTrigger>
            <PopoverContent className="grid w-64 gap-2">
              <Button variant="ghost" onClick={() => approve({ mode: "timed-session", durationMs: 15 * 60 * 1000, agentScope: "same-agent" })}>15 minutes</Button>
              <Button variant="ghost" onClick={() => approve({ mode: "timed-session", durationMs: 60 * 60 * 1000, agentScope: "same-agent" })}>1 hour</Button>
              <Button variant="ghost" onClick={() => approve({ mode: "timed-session", durationMs: 24 * 60 * 60 * 1000, agentScope: "same-agent" })}>1 day</Button>
              <Button variant="ghost" onClick={() => approve({ mode: "login-session", agentScope: "same-agent" })}>Current login session</Button>
              <Separator />
              <Button variant="ghost" className="justify-start gap-2" disabled={busy} onClick={() => void alwaysAllow()} data-approve-policy={request?.id}>
                <ShieldCheck className="h-4 w-4" />
                Always allow this request scope
              </Button>
            </PopoverContent>
          </Popover>
          <Button disabled={busy} variant="destructive" onClick={deny}>Deny</Button>
        </SheetFooter> : null}
      </SheetContent>
    </Sheet>
  );
}

function CredentialSheet({
  credential,
  onOpenChange,
  onDone
}: {
  credential: HandleSummary | null;
  onOpenChange: (open: boolean) => void;
  onDone: () => void;
}) {
  const [confirm, setConfirm] = React.useState(false);
  return (
    <>
      <Sheet open={Boolean(credential)} onOpenChange={onOpenChange}>
        <SheetContent className="w-[min(560px,calc(100vw-24px))] sm:max-w-none">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              {credential?.name || "Credential"}
              {credential?.demo ? <DemoBadge /> : null}
            </SheetTitle>
            <SheetDescription>{credential ? shortHandle(credential.handle) : ""}</SheetDescription>
          </SheetHeader>
          {credential ? (
            <div className="space-y-5 px-4">
              <DetailGrid
                rows={[
                  ["Provider", <ProviderIdentity provider={credential.provider} backend={credential.backend} />],
                  ["Backend", credentialBackendLabel(credential.backend)],
                  ["Severity", credential.severity || "low"],
                  ["Inject env", credential.policy.injectEnv || "-"],
                  ["Allowed commands", credential.policy.allowedCommands.join(", ") || "-"],
                  ["Source", credential.source || "-"],
                  ["Updated", relativeTime(credential.updatedAt)]
                ]}
              />
              {credential.demo ? (
                <div className="rounded-md border border-primary/25 bg-primary/5 p-3 text-sm text-muted-foreground">
                  Demo credentials are display-only and cannot be used or deleted.
                </div>
              ) : <Button variant="destructive" onClick={() => setConfirm(true)}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete credential
              </Button>}
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
      <AlertDialog open={confirm} onOpenChange={setConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this credential handle?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes the local handle and fails pending requests that depend on it.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={async () => {
                if (!credential) return;
                await deleteSecret(credential.handle);
                toast.success("Credential deleted");
                setConfirm(false);
                onOpenChange(false);
                onDone();
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function AddCredentialDialog({
  onDone,
  compact = false,
  triggerClassName
}: {
  onDone: () => void;
  compact?: boolean;
  triggerClassName?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [type, setType] = React.useState("api-token");
  const [provider, setProvider] = React.useState("");
  const [injectEnv, setInjectEnv] = React.useState("");
  const [value, setValue] = React.useState("");
  const [allowedCommand, setAllowedCommand] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size={compact ? "icon" : "default"} className={cn("gap-2", compact ? "" : "px-2 sm:px-3", triggerClassName)}>
          <Plus className="h-4 w-4" />
          <span className={compact ? "sr-only" : "sr-only sm:not-sr-only"}>Add credential</span>
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add credential</DialogTitle>
          <DialogDescription>The value is sent only to the local s-gw daemon and stored using the configured local backend.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <Input placeholder="Name" value={name} onChange={(event) => setName(event.target.value)} />
          <div className="grid gap-3 md:grid-cols-2">
            <Select value={type} onValueChange={setType}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="api-token">API token</SelectItem>
                <SelectItem value="private-key">Private key</SelectItem>
                <SelectItem value="password">Password</SelectItem>
                <SelectItem value="credential">Credential pair</SelectItem>
                <SelectItem value="access-key">Access key</SelectItem>
              </SelectContent>
            </Select>
            <Input placeholder="Provider, e.g. aws" value={provider} onChange={(event) => setProvider(event.target.value)} />
          </div>
          <Input placeholder="Inject env, e.g. AWS_ACCESS_KEY_ID" value={injectEnv} onChange={(event) => setInjectEnv(event.target.value)} />
          <Input placeholder="Allowed command, e.g. aws" value={allowedCommand} onChange={(event) => setAllowedCommand(event.target.value)} />
          <Textarea placeholder="Credential value" value={value} onChange={(event) => setValue(event.target.value)} />
        </div>
        <DialogFooter>
          <Button
            disabled={busy || !name || !value}
            onClick={async () => {
              setBusy(true);
              try {
                await createSecret({
                  name,
                  type,
                  provider: provider || undefined,
                  injectEnv: injectEnv || undefined,
                  allowedCommands: allowedCommand ? [allowedCommand] : [],
                  value,
                  backend: "keychain"
                });
                toast.success("Credential handle created");
                setOpen(false);
                setName("");
                setValue("");
                onDone();
              } catch (err) {
                toast.error(err instanceof Error ? err.message : String(err));
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Create handle
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const policySecretTypeOptions: MultiSelectOption[] = [
  { value: "api-token", label: "API token" },
  { value: "ssh-key", label: "SSH key" },
  { value: "private-key", label: "Private key" },
  { value: "password", label: "Password" },
  { value: "credential", label: "Credential pair" },
  { value: "access-key", label: "Access key" },
  { value: "unknown", label: "Unknown" }
];

const policyActionKindOptions: MultiSelectOption[] = [
  { value: "env_command", label: "Command" },
  { value: "ssh_session", label: "SSH session" }
];

type PolicyOptionSources = {
  agents: MultiSelectOption[];
  handles: MultiSelectOption[];
  providers: MultiSelectOption[];
  commands: MultiSelectOption[];
  injectEnvs: MultiSelectOption[];
  workingDirs: MultiSelectOption[];
  sshTargets: MultiSelectOption[];
  sshPorts: MultiSelectOption[];
};

type PolicyFormState = {
  name: string;
  decision: ApprovalPolicyDecision;
  priority: string;
  agents: string[];
  handles: string[];
  providers: string[];
  secretTypes: string[];
  minSeverity: string;
  actionKinds: string[];
  commands: string[];
  injectEnvs: string[];
  workingDirs: string[];
  sshTargets: string[];
  sshPorts: string[];
};

function buildPolicyOptionSources(state: ConsoleState): PolicyOptionSources {
  const agents = new Set<string>();
  for (const agent of state.agents) agents.add(agent.name);
  for (const request of state.requests) if (request.agentName) agents.add(request.agentName);

  const providers = new Set<string>();
  for (const handle of state.handles) if (handle.provider) providers.add(handle.provider);

  const commands = new Set<string>();
  for (const request of state.requests) commands.add(request.action.command);
  for (const handle of state.handles) for (const command of handle.policy.allowedCommands) commands.add(command);

  const injectEnvs = new Set<string>();
  for (const handle of state.handles) if (handle.policy.injectEnv) injectEnvs.add(handle.policy.injectEnv);
  for (const request of state.requests) if (request.action.injectEnv) injectEnvs.add(request.action.injectEnv);

  const workingDirs = new Set<string>();
  for (const request of state.requests) if (request.action.workingDir) workingDirs.add(request.action.workingDir);

  const sshTargets = new Set<string>();
  const sshPorts = new Set<string>();
  for (const request of state.requests) {
    if (request.action.ssh?.target) sshTargets.add(request.action.ssh.target);
    if (request.action.ssh?.port) sshPorts.add(String(request.action.ssh.port));
  }

  return {
    agents: sortedPolicyOptions(agents),
    handles: state.handles
      .map((handle) => ({ value: handle.handle, label: handle.name || shortHandle(handle.handle), hint: handle.provider || handle.type }))
      .sort((left, right) => (left.label || left.value).localeCompare(right.label || right.value)),
    providers: sortedPolicyOptions(providers),
    commands: sortedPolicyOptions(commands),
    injectEnvs: sortedPolicyOptions(injectEnvs),
    workingDirs: sortedPolicyOptions(workingDirs),
    sshTargets: sortedPolicyOptions(sshTargets),
    sshPorts: sortedPolicyOptions(sshPorts)
  };
}

function sortedPolicyOptions(values: Iterable<string>): MultiSelectOption[] {
  return [...new Set([...values].filter(Boolean))]
    .sort((left, right) => left.localeCompare(right))
    .map((value) => ({ value }));
}

function emptyPolicyForm(): PolicyFormState {
  return {
    name: "",
    decision: "ask",
    priority: "",
    agents: [],
    handles: [],
    providers: [],
    secretTypes: [],
    minSeverity: "",
    actionKinds: [],
    commands: [],
    injectEnvs: [],
    workingDirs: [],
    sshTargets: [],
    sshPorts: []
  };
}

function policyFormFromRule(rule: ApprovalPolicyRuleRecord): PolicyFormState {
  const conditions = rule.conditions;
  return {
    name: rule.name,
    decision: rule.decision,
    priority: String(rule.priority),
    agents: conditions.agents || [],
    handles: conditions.handles || [],
    providers: conditions.providers || [],
    secretTypes: conditions.secretTypes || [],
    minSeverity: conditions.minSeverity || "",
    actionKinds: conditions.actionKinds || [],
    commands: conditions.commands || [],
    injectEnvs: conditions.injectEnvs || [],
    workingDirs: conditions.workingDirs || [],
    sshTargets: conditions.sshTargets || [],
    sshPorts: (conditions.sshPorts || []).map(String)
  };
}

function policyFormToInput(form: PolicyFormState, enabled: boolean, bindingsLocked = false): PolicyInput {
  const priority = form.priority.trim();
  const input: PolicyInput = {
    name: form.name.trim(),
    enabled,
    decision: form.decision,
    priority: priority ? Number(priority) : undefined,
    agents: form.agents,
    providers: form.providers,
    secretTypes: form.secretTypes,
    minSeverity: form.minSeverity ? form.minSeverity as SecretSeverity : null,
    actionKinds: form.actionKinds,
    commands: form.commands,
    workingDirs: form.workingDirs,
    sshTargets: form.sshTargets,
    sshPorts: form.sshPorts.map((port) => Number(port))
  };
  if (!bindingsLocked) {
    input.handles = form.handles;
    input.injectEnvs = form.injectEnvs;
  }
  return input;
}

function PolicyEditorDialog({
  open,
  onOpenChange,
  onDone,
  state,
  rule
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDone: () => void;
  state: ConsoleState;
  rule?: ApprovalPolicyRuleRecord | null;
}) {
  const [form, setForm] = React.useState<PolicyFormState>(emptyPolicyForm);
  const [advanced, setAdvanced] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const sources = React.useMemo(() => buildPolicyOptionSources(state), [state]);
  const editing = Boolean(rule);
  const bindingsLocked = Boolean(rule?.conditions.envBindings?.length);

  React.useEffect(() => {
    if (!open) return;
    setForm(rule ? policyFormFromRule(rule) : emptyPolicyForm());
    setAdvanced(Boolean(rule));
  }, [open, rule]);

  const update = <K extends keyof PolicyFormState>(field: K, value: PolicyFormState[K]) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  async function save() {
    if (busy || !form.name.trim()) return;
    setBusy(true);
    try {
      const body = policyFormToInput(form, rule?.enabled ?? true, bindingsLocked);
      if (rule) {
        await updatePolicy(rule.id, body);
        toast.success("Policy rule updated");
      } else {
        await addPolicy(body);
        toast.success("Policy rule added");
      }
      onOpenChange(false);
      onDone();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Could not save policy");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100vh-48px)] w-[min(760px,calc(100vw-24px))] overflow-y-auto sm:max-w-none">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit policy rule" : "Add policy rule"}</DialogTitle>
          <DialogDescription>
            Leave a condition empty to match anything. The preview shows the request shape this rule will affect.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-5">
          {rule?.conditions.envBindings?.length ? (
            <Alert>
              <AlertTitle>Exact credential bindings</AlertTitle>
              <AlertDescription>
                <span>This rule stays tied to the approved credential and environment-variable set.</span>
                <span className="mt-2 flex flex-wrap gap-1.5">
                  {rule.conditions.envBindings.map((binding) => (
                    <code key={`${binding.injectEnv}:${binding.handle}`} className="rounded bg-muted px-1.5 py-0.5 text-xs">
                      {binding.injectEnv} → {state.handles.find((handle) => handle.handle === binding.handle)?.name || shortHandle(binding.handle)}
                    </code>
                  ))}
                </span>
                <span className="mt-2 block">Create a new rule from an approval to change these bindings.</span>
              </AlertDescription>
            </Alert>
          ) : null}
          <PolicyFlowPreview form={form} state={state} />
          <PolicyFormFields
            form={form}
            update={update}
            sources={sources}
            advanced={advanced}
            bindingsLocked={bindingsLocked}
            onShowAdvanced={() => setAdvanced(true)}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>Cancel</Button>
          <Button onClick={() => void save()} disabled={busy || !form.name.trim()}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {editing ? "Save changes" : "Add rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PolicyFormFields({
  form,
  update,
  sources,
  advanced,
  bindingsLocked,
  onShowAdvanced
}: {
  form: PolicyFormState;
  update: <K extends keyof PolicyFormState>(field: K, value: PolicyFormState[K]) => void;
  sources: PolicyOptionSources;
  advanced: boolean;
  bindingsLocked: boolean;
  onShowAdvanced: () => void;
}) {
  return (
    <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
      <PolicyField label="Name" className="sm:col-span-2">
        <Input value={form.name} onChange={(event) => update("name", event.target.value)} placeholder="e.g. Allow Codex to run aws" />
      </PolicyField>
      <PolicyField label="Decision" hint="What s-gw does when this rule matches.">
        <Select value={form.decision} onValueChange={(value) => update("decision", value as ApprovalPolicyDecision)}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="ask">Ask for approval</SelectItem>
            <SelectItem value="allow">Allow automatically</SelectItem>
            <SelectItem value="deny">Deny automatically</SelectItem>
          </SelectContent>
        </Select>
      </PolicyField>
      <PolicyField label="Agents" hint="Request attribution, not a cryptographic identity boundary.">
        <MultiSelectField values={form.agents} onChange={(value) => update("agents", value)} options={sources.agents} renderIcon={(value) => <AgentIcon name={value} className="h-4 w-4" />} aria-label="Policy agents" />
      </PolicyField>
      <PolicyField label={bindingsLocked ? "Credentials (fixed)" : "Credentials"} hint={bindingsLocked ? "Fixed by the exact binding set above." : undefined}>
        <MultiSelectField values={form.handles} onChange={(value) => update("handles", value)} options={sources.handles} disabled={bindingsLocked} aria-label="Policy credentials" />
      </PolicyField>
      <PolicyField label="Commands">
        <MultiSelectField values={form.commands} onChange={(value) => update("commands", value)} options={sources.commands} aria-label="Policy commands" />
      </PolicyField>
      <PolicyField label="Action kinds">
        <MultiSelectField values={form.actionKinds} onChange={(value) => update("actionKinds", value)} options={policyActionKindOptions} allowCustom={false} aria-label="Policy action kinds" />
      </PolicyField>
      {advanced ? (
        <>
          <PolicyField label="Providers">
            <MultiSelectField values={form.providers} onChange={(value) => update("providers", value)} options={sources.providers} aria-label="Policy providers" />
          </PolicyField>
          <PolicyField label="Credential types">
            <MultiSelectField values={form.secretTypes} onChange={(value) => update("secretTypes", value)} options={policySecretTypeOptions} allowCustom={false} aria-label="Policy credential types" />
          </PolicyField>
          <PolicyField label="Minimum severity">
            <Select value={form.minSeverity || "any"} onValueChange={(value) => update("minSeverity", value === "any" ? "" : value)}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="any">Any severity</SelectItem>
                <SelectItem value="low">Low and above</SelectItem>
                <SelectItem value="medium">Medium and above</SelectItem>
                <SelectItem value="high">High and above</SelectItem>
                <SelectItem value="critical">Critical only</SelectItem>
              </SelectContent>
            </Select>
          </PolicyField>
          <PolicyField label={bindingsLocked ? "Injected environment variables (fixed)" : "Injected environment variables"} hint={bindingsLocked ? "Fixed by the exact binding set above." : undefined}>
            <MultiSelectField values={form.injectEnvs} onChange={(value) => update("injectEnvs", value)} options={sources.injectEnvs} disabled={bindingsLocked} aria-label="Policy environment variables" />
          </PolicyField>
          <PolicyField label="Working directories">
            <MultiSelectField values={form.workingDirs} onChange={(value) => update("workingDirs", value)} options={sources.workingDirs} aria-label="Policy working directories" />
          </PolicyField>
          <PolicyField label="SSH targets">
            <MultiSelectField values={form.sshTargets} onChange={(value) => update("sshTargets", value)} options={sources.sshTargets} aria-label="Policy SSH targets" />
          </PolicyField>
          <PolicyField label="SSH ports">
            <MultiSelectField values={form.sshPorts} onChange={(value) => update("sshPorts", value)} options={sources.sshPorts} aria-label="Policy SSH ports" />
          </PolicyField>
          <PolicyField label="Priority" hint="Lower values run first. Leave empty to add at the end.">
            <Input value={form.priority} inputMode="numeric" onChange={(event) => update("priority", event.target.value.replace(/[^0-9]/g, ""))} placeholder="Auto" />
          </PolicyField>
        </>
      ) : (
        <Button type="button" variant="ghost" size="sm" className="justify-self-start text-muted-foreground sm:col-span-2" onClick={onShowAdvanced}>
          <SlidersHorizontal className="mr-2 h-4 w-4" />More conditions
        </Button>
      )}
    </div>
  );
}

function PolicyField({ label, hint, className, children }: { label: string; hint?: string; className?: string; children: React.ReactNode }) {
  return (
    <div className={cn("min-w-0 space-y-1.5", className)}>
      <div>
        <div className="text-sm font-medium">{label}</div>
        {hint ? <div className="text-xs text-muted-foreground">{hint}</div> : null}
      </div>
      {children}
    </div>
  );
}

function PolicyFlowPreview({ form, state }: { form: PolicyFormState; state: ConsoleState }) {
  const handleLabels = form.handles.map((handle) => state.handles.find((item) => item.handle === handle)?.name || shortHandle(handle));
  const decisionCopy = form.decision === "allow" ? "Runs automatically" : form.decision === "deny" ? "Blocked automatically" : "Requires approval";
  const DecisionIcon = form.decision === "allow" ? ShieldCheck : form.decision === "deny" ? Ban : Clock3;
  return (
    <div className="grid gap-2 rounded-lg border bg-muted/30 p-3 text-sm sm:grid-cols-4" data-policy-flow-preview>
      <PolicyFlowCell label="Agent" value={summarizePolicyValues(form.agents, "Any agent")} icon={<UsersRound className="h-4 w-4" />} />
      <PolicyFlowCell label="Action" value={summarizePolicyValues(form.commands, form.actionKinds.includes("ssh_session") ? "SSH session" : "Any command")} icon={<CommandIcon className="h-4 w-4" />} />
      <PolicyFlowCell label="Credential" value={summarizePolicyValues(handleLabels, "Any credential")} icon={<KeyRound className="h-4 w-4" />} />
      <PolicyFlowCell label="Decision" value={decisionCopy} icon={<DecisionIcon className="h-4 w-4" />} />
    </div>
  );
}

function PolicyFlowCell({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-md border bg-background/70 p-2">
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">{icon}{label}</div>
      <div className="mt-1 truncate font-medium">{value}</div>
    </div>
  );
}

function summarizePolicyValues(values: string[], fallback: string): string {
  if (values.length === 0) return fallback;
  if (values.length <= 2) return values.join(", ");
  return `${values.slice(0, 2).join(", ")} +${values.length - 2}`;
}

function CommandPalette({
  open,
  onOpenChange,
  setView,
  state
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  setView: (view: ViewId) => void;
  state: ConsoleState | null;
}) {
  const go = (view: ViewId) => {
    setView(view);
    onOpenChange(false);
  };
  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Command Palette">
      <Command>
        <CommandInput placeholder="Search commands..." />
        <CommandList>
          <CommandEmpty>No command found.</CommandEmpty>
          <CommandGroup heading="Views">
            {navItems.map((item) => (
              <CommandItem key={item.id} onSelect={() => go(item.id)}>
                <item.icon className="h-4 w-4" />
                {item.label}
                <CommandShortcut>open</CommandShortcut>
              </CommandItem>
            ))}
          </CommandGroup>
          <CommandGroup heading="Safe actions">
            <CommandItem onSelect={() => go("approvals")}>
              <Bell className="h-4 w-4" />
              Review pending approvals
              <CommandShortcut>{state?.metrics.pendingApprovals || 0}</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => window.open(auditCsvUrl(), "_blank")}>
              <Download className="h-4 w-4" />
              Download audit CSV
            </CommandItem>
          </CommandGroup>
        </CommandList>
      </Command>
    </CommandDialog>
  );
}

function FlowRowsTable({ rows }: { rows: UsageFlowRow[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Agent</TableHead>
          <TableHead>Authentication type</TableHead>
          <TableHead>Target type</TableHead>
          <TableHead className="w-16 text-right">Req.</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={`${row.agentId}-${row.authTypeId}-${row.targetTypeId}-${row.lastSeen}`}>
            <TableCell>
              <span className="flex items-center gap-2">{row.agent}{row.demo ? <DemoBadge /> : null}</span>
            </TableCell>
            <TableCell>{row.authType}</TableCell>
            <TableCell>{row.targetType}</TableCell>
            <TableCell className="text-right">{row.count}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function PageFrame({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <div className="sgw-page-frame space-y-4 p-4 lg:p-5">
      <PageHeading title={title} description={description} />
      {children}
    </div>
  );
}

function PageHeading({ title, description }: { title: string; description: string }) {
  return (
    <div className="sgw-page-heading">
      <h1 className="text-2xl font-semibold tracking-normal">{title}</h1>
      <p className="mt-1 text-sm text-muted-foreground">{description}</p>
    </div>
  );
}

function DataCard({ children }: { children: React.ReactNode }) {
  return <Card><CardContent className="p-0">{children}</CardContent></Card>;
}

function StatusPill({ ok, label }: { ok?: boolean; label: string }) {
  return (
    <div className="sgw-glass-panel hidden items-center gap-2 rounded-full border bg-card/70 px-3 py-2 text-sm lg:flex">
      <span className={cn("h-2 w-2 rounded-full", ok ? "bg-emerald-400" : "bg-amber-400")} />
      {label}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: SecretSeverity }) {
  const variant = severityRank(severity) >= 3 ? "destructive" : severity === "medium" ? "secondary" : "outline";
  return <Badge variant={variant}>{titleCase(severity)}</Badge>;
}

function RequestStateBadge({ state }: { state: string }) {
  const variant = state === "pending" ? "secondary" : state === "denied" || state === "failed" ? "destructive" : "outline";
  return <Badge variant={variant}>{titleCase(state)}</Badge>;
}

function DecisionBadge({ decision }: { decision: ApprovalPolicyDecision }) {
  const variant = decision === "deny" ? "destructive" : decision === "allow" ? "outline" : "secondary";
  return <Badge variant={variant}>{titleCase(decision)}</Badge>;
}

function ReadinessAlert({ state }: { state: ConsoleState }) {
  return (
    <Alert data-readiness-banner className={cn("show", state.ready ? "hidden" : "")}>
      <AlertTriangle className="h-4 w-4" />
      <AlertTitle>{state.readiness.summary || "s-gw is not ready"}</AlertTitle>
      <AlertDescription>{state.readiness.blockers.join(" ") || "Run s-gw setup to finish local configuration."}</AlertDescription>
    </Alert>
  );
}

function DetailGrid({ rows }: { rows: Array<[string, React.ReactNode]> }) {
  return (
    <div className="grid gap-3 text-sm">
      {rows.map(([label, value]) => (
        <div key={label} className="grid grid-cols-[130px_1fr] gap-3 border-b border-border/60 pb-2">
          <div className="text-muted-foreground">{label}</div>
          <div className="min-w-0 break-words font-medium">{value}</div>
        </div>
      ))}
    </div>
  );
}

function LoadingDashboard() {
  return (
    <div className="grid gap-4 p-6 md:grid-cols-2 xl:grid-cols-4">
      {Array.from({ length: 8 }).map((_, index) => <Skeleton key={index} className="h-40 rounded-lg" />)}
    </div>
  );
}

function humanEvent(value: string): string {
  return titleCase(value.replace(/\./g, " "));
}

function filterText<T>(items: T[], search: string, text: (item: T) => string): T[] {
  const needle = search.trim().toLowerCase();
  if (!needle) return items;
  return items.filter((item) => text(item).toLowerCase().includes(needle));
}

function viewFromLocation(): ViewId {
  const params = new URLSearchParams(window.location.search);
  const byQuery = params.get("view");
  const path = window.location.pathname.replace(/^\/+/, "");
  const value = byQuery || path || "overview";
  if (navItems.some((item) => item.id === value)) return value as ViewId;
  if (value === "flow") return "usage-flow";
  return "overview";
}

function isNativeShellRoute(): boolean {
  return new URLSearchParams(window.location.search).get("native-shell") === "1";
}

function embeddedView(): { compact: boolean } | null {
  const params = new URLSearchParams(window.location.search);
  if (window.location.pathname === "/menubar") return null;
  if (params.get("embed") === "usage-flow") {
    return { compact: params.get("compact") === "1" };
  }
  return null;
}

export default App;
