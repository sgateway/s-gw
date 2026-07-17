import * as React from "react";
import {
  sankey,
  sankeyLinkHorizontal,
  type SankeyNode
} from "d3-sankey";
import { ArrowUpRight, XIcon } from "lucide-react";

import { UsageFlowDetailRow } from "@/components/UsageFlowDetailRow";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle
} from "@/components/ui/sheet";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { useElementSize } from "@/hooks/use-element-size";
import type { UsageFlow, UsageFlowEntry, UsageFlowLink, UsageFlowNode } from "@/lib/types";
import { cn } from "@/lib/utils";

type Stage = "agent" | "auth" | "target";

interface SankeyDatum extends UsageFlowNode {
  stage: Stage;
  x0?: number;
  x1?: number;
  y0?: number;
  y1?: number;
}

interface SankeyEdge {
  source: string | SankeyDatum;
  target: string | SankeyDatum;
  value: number;
  width?: number;
}

interface SelectedFlow {
  id: string;
  title: string;
  subtitle: string;
  entries: UsageFlowEntry[];
}

const stageLabels: Record<Stage, string> = {
  agent: "Agent",
  auth: "Authentication type",
  target: "Target type"
};

const stageColors: Record<Stage, string> = {
  agent: "#5f78ff",
  auth: "#21d2b6",
  target: "#2b9cff"
};

export function UsageFlowSankey({
  flow,
  compact = false,
  className,
  onExpand
}: {
  flow: UsageFlow;
  compact?: boolean;
  className?: string;
  onExpand?: () => void;
}) {
  const [wrapRef, size] = useElementSize<HTMLDivElement>();
  const [selected, setSelected] = React.useState<SelectedFlow | null>(null);
  const resizing = React.useRef(false);
  const lastResizeAt = React.useRef(0);
  const hasFlow = flow.nodes.length > 0 && flow.links.length > 0;
  const layout = React.useMemo(() => (hasFlow ? buildLayout(flow, compact, size) : null), [flow, compact, hasFlow, size]);

  React.useEffect(() => {
    document.documentElement.dataset.flowSelected = selected ? "true" : "false";
    return () => {
      delete document.documentElement.dataset.flowSelected;
    };
  }, [selected]);

  React.useEffect(() => {
    if (!selected) return;

    const closeOutside = (event: PointerEvent) => {
      if (event.button !== 0 || !(event.target instanceof Element)) return;
      if (event.target.closest("[data-flow-detail-panel], [data-flow-detail-resize], [data-flow-node], [data-flow-link-source]")) return;
      event.preventDefault();
      event.stopPropagation();
      setSelected(null);
    };

    document.addEventListener("pointerup", closeOutside, true);
    return () => document.removeEventListener("pointerup", closeOutside, true);
  }, [selected]);

  const onSheetOpenChange = (open: boolean) => {
    if (open) return;
    if (resizing.current || Date.now() - lastResizeAt.current < 200) return;
    setSelected(null);
  };

  const finishResize = () => {
    lastResizeAt.current = Date.now();
    resizing.current = false;
    document.removeEventListener("pointerup", finishResize);
    document.removeEventListener("pointercancel", finishResize);
  };

  const startResize = () => {
    resizing.current = true;
    lastResizeAt.current = Date.now();
    document.addEventListener("pointerup", finishResize, { once: true });
    document.addEventListener("pointercancel", finishResize, { once: true });
  };

  if (!hasFlow || !layout) {
    return (
      <div className={cn("grid min-h-64 place-items-center rounded-lg border border-dashed border-border/70 bg-muted/20", className)}>
        <div className="text-center">
          <div className="text-sm font-medium">No credential flow yet</div>
          <div className="mt-1 text-xs text-muted-foreground">Agent requests will map here after s-gw sees handle-backed actions.</div>
        </div>
      </div>
    );
  }

  return (
    <div
      ref={wrapRef}
      className={cn("sankey-wrap relative h-full min-h-80 overflow-hidden rounded-lg border border-border/70 bg-card/55", className)}
      data-sankey-wrap
      data-compact={compact ? "true" : "false"}
    >
      {flow.demo ? (
        <Badge variant="outline" className="absolute left-3 top-3 z-10 h-5 bg-background/85 px-1.5 text-[9px] uppercase tracking-wide">
          Demo
        </Badge>
      ) : null}
      {onExpand ? (
        <Button
          type="button"
          size="icon"
          variant="secondary"
          className="absolute right-3 top-3 z-10 h-8 w-8"
          onClick={onExpand}
          aria-label="Open usage flow"
        >
          <ArrowUpRight className="h-4 w-4" />
        </Button>
      ) : null}
      <svg
        data-sankey
        data-engine="d3-sankey"
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="img"
        aria-label="Agent to authentication type to target type usage flow"
        className="h-full w-full"
        preserveAspectRatio="xMidYMid meet"
      >
        <defs>
          {layout.graph.links.map((link, index) => {
            const source = link.source as SankeyDatum;
            const target = link.target as SankeyDatum;
            return (
              <linearGradient
                key={`${source.id}-${target.id}-${index}`}
                id={`sankey-gradient-${index}`}
                gradientUnits="userSpaceOnUse"
                x1={source.x1}
                x2={target.x0}
              >
                <stop offset="0%" stopColor={stageColors[source.stage]} />
                <stop offset="100%" stopColor={stageColors[target.stage]} />
              </linearGradient>
            );
          })}
        </defs>
        <g data-d3-sankey-renderer="true">
          {layout.stageHeadings.map((heading) => (
            <text
              key={heading.stage}
              x={heading.x}
              y={layout.margin.top - 18}
              textAnchor={heading.textAnchor}
              className="sankey-heading fill-foreground text-[18px] font-semibold"
            >
              {stageLabels[heading.stage]}
            </text>
          ))}

          {layout.graph.links.map((link, index) => {
            const source = link.source as SankeyDatum;
            const target = link.target as SankeyDatum;
            const selectedId = selected?.id;
            const active = !selectedId || source.id === selectedId || target.id === selectedId;
            return (
              <path
                key={`${source.id}-${target.id}-${index}`}
                className={cn("sankey-link cursor-pointer transition-opacity", active ? "opacity-70 hover:opacity-95" : "opacity-15")}
                d={layout.linkPath(link) || ""}
                fill="none"
                stroke={`url(#sankey-gradient-${index})`}
                strokeLinecap="butt"
                strokeWidth={Math.max(2, link.width || 1)}
                data-flow-link-source={source.id}
                data-flow-link-target={target.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelected(selectLink(flow, source, target))}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelected(selectLink(flow, source, target));
                  }
                }}
              />
            );
          })}

          {layout.graph.nodes.map((node) => {
            const selectedId = selected?.id;
            const active = !selectedId || node.id === selectedId;
            const labelX = node.stage === "target" ? (node.x0 || 0) - 10 : (node.x1 || 0) + 10;
            const labelAnchor = node.stage === "target" ? "end" : "start";
            return (
              <g
                key={node.id}
                className={cn("sankey-node cursor-pointer transition-opacity", active && selectedId ? "is-selected" : "", !active ? "is-muted opacity-35" : "")}
                data-flow-node={node.id}
                role="button"
                tabIndex={0}
                onClick={() => setSelected(selectNode(flow, node))}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    setSelected(selectNode(flow, node));
                  }
                }}
              >
                <rect
                  x={node.x0}
                  y={node.y0}
                  width={Math.max(10, (node.x1 || 0) - (node.x0 || 0))}
                  height={Math.max(8, (node.y1 || 0) - (node.y0 || 0))}
                  rx={4}
                  fill={stageColors[node.stage]}
                />
                <text
                  x={labelX}
                  y={(node.y0 || 0) + Math.max(16, ((node.y1 || 0) - (node.y0 || 0)) / 2)}
                  className="sankey-label fill-foreground text-[13.5px] font-normal"
                  dominantBaseline="middle"
                  textAnchor={labelAnchor}
                >
                  {node.label}
                </text>
                {!compact ? (
                  <text
                    x={labelX}
                    y={(node.y0 || 0) + Math.max(34, ((node.y1 || 0) - (node.y0 || 0)) / 2 + 19)}
                    className="fill-muted-foreground text-[12px] font-normal"
                    dominantBaseline="middle"
                    textAnchor={labelAnchor}
                  >
                    {node.count} request{node.count === 1 ? "" : "s"}
                  </text>
                ) : null}
              </g>
            );
          })}
        </g>
      </svg>
      {!compact ? (
        <div className="flow-legend absolute bottom-3 left-3 flex flex-wrap gap-2 text-xs text-muted-foreground">
          <Badge variant="outline">Agent</Badge>
          <Badge variant="outline">Authentication type</Badge>
          <Badge variant="outline">Target type</Badge>
        </div>
      ) : null}

      <Sheet open={Boolean(selected)} onOpenChange={onSheetOpenChange}>
        <SheetContent
          side="right"
          showCloseButton={false}
          className="pointer-events-none w-screen max-w-none border-0 bg-transparent p-0 shadow-none data-[side=right]:!w-screen data-[side=right]:!max-w-none data-[side=right]:sm:!max-w-none"
          data-flow-detail-sheet
          onPointerDownOutside={(event) => event.preventDefault()}
          onInteractOutside={(event) => event.preventDefault()}
        >
          <ResizablePanelGroup
            orientation="horizontal"
            className="h-full w-full"
            data-flow-detail-resizable
          >
            <ResizablePanel defaultSize="46%" minSize="0%" className="pointer-events-none" />
            <ResizableHandle
              withHandle
              className="pointer-events-auto"
              data-flow-detail-resize
              onPointerDownCapture={startResize}
              onPointerUp={finishResize}
              onPointerCancel={finishResize}
            />
            <ResizablePanel defaultSize="54%" minSize="360px" maxSize="92%" className="pointer-events-auto">
              <div className="relative flex h-full min-w-0 flex-col border-l bg-popover text-popover-foreground shadow-lg" data-flow-detail-panel>
                <SheetHeader className="pr-12">
                  <SheetTitle data-flow-drill-title>{selected?.title || "All credential-use routes"}</SheetTitle>
                  <SheetDescription data-flow-drill-detail>
                    {selected?.subtitle || "Agent requests grouped by authentication type and target type."}
                  </SheetDescription>
                </SheetHeader>
                <SheetClose asChild>
                  <Button variant="ghost" size="icon-sm" className="absolute right-3 top-3" onClick={() => setSelected(null)}>
                    <XIcon data-icon="inline-start" />
                    <span className="sr-only">Close</span>
                  </Button>
                </SheetClose>
                <div className="min-h-0 flex-1 px-4 pb-4">
                  <FlowEntries entries={selected?.entries || flow.entries} />
                </div>
              </div>
            </ResizablePanel>
          </ResizablePanelGroup>
        </SheetContent>
      </Sheet>
    </div>
  );
}

function FlowEntries({ entries }: { entries: UsageFlowEntry[] }) {
  return (
    <div className="h-full overflow-auto rounded-md border" data-flow-entries>
      {entries.map((entry) => <UsageFlowDetailRow key={entry.requestId} entry={entry} />)}
      {entries.length === 0 ? (
        <div className="grid h-40 place-items-center text-sm text-muted-foreground">No matching access events.</div>
      ) : null}
    </div>
  );
}

function buildLayout(flow: UsageFlow, compact: boolean, size: { width: number; height: number }) {
  const width = Math.max(compact ? 680 : 980, size.width || 0);
  const rowCount = Math.max(1, flow.nodes.length);
  const height = compact ? Math.max(320, size.height || 0) : Math.max(560, size.height || rowCount * 62);
  const margin = {
    top: compact ? 52 : 70,
    right: compact ? 26 : 44,
    bottom: compact ? 34 : 58,
    left: compact ? 26 : 44
  };

  const nodes: SankeyDatum[] = flow.nodes.map((node) => ({ ...node, stage: node.kind }));
  const links: SankeyEdge[] = flow.links.map((link) => ({ ...link }));

  const stageOrder: Record<Stage, number> = { agent: 0, auth: 1, target: 2 };
  const renderer = sankey<SankeyDatum, SankeyEdge>()
    .nodeId((node) => node.id)
    .nodeWidth(compact ? 12 : 16)
    .nodePadding(compact ? 18 : 24)
    .nodeAlign((node) => stageOrder[node.stage])
    .nodeSort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .extent([
      [margin.left, margin.top],
      [width - margin.right, height - margin.bottom]
    ]);

  const graph = renderer({ nodes, links });
  const stageHeadings = (["agent", "auth", "target"] as Stage[]).map((stage) => {
    const stageNodes = graph.nodes.filter((node) => node.stage === stage);
    if (!stageNodes.length) {
      return { stage, textAnchor: "start" as const, x: margin.left };
    }

    const left = Math.min(...stageNodes.map((node) => node.x0 || 0));
    const right = Math.max(...stageNodes.map((node) => node.x1 || 0));
    if (stage === "auth") {
      return { stage, textAnchor: "middle" as const, x: (left + right) / 2 };
    }
    if (stage === "target") {
      return { stage, textAnchor: "end" as const, x: Math.min(width - margin.right, right) };
    }
    return { stage, textAnchor: "start" as const, x: left };
  });

  const linkPath = sankeyLinkHorizontal<SankeyDatum, SankeyEdge>();
  return { width, height, margin, graph, stageHeadings, linkPath };
}

function selectNode(flow: UsageFlow, node: SankeyNode<SankeyDatum, SankeyEdge>): SelectedFlow {
  const id = node.id;
  const entries = flow.entries.filter((entry) => entry.agentId === id || entry.authTypeId === id || entry.targetTypeId === id);
  return {
    id,
    title: node.label,
    subtitle: `${entries.length} access event${entries.length === 1 ? "" : "s"} · ${node.detail || stageLabels[node.stage]}`,
    entries
  };
}

function selectLink(flow: UsageFlow, source: SankeyDatum, target: SankeyDatum): SelectedFlow {
  const entries = flow.entries.filter((entry) => {
    const agentAuth = entry.agentId === source.id && entry.authTypeId === target.id;
    const authTarget = entry.authTypeId === source.id && entry.targetTypeId === target.id;
    return agentAuth || authTarget;
  });
  return {
    id: `${source.id}->${target.id}`,
    title: `${source.label} -> ${target.label}`,
    subtitle: `${entries.length} access event${entries.length === 1 ? "" : "s"}`,
    entries
  };
}
