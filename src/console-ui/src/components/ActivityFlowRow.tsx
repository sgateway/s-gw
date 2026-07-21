import type { LucideIcon } from "lucide-react";
import {
  ArrowRight,
  Cloud,
  KeyRound,
  Monitor,
  Route,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Terminal
} from "lucide-react";

import { AgentIcon } from "@/components/AgentIcon";
import { commandName, relativeTime, requestTarget, shortHandle, titleCase } from "@/lib/format";
import type { AuditEvent, ConsoleState, RequestRecord } from "@/lib/types";
import { cn } from "@/lib/utils";

type ActivityTone = "success" | "pending" | "failure" | "neutral";

interface ActivityNode {
  label: string;
  detail: string;
  Icon?: LucideIcon;
  agentName?: string;
}

interface ActivityFlow {
  agent: ActivityNode;
  action: ActivityNode;
  target: ActivityNode;
  status: string;
  tone: ActivityTone;
}

interface EventFlowCard {
  badge: string;
  title: string;
  detail: string;
  Icon?: LucideIcon;
  agentName?: string;
  tone?: ActivityTone;
  lines: Array<[string, string]>;
}

export interface ActivityEventFlow {
  source: EventFlowCard;
  agent: EventFlowCard;
  action: EventFlowCard;
  control: EventFlowCard;
  target: EventFlowCard;
  status: string;
  tone: ActivityTone;
  eventType: string;
  eventId: string;
  sourceLabel: string;
  destinationLabel: string;
  reasonCode: string;
  ruleName: string;
}

interface ActivityLookups {
  requests: Map<string, RequestRecord>;
  handles: Map<string, ConsoleState["handles"][number]>;
}

const lookupCache = new WeakMap<ConsoleState, ActivityLookups>();

export function ActivityFlowRow({
  event,
  state,
  compact = false
}: {
  event: AuditEvent;
  state: ConsoleState;
  compact?: boolean;
}) {
  const flow = describeActivity(event, state);

  return (
    <div className={cn("sgw-activity-flow-row", compact && "is-compact")} data-activity-flow>
      <div className="sgw-activity-flow-path" aria-label={`${flow.agent.label} ${flow.action.label} ${flow.target.label}`}>
        <FlowNode node={flow.agent} />
        <FlowConnector />
        <FlowNode node={flow.action} />
        <FlowConnector />
        <FlowNode node={flow.target} />
      </div>

      <div className="sgw-activity-flow-meta">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={cn("sgw-activity-status-dot", `is-${flow.tone}`)} />
            <span className="font-medium">{flow.status}</span>
          </div>
          <p className="truncate text-muted-foreground">{event.message}</p>
        </div>
        <time dateTime={event.ts} className="whitespace-nowrap text-muted-foreground">{relativeTime(event.ts)}</time>
      </div>
    </div>
  );
}

export function isAgentActivityEvent(event: AuditEvent, state: ConsoleState): boolean {
  const request = event.requestId ? activityLookups(state).requests.get(event.requestId) : undefined;
  return request !== undefined;
}

function FlowNode({ node }: { node: ActivityNode }) {
  return (
    <div className="sgw-activity-node">
      <div className={cn("sgw-activity-node-icon", node.agentName && "is-agent")} aria-hidden="true">
        {node.agentName
          ? <AgentIcon name={node.agentName} className="h-7 w-7" />
          : node.Icon ? <node.Icon className="h-4 w-4" /> : null}
      </div>
      <div className="sgw-activity-node-copy min-w-0 text-center">
        <div className="sgw-activity-node-label truncate text-xs font-semibold">{node.label}</div>
        <div className="sgw-activity-node-detail truncate text-[10px] text-muted-foreground">{node.detail}</div>
      </div>
    </div>
  );
}

function FlowConnector() {
  return (
    <div className="sgw-activity-connector" aria-hidden="true">
      <span />
      <ArrowRight className="h-3 w-3" />
    </div>
  );
}

function describeActivity(event: AuditEvent, state: ConsoleState): ActivityFlow {
  const fullFlow = describeEventFlow(event, state);

  return {
    agent: {
      label: fullFlow.agent.title,
      detail: fullFlow.agent.detail,
      agentName: fullFlow.agent.agentName
    },
    action: {
      label: fullFlow.action.title,
      detail: fullFlow.action.detail,
      Icon: fullFlow.action.Icon
    },
    target: {
      label: fullFlow.target.title,
      detail: fullFlow.target.detail,
      Icon: fullFlow.target.Icon
    },
    status: fullFlow.status,
    tone: fullFlow.tone
  };
}

export function describeEventFlow(event: AuditEvent, state: ConsoleState): ActivityEventFlow {
  const lookups = activityLookups(state);
  const request = event.requestId ? lookups.requests.get(event.requestId) : undefined;
  const handle = event.handle ? lookups.handles.get(event.handle) : undefined;
  const agentName = request?.agentName || "s-gw";
  const status = eventStatus(event.type);
  const tone = eventTone(event.type);
  const action = actionNode(event, request);
  const target = targetNode(event, request, handle);
  const handleName = handle?.name || (event.handle ? shortHandle(event.handle) : "No credential handle");
  const actionKind = request ? titleCase(request.action.kind.replace(/_/g, " ")) : eventStatus(event.type);
  const destination = request ? requestTarget(request) : target.label;
  const sourceDetail = request?.reason || event.message || "Local audit event";
  const ruleName = handle?.name || (event.type.toLowerCase().includes("policy") ? "Policy Engine" : "s-gw audit trail");

  return {
    source: {
      badge: "Source",
      title: request ? `${agentName} request` : "s-gw",
      detail: request ? "Agent request" : "Local system",
      Icon: request ? Route : Monitor,
      tone,
      lines: [
        ["Reason", sourceDetail],
        ["Posture", request?.state ? titleCase(request.state) : "Recorded"],
        ["Connection", request ? actionKind : "Internal"]
      ]
    },
    agent: {
      badge: "Agent",
      title: agentName,
      detail: agentName === "s-gw" ? "Local control" : "Requesting agent",
      agentName,
      tone,
      lines: [
        ["Name", agentName],
        ["Status", request?.state ? titleCase(request.state) : "Recorded"],
        ["Tool called", request ? commandName(request) : "s-gw"]
      ]
    },
    action: {
      badge: request?.action.kind === "ssh_session" ? "SSH" : "Action",
      title: action.label,
      detail: action.detail,
      Icon: action.Icon,
      tone,
      lines: [
        ["Kind", actionKind],
        ["Command", request ? commandName(request) : eventStatus(event.type)],
        ["Credential", handleName]
      ]
    },
    control: {
      badge: "Security Controls",
      title: controlTitle(tone),
      detail: status,
      Icon: ShieldCheck,
      tone,
      lines: [
        ["Event", humanEventType(event.type)],
        ["Action", status],
        ["Reason", event.message || "Recorded by s-gw"]
      ]
    },
    target: {
      badge: "Destination",
      title: target.label,
      detail: target.detail,
      Icon: target.Icon,
      tone,
      lines: [
        ["Target", destination],
        ["Provider", target.detail],
        ["Handle", event.handle ? shortHandle(event.handle) : "None"]
      ]
    },
    status,
    tone,
    eventType: humanEventType(event.type),
    eventId: event.id || event.requestId || compactEventId(event.ts, event.type),
    sourceLabel: agentName,
    destinationLabel: target.label,
    reasonCode: reasonCode(event, request, handle),
    ruleName
  };
}

export function EventFlowDiagram({ flow, compact = false }: { flow: ActivityEventFlow; compact?: boolean }) {
  const cards = [flow.source, flow.agent, flow.action, flow.control, flow.target];

  return (
    <div className={cn("sgw-event-detail-stage", `is-${flow.tone}`, compact && "is-compact")} data-event-flow-detail>
      <div className="sgw-event-detail-flow">
        {cards.map((card, index) => (
          <div className="contents" key={`${card.badge}-${index}`}>
            <EventFlowCardView card={card} />
            {index < cards.length - 1 ? <EventFlowLink tone={flow.tone} /> : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function EventFlowCardView({ card }: { card: EventFlowCard }) {
  return (
    <div className={cn("sgw-event-flow-card", card.tone && `is-${card.tone}`)}>
      <div className="sgw-event-flow-icon" aria-hidden="true">
        {card.agentName
          ? <AgentIcon name={card.agentName} className="h-9 w-9" />
          : card.Icon ? <card.Icon className="h-5 w-5" /> : null}
      </div>
      <div className={cn("sgw-event-flow-badge", card.tone && `is-${card.tone}`)}>{card.badge}</div>
      <div className="sgw-event-flow-title">{card.title}</div>
      <div className="sgw-event-flow-subtitle">{card.detail}</div>
      <div className="sgw-event-flow-lines">
        {card.lines.map(([label, value]) => (
          <div key={label} className="sgw-event-flow-line">
            <span>{label}:</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function EventFlowLink({ tone }: { tone: ActivityTone }) {
  return (
    <div className={cn("sgw-event-flow-link", `is-${tone}`)} aria-hidden="true">
      <span />
    </div>
  );
}

function actionNode(event: AuditEvent, request?: RequestRecord): ActivityNode {
  const type = event.type.toLowerCase();
  if (request?.action.kind === "ssh_session") {
    return { label: "SSH", detail: eventStatus(event.type), Icon: Terminal };
  }

  if (request) {
    return { label: commandName(request), detail: eventStatus(event.type), Icon: Terminal };
  }

  if (type.includes("policy") || type.includes("settings") || type.includes("grant")) {
    return { label: "Policy", detail: eventStatus(event.type), Icon: SlidersHorizontal };
  }
  if (type.includes("secret") || type.includes("credential") || type.includes("handle")) {
    return { label: "Credential", detail: eventStatus(event.type), Icon: KeyRound };
  }
  if (type.includes("approval") || type.includes("approv") || type.includes("denied")) {
    return { label: "Approval", detail: eventStatus(event.type), Icon: ShieldCheck };
  }

  return { label: "Local action", detail: eventStatus(event.type), Icon: Terminal };
}

function targetNode(
  event: AuditEvent,
  request: RequestRecord | undefined,
  handle: ConsoleState["handles"][number] | undefined
): ActivityNode {
  if (request?.action.kind === "ssh_session" && request.action.ssh?.target) {
    const host = request.action.ssh.target.split("@").pop() || request.action.ssh.target;
    const context = activityText(event, request, handle);
    const isEC2 = context.includes("ec2")
      || context.includes("aws")
      || host === "amazonaws.com"
      || host.endsWith(".amazonaws.com");
    return {
      label: host,
      detail: isEC2 ? "Amazon EC2" : "Remote host",
      Icon: isEC2 ? Cloud : Server
    };
  }

  if (request) {
    const command = commandName(request);
    const isAWS = command.toLowerCase() === "aws" || activityText(event, request, handle).includes("aws");
    return {
      label: isAWS ? "AWS" : "This Mac",
      detail: isAWS ? "Cloud service" : "Local execution",
      Icon: isAWS ? Cloud : Monitor
    };
  }

  if (handle) {
    return {
      label: handle.name || shortHandle(handle.handle),
      detail: handle.provider ? titleCase(handle.provider) : titleCase(handle.type),
      Icon: handle.provider === "aws" ? Cloud : KeyRound
    };
  }

  if (event.type.toLowerCase().includes("policy") || event.type.toLowerCase().includes("settings")) {
    return { label: "Policy engine", detail: "s-gw", Icon: ShieldCheck };
  }

  return { label: "This Mac", detail: "Local system", Icon: Monitor };
}

function activityLookups(state: ConsoleState): ActivityLookups {
  const cached = lookupCache.get(state);
  if (cached) return cached;

  const lookups = {
    requests: new Map(state.requests.map((request) => [request.id, request])),
    handles: new Map(state.handles.map((handle) => [handle.handle, handle]))
  };
  lookupCache.set(state, lookups);
  return lookups;
}

function activityText(
  event: AuditEvent,
  request?: RequestRecord,
  handle?: ConsoleState["handles"][number]
): string {
  return [
    event.type,
    event.message,
    event.handle,
    request?.reason,
    request?.action.command,
    request?.action.ssh?.target,
    handle?.provider,
    handle?.name
  ].filter(Boolean).join(" ").toLowerCase();
}

function controlTitle(tone: ActivityTone): string {
  if (tone === "failure") return "Blocked";
  if (tone === "success") return "Allowed";
  if (tone === "pending") return "Review required";
  return "Recorded";
}

function humanEventType(value: string): string {
  return titleCase(value.replace(/\./g, " "));
}

function reasonCode(
  event: AuditEvent,
  request: RequestRecord | undefined,
  handle: ConsoleState["handles"][number] | undefined
): string {
  const lower = event.type.toLowerCase();
  if (lower.includes("deny")) return "Approval denied";
  if (lower.includes("fail") || lower.includes("error")) return "Execution failed";
  if (lower.includes("pending")) return "Approval required";
  if (lower.includes("approv")) return "User approved";
  if (request?.action.kind === "ssh_session") return "SSH credential use";
  if (request) return "Credential command";
  if (handle) return titleCase(handle.type);
  if (lower.includes("policy")) return "Policy change";
  return "Audit event";
}

function compactEventId(ts: string, type: string): string {
  const digits = new Date(ts).getTime();
  if (Number.isFinite(digits)) return String(digits).slice(-8);
  return type.replace(/[^a-z0-9]/gi, "").slice(0, 10) || "event";
}

function eventStatus(type: string): string {
  const last = type.split(".").pop() || type;
  return titleCase(last);
}

function eventTone(type: string): ActivityTone {
  const lower = type.toLowerCase();
  if (lower.includes("fail") || lower.includes("deny") || lower.includes("error")) return "failure";
  if (lower.includes("approv") || lower.includes("execut") || lower.includes("updated") || lower.includes("enabled")) return "success";
  if (lower.includes("pending") || lower.includes("requested") || lower.includes("created")) return "pending";
  return "neutral";
}
