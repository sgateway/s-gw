import {
  ArrowRight,
  Boxes,
  Cloud,
  Database,
  GitBranch,
  Globe,
  HardDrive,
  KeyRound,
  Monitor,
  Server,
  Terminal
} from "lucide-react";
import type { ReactNode } from "react";

import { AgentIcon } from "@/components/AgentIcon";
import { Badge } from "@/components/ui/badge";
import { relativeTime, titleCase } from "@/lib/format";
import type { UsageFlowEntry } from "@/lib/types";

export function UsageFlowDetailRow({ entry }: { entry: UsageFlowEntry }) {
  const AuthIcon = entry.authType.toLowerCase().includes("ssh") ? Terminal : KeyRound;
  const TargetIcon = targetIcon(entry.targetType);

  return (
    <div className="sgw-usage-detail-row" data-flow-entry data-request-id={entry.requestId}>
      <div className="sgw-usage-detail-path" aria-label={`${entry.agent} ${entry.authType} ${entry.target}`}>
        <FlowNode
          icon={<AgentIcon name={entry.agent} className="h-7 w-7" />}
          label={entry.agent}
          detail="Agent"
          plainIcon
        />
        <FlowConnector />
        <FlowNode icon={<AuthIcon className="h-4 w-4" />} label={entry.authType} detail={entry.credential} />
        <FlowConnector />
        <FlowNode icon={<TargetIcon className="h-4 w-4" />} label={entry.target} detail={entry.targetType} />
      </div>
      <div className="sgw-usage-detail-meta">
        <Badge variant={entry.state === "failed" || entry.state === "denied" ? "destructive" : "outline"}>
          {titleCase(entry.state)}
        </Badge>
        <time dateTime={entry.lastSeen}>{relativeTime(entry.lastSeen)}</time>
      </div>
    </div>
  );
}

function FlowNode({
  icon,
  label,
  detail,
  plainIcon = false
}: {
  icon: ReactNode;
  label: string;
  detail: string;
  plainIcon?: boolean;
}) {
  return (
    <div className="sgw-usage-detail-node">
      <div className={plainIcon ? "sgw-usage-detail-icon is-agent" : "sgw-usage-detail-icon"} aria-hidden="true">
        {icon}
      </div>
      <div className="min-w-0">
        <div className="truncate text-xs font-semibold">{label}</div>
        <div className="truncate text-[10px] text-muted-foreground">{detail}</div>
      </div>
    </div>
  );
}

function FlowConnector() {
  return (
    <div className="sgw-usage-detail-connector" aria-hidden="true">
      <span />
      <ArrowRight className="h-3 w-3" />
    </div>
  );
}

function targetIcon(targetType: string) {
  const value = targetType.toLowerCase();
  if (value.includes("ssh")) return Server;
  if (value.includes("aws")) return Cloud;
  if (value.includes("github")) return GitBranch;
  if (value.includes("kubernetes") || value.includes("container")) return Boxes;
  if (value.includes("database")) return Database;
  if (value.includes("nas")) return HardDrive;
  if (value.includes("web")) return Globe;
  if (value.includes("local")) return Monitor;
  return Server;
}
