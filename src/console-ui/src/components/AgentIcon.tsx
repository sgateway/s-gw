import antigravityIcon from "@/assets/agents/antigravity.png";
import claudeIcon from "@/assets/agents/claude.svg";
import codexIcon from "@/assets/agents/codex.png";
import cursorIcon from "@/assets/agents/cursor.png";
import geminiIcon from "@/assets/agents/gemini.svg";
import githubCopilotIcon from "@/assets/agents/github-copilot.svg";
import hermesIcon from "@/assets/agents/hermes.png";
import omnigentIcon from "@/assets/agents/omnigent.png";
import openclawIcon from "@/assets/agents/openclaw.png";
import opencodeIcon from "@/assets/agents/opencode.png";
import openhandsIcon from "@/assets/agents/openhands.svg";
import vscodeIcon from "@/assets/agents/vscode.png";
import windsurfIcon from "@/assets/agents/windsurf.svg";
import zeptoclawIcon from "@/assets/agents/zeptoclaw.png";
import sgwIcon from "@/assets/s-gw-64.png";
import { cn } from "@/lib/utils";

interface AgentIconProps {
  name?: string;
  className?: string;
}

interface AgentArtwork {
  src: string;
  kind: "app" | "mark";
}

const agentArtwork: Array<{ names: string[]; artwork: AgentArtwork }> = [
  { names: ["s gw", "sgw", "secret gateway"], artwork: { src: sgwIcon, kind: "app" } },
  { names: ["openclaw", "open claw"], artwork: { src: openclawIcon, kind: "app" } },
  { names: ["zeptoclaw", "zepto claw"], artwork: { src: zeptoclawIcon, kind: "app" } },
  { names: ["hermes agent", "hermes"], artwork: { src: hermesIcon, kind: "app" } },
  { names: ["openhands", "open hands"], artwork: { src: openhandsIcon, kind: "app" } },
  { names: ["antigravity", "google antigravity"], artwork: { src: antigravityIcon, kind: "app" } },
  { names: ["omnigent", "omni gent"], artwork: { src: omnigentIcon, kind: "app" } },
  { names: ["codex", "openai codex"], artwork: { src: codexIcon, kind: "app" } },
  { names: ["cursor"], artwork: { src: cursorIcon, kind: "app" } },
  { names: ["opencode", "open code"], artwork: { src: opencodeIcon, kind: "app" } },
  { names: ["vscode", "vs code", "visual studio code"], artwork: { src: vscodeIcon, kind: "app" } },
  { names: ["claude", "claude code", "anthropic"], artwork: { src: claudeIcon, kind: "mark" } },
  { names: ["gemini", "gemini cli", "google gemini"], artwork: { src: geminiIcon, kind: "mark" } },
  { names: ["github copilot", "github copilot cli", "copilot", "copilot cli"], artwork: { src: githubCopilotIcon, kind: "mark" } },
  { names: ["windsurf", "codeium windsurf"], artwork: { src: windsurfIcon, kind: "mark" } }
];

export function AgentIcon({ name, className }: AgentIconProps) {
  const label = name?.trim() || "Agent";
  const artwork = findArtwork(label);

  if (!artwork) {
    return (
      <span
        aria-hidden="true"
        className={cn("sgw-agent-icon sgw-agent-icon-fallback h-7 w-7", className)}
        data-agent-icon={normalizeName(label)}
      >
        {agentMonogram(label)}
      </span>
    );
  }

  if (artwork.kind === "mark") {
    return (
      <span
        aria-hidden="true"
        className={cn("sgw-agent-icon h-7 w-7", className)}
        data-agent-icon={normalizeName(label)}
        data-agent-icon-kind="mark"
      >
        <img className="sgw-agent-icon-mark-image" src={artwork.src} alt="" />
      </span>
    );
  }

  return (
    <span
      aria-hidden="true"
      className={cn("sgw-agent-icon h-7 w-7", className)}
      data-agent-icon={normalizeName(label)}
      data-agent-icon-kind="app"
    >
      <img src={artwork.src} alt="" />
    </span>
  );
}

function findArtwork(name: string): AgentArtwork | undefined {
  const normalized = normalizeName(name);
  for (const item of agentArtwork) {
    if (item.names.some((candidate) => normalized === candidate || normalized.includes(candidate))) {
      return item.artwork;
    }
  }
  return undefined;
}

function normalizeName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function agentMonogram(name: string): string {
  const parts = normalizeName(name).split(" ").filter(Boolean);
  if (parts.length === 0) return "A";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}
