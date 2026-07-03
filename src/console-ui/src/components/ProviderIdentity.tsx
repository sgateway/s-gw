import { Cloud, GitBranch, KeyRound, Sparkles, Terminal } from "lucide-react";

import onePasswordIcon from "@/assets/providers/1password.svg";
import sgwIcon from "@/assets/s-gw-64.png";
import { credentialProviderPresentation } from "@/lib/credential-presentation";

export function ProviderIdentity({ provider, backend }: { provider?: string; backend?: string }) {
  const presentation = credentialProviderPresentation(provider, backend);
  const Icon = providerIcon(presentation.kind);

  return (
    <span className="sgw-provider-identity" data-provider={presentation.kind}>
      <span className="sgw-provider-logo" aria-hidden="true">
        {presentation.kind === "onepassword" ? <img src={onePasswordIcon} alt="" /> : null}
        {presentation.kind === "sgw" ? <img src={sgwIcon} alt="" /> : null}
        {Icon ? <Icon className="h-4 w-4" /> : null}
      </span>
      <span>{presentation.label}</span>
    </span>
  );
}

function providerIcon(kind: ReturnType<typeof credentialProviderPresentation>["kind"]) {
  if (kind === "aws") return Cloud;
  if (kind === "github") return GitBranch;
  if (kind === "ssh") return Terminal;
  if (kind === "openai") return Sparkles;
  if (kind === "generic") return KeyRound;
  return null;
}
