# Agent identity and launcher evidence

## Three levels

| Level | How the agent is identified | Platforms | What it is good for |
| --- | --- | --- | --- |
| Declared name | The name set by the s-gw integration (`SGW_AGENT_NAME`), the MCP client name, or a detected runtime or process | macOS, Linux, Windows | Reusable grants and name-based allow policies, as in 0.1.22. Identifies the agent; does not prove it |
| Pinned launcher signature | The code signature of the application that launched the s-gw MCP server, pinned by the operator | macOS | Grants and policies bound to a real application instead of a string |
| Verified peer | A kernel-verified OS identity from a managed launcher | Where a managed launcher is installed | The paths that need real isolation, such as model relay |

A name taken only from the free-form reason on a request never gets a grant or a policy.

Whatever the level, an approved request can be executed by the agent session that created it, by the operator, or by a matching verified peer. Another MCP client that learns the request ID cannot execute it.

## Launcher evidence on every platform

Each request records which applications launched the requesting MCP server, nearest first:

- macOS: team-signed code signatures (`codesign:<TEAM ID>:<identifier>`);
- Windows: the Authenticode publisher when the signature is valid, otherwise the executable path;
- Linux: the executable path of each ancestor.

This is evidence for the operator and is never enforced on its own. When a known agent name arrives from a different launcher than before, s-gw writes an `agent.launcher.changed` audit event and carries on.

## Pinning a signature (macOS)

On macOS, an operator can pin the code signature of the application that launches the s-gw MCP server. Requests from a process whose ancestry carries a pinned signature are treated as a verified agent for three things:

- reusable grants, bound to that signature and to the launching process (they end when that process exits);
- allow policies that name the signature's principal ID;
- executing a request that was approved for that same signature and launching process.

Model relay and the other paths that need a kernel-verified peer still require one.

## How it works

When the MCP server starts, it walks up to eight ancestors of its own process. For each one it asks `/usr/bin/codesign` to validate the running code, then reads the signing identifier and team identifier. An ancestor is recorded only when validation passes and a team identifier is present. Each request stores that list so an operator can see which signed applications were involved.

The first ancestor that matches a pinned signature names the agent. The principal ID is `codesign:<TEAM ID>:<identifier>`, and the session is that ancestor's process ID plus start time.

## Commands

```bash
# Which signed applications launched this shell, nearest first
s-gw agent trust current

# Pin the signature recorded on a request you have reviewed
s-gw agent trust add --name "Claude Code" --request REQUEST_ID

# Or pin it explicitly
s-gw agent trust add --name "Claude Code" --team-id Q6L2SF6YDW --identifier com.anthropic.claude-code

# Also bind existing allow policies that name this agent to the signature
s-gw agent trust add --name "Claude Code" --request REQUEST_ID --bind-policies

s-gw agent trust list
s-gw agent trust remove --id LAUNCHER_ID
```

Removing a signature also removes the reusable grants issued to it.

General-purpose runtimes such as `node`, `python`, `bun`, `deno` and shells cannot be pinned, because every script they run would share the identity.

The trust list is part of the sealed authorization state, which s-gw seals and reseals on its own.

## What it does not do

This identifies the launching application. It is not an isolation boundary and must not be described as verified OS identity.

- A process running as the same user can start the s-gw MCP server and then replace itself with a signed agent binary. The server's parent then carries the signature while the original process still holds the MCP pipes.
- A signed Electron application that can be run as plain Node gives its signature to any script.
- The check runs inside the s-gw MCP server, which the agent's own user launches and could replace.
- Anything the signed application itself runs, including a shell command it was talked into, inherits its identity. That is correct attribution, not containment.

The tier stops casual impersonation by name, environment variable or process name, and it lets policies follow a real application instead of a string. Separating the broker from the agent's OS user, described in [OS identity for confined agents](agent-os-identity.md), is what provides isolation.

Set `SGW_DISABLE_LAUNCHER_ATTESTATION=1` to turn launcher checks and evidence off. Pinning is macOS-only in this release; Linux and Windows record launcher evidence but have nothing to pin.
