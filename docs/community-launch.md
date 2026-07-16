# Community Launch Notes

Use this when sharing s-gw with developer communities. Keep the tone practical: show the credential problem, show the local trust loop, and avoid broad enterprise security claims while the project is in preview.

## Core Message

s-gw is local credential control for AI coding agents. Agents get typed handles and scoped action requests. The user approves the action locally, s-gw injects the credential into one constrained child process, and command output is sanitized before the agent sees it.

## Suggested Repository Topics

Use focused GitHub topics that match how developers search:

```text
ai-agents
agent-security
coding-agents
credential-security
credentials
local-first
mcp
model-context-protocol
secrets
security-tools
typescript
rust
macos
windows
onepassword
```

## Hacker News Draft

Title:

```text
Show HN: s-gw, local credential control for AI coding agents
```

Body:

```text
I built s-gw because coding agents increasingly need to run real commands that touch API tokens, SSH keys, cloud credentials, and local MCP tools.

The idea is simple: the agent sees typed handles, not raw secrets. When it needs to do something, it creates a scoped local action request. You approve the command, handle, env binding, working directory, and target on your machine. s-gw injects the credential only into that child process, then sanitizes output before returning it to the agent.

It is a preview, not a hardened enterprise secrets platform. macOS is the primary path today, Windows is preview, and Linux is experimental. The broker and clients are open source; distributed packages include a proprietary compiled Rust execution core.

Repo: https://github.com/sgateway/s-gw
Demo: https://s-gw.com
```

## Reddit Draft

Use a subreddit-specific title, then keep the body short.

```text
I’m building s-gw, a local credential gateway for AI coding agents.

Problem: agents need useful access to credentials for real workflows, but pasting raw tokens into prompts, shell output, MCP configs, or tool logs is a bad default.

s-gw lets the agent work with handles, asks for local approval before an action runs, injects the secret only into that approved process, and sanitizes output before the model sees it.

It is early preview software, so I’m looking for feedback from people using Codex, Claude Code, Cursor, OpenCode, MCP tools, SSH keys, API tokens, or 1Password in agent workflows.

Repo: https://github.com/sgateway/s-gw
Demo: https://s-gw.com
```

## Dev.to Outline

```text
Title: Stop giving coding agents raw credentials

1. Why this problem is showing up now
2. Why vaults alone do not solve agent execution
3. Handles instead of secrets
4. Local approval and bounded execution
5. Output sanitization and audit history
6. Current preview limitations
7. How to try s-gw
```

## Good First Issue Seeds

These are intentionally small and safe for new contributors:

- Improve the quickstart copy for Windows preview users.
- Add a docs screenshot showing the approval queue state.
- Add a regression test for one agent profile alias.
- Add a CLI example for `s-gw approval grants`.
- Audit docs for stale `barryqy/s-gw` links after the repository move.
