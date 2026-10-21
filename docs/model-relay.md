# Broker-owned model relay

## Status

The streaming transport in `src/model-relay-transport.ts` is an opt-in foundation. It has no listening socket or CLI flag. No native agent is routed through it yet. The trusted caller must supply an approved s-gw API-token handle's value and an authorization callback. An agent cannot invoke it through the current MCP bridge. The current same-UID Anthropic launcher does not provide the verified peer identity needed for a live relay.

The relay has fixed upstreams: `api.anthropic.com` for Anthropic Messages and `api.openai.com` for OpenAI Responses. It never accepts an upstream URL from an agent, does not implement `CONNECT`, and does not intercept TLS. It drops the client's `Authorization`, `x-api-key`, cookies, proxy authorization, and routing/account headers; the broker writes its own bearer credential. Anthropic beta/version headers and the JSON body pass through. An operator-owned workspace, project, or organization ID may be supplied by the trusted caller.

Allowed requests are `POST /v1/messages` (including Claude Code's `?beta=true`), `POST /v1/messages/count_tokens`, `GET /v1/models` (optional model discovery), and `POST /v1/responses`. Redirects, compressed responses, unsupported methods and queries, untrusted TLS, and private DNS results fail closed. Responses stream with backpressure and bounded memory. The transport rechecks authorization during the stream and withholds exact echoes of the broker credential, including split-chunk, URL-encoded, JSON-escaped, and base64 forms. A response that echoes a different secret is still native model output and is outside this transport's credential guarantee.

Each request body may be up to 32 MiB. Across active uploads, the transport retains at most 64 MiB of request chunks; it returns 503 when that budget is full and releases a reservation after the upstream write finishes or the request ends. Concatenation and TLS writes can briefly use more memory, so this is a request-buffer budget rather than a process-memory ceiling. A live listener still needs its own connection and stream limits.

## Live attachment required

1. Add a first-class model-relay approval action scoped to a verified principal, session, provider, fixed route set, API-token handle, optional operator-owned account/workspace ID, and a finite lifetime. Do not treat a copied request ID, process name, bearer, or the current same-UID MCP capability as a principal.
2. The broker claims the approved action, checks the handle's provider/destination policy, resolves the handle inside the broker, and supplies the credential to the transport in memory. A subprocess with the key in an environment variable is unsafe until agent and broker use distinct OS identities.
3. Expose an agent-local HTTP forwarder only inside that agent's network boundary. It connects to s-gw over a broker-owned Unix socket or named pipe. s-gw obtains kernel peer credentials on every connection and maps them to the live session before passing a request to the transport. The relay listener must not share the operator console's listener or credentials.
4. Cap concurrent streams per principal, set short HTTP header and request-body idle deadlines, and close the upstream on client disconnect, policy revocation, grant expiry, or session death. Record route/status/byte counts without logging prompts or credentials. Test two agents simultaneously, including an attempted cross-session connection.
5. Validate a real Claude Code and Codex turn with tools, retry, token counting, model discovery where enabled, and SSE cancellation. The API-funded gateway is a separate auth and billing path from saved claude.ai or ChatGPT sign-in. Preserve existing sign-in and direct network defaults until an explicit migration is approved.

Claude Code's [gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol) documents the Messages routes, version and beta headers, response headers, and streaming behavior. The [Claude Platform API overview](https://platform.claude.com/docs/en/api/overview) and [OpenAI Responses reference](https://developers.openai.com/api/reference/resources/responses/methods/create) document the fixed upstream APIs. The OS peer boundary is described in [agent-os-identity.md](agent-os-identity.md).

## Current verification

`npx vitest run tests/model-relay-transport.test.ts` uses a synthetic HTTPS provider behind a test-only transport seam. It proves incremental SSE delivery, exact upstream routing, client credential stripping, broker credential substitution, split credential redaction, optional Anthropic routes, OpenAI Responses routing, redirect refusal, authorization refusal, TLS trust failure, and the concurrent request-buffer limit with a full 32 MiB request. It is not native-agent or OS-identity end-to-end evidence.
