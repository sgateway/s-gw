---
name: s-gw
description: Use s-gw when working with credentials, private keys, API tokens, SSH identities, browser credentials, or other sensitive data in agentic coding workflows. Prefer typed handles and local approved execution over exposing raw secret values to a model.
---

# s-gw

Use s-gw to keep raw credentials local while still letting an agent plan and request useful credential-backed actions.

Core rules:

- Never ask the user to paste a raw secret into the chat.
- Use `sgw_scan_file` to inspect local files and return typed handles instead of secret values.
- Use `sgw_list_handles` and `sgw_describe_handle` when the agent needs to reason about available secrets.
- Use `sgw_request_execution` to create a bounded operation manifest. The user must approve the request locally before execution.
- Use `sgw_execute_request` only after approval. Returned output is sanitized and should be treated as the only model-visible result.
- If a secret-backed action is too broad, ask for a narrower operation instead of requesting blanket access.

s-gw is local-first. The MCP server runs on the user's machine over stdio. Raw secrets should remain in the local encrypted ledger or local OS/vault-backed stores.
