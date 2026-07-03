# Secret Detection

s-gw identifies credentials locally before any tokenized text is sent to an AI coding agent.

## Current Approach

Detection is deterministic by default. The scanner uses a provider-aware rule pack with regular expressions, light validators, placeholder filtering, severity, and confidence metadata.

Current provider coverage includes:

- OpenAI and Anthropic API keys
- AWS access keys and secret access key assignments
- GitHub and GitLab tokens
- Slack and Discord webhooks/tokens
- Stripe keys
- Google API keys
- Azure storage keys and SAS signatures
- SendGrid, Mailgun, Twilio, npm, and PyPI tokens
- JWTs with local header/payload validation
- database connection-string credentials
- Basic and Bearer auth headers
- generic secret, token, API key, and password assignments
- PEM private key blocks

When a value is detected, only the matched sensitive value is replaced with a `<<SGW_SECRET:...>>` handle token. Non-secret context around it remains visible so the agent can still reason about code structure.

## Why Not Remote AI Detection

Raw secrets should not leave the user's machine. A remote model is not part of the detection path.

A future local small language model can be useful for ambiguous cases, such as classifying a strange variable assignment or helping name a handle. It should not be the primary detector and should not receive raw values unless it runs fully local under the same trust boundary.

## Metadata

Findings and persisted handles can carry non-secret metadata:

- `provider`
- `ruleId`
- `severity`
- `confidence`
- `type`
- source file or source label

This metadata is safe to show in a future management UI and helps users review high-risk items without exposing credential values.
