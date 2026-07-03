# Security Policy

s-gw handles credential material and approval decisions. Please report suspected security problems privately so they can be investigated before public disclosure.

## Supported Versions

Until the first stable release, security fixes are made on the latest published preview and the current `main` branch. Older source snapshots are not supported.

## Reporting A Vulnerability

Use GitHub's **Report a vulnerability** action in the repository Security tab. This creates a private security advisory visible only to the reporter and maintainers.

Include, when possible:

- the affected version or commit;
- operating system and credential backend;
- the agent or MCP client involved;
- steps to reproduce with disposable credentials;
- expected and observed behavior;
- potential impact and any suggested mitigation.

Do not include real credentials, unlock material, customer data, or public proof-of-concept exploits. Do not open a public issue for suspected credential disclosure, approval bypass, command-policy bypass, output-sanitization failure, or local API authorization failure.

We aim to acknowledge complete reports within five business days. Validation and release timing depend on severity and reproducibility. Credit is offered in the advisory unless the reporter prefers to remain anonymous.

## Scope

Security-sensitive areas include:

- credential storage and retrieval;
- ledger encryption and unlock handling;
- approval and reusable-grant scope;
- command and SSH destination enforcement;
- MCP and local console authorization;
- output sanitization and audit integrity;
- native helper and installer behavior.

Read the [threat model](docs/threat-model.md) for intended guarantees, trust boundaries, and explicit non-goals.
