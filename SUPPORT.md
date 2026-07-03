# Support

Use the repository issue tracker for reproducible bugs and focused feature requests. Include the s-gw version, operating system, credential backend, agent, and sanitized steps to reproduce.

Before opening an issue:

```bash
s-gw status
s-gw doctor
npm run check
```

Remove credential values, local paths, account names, request IDs, SSH destinations, and approval history from logs or screenshots.

Suspected vulnerabilities must use the private process in [SECURITY.md](SECURITY.md). Public issues containing secrets or exploit details may be removed to protect users.
