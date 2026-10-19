# OS identity for confined agents

## Status and trust boundary

This is the target design for agent-scoped authorization. The current Anthropic launcher uses a loopback TCP bridge with a capability visible to the agent. That capability authenticates the bridge to the broker, but it does not identify the agent to the operating system. An MCP client name, environment variable, request reason, PID supplied by the client, or readable token must not become a managed principal.

The broker is an s-gw process outside the agent's confinement. It owns the credential store, approval policy, audit record, and authenticated HTTPS/SSH executors. A trusted launcher starts each agent inside a separate OS security identity, registers that identity with the broker, and controls its lifetime. The broker accepts requests over local IPC, asks the kernel who connected, and maps that identity to exactly one active launcher record. The agent can choose a display name, but policy and reusable grants use the broker's principal and session IDs. A broker process running under the same unrestricted account as an unconfined agent does not provide this boundary.

## Common protocol

1. The trusted operator starts an agent through s-gw. The launcher creates a unique security identity for each concurrent session, a scoped workspace, and a session record. The session ID is not an authentication secret.
2. The launcher drops the agent's privileges and passes only the IPC location and nonsecret configuration. Broker credentials, policy files, private SSH material, and approval authority never enter the agent's filesystem or environment.
3. On each IPC connection the broker obtains the kernel's peer identity. It rejects an unknown identity, one mapped to a different live session, or a connection after the launcher reports the session stopped. It does not accept identity fields in request JSON.
4. The broker binds each request, approval, policy match, reusable permit, and execution recheck to the verified principal and session. It revokes outstanding permits and closes in-flight channels when the session ends.
5. The broker performs approved HTTPS/SSH actions itself. Agent network policy prevents direct access to credential-backed service destinations. A separate model transport is required if a native agent must make authenticated model requests without holding its model credential.

## macOS

Install a signed, narrow LaunchDaemon/helper through ServiceManagement. Provision a pool of dedicated unprivileged local accounts during installation, then assign one account to each concurrent session; recycling an account requires closing its old sockets and revoking its grants first. The helper only accepts a vetted launch plan from the operator's s-gw process, prepares a session workspace, drops supplementary groups and UID/GID, and starts the agent. It must not become a general command runner. The s-gw broker can remain a LaunchAgent in the operator's login session so it can use the operator's authorized Keychain context. Its store stays readable only by that account.

For each concurrent session, use a distinct agent UID. Grant that UID access only to the selected workspace and its broker Unix socket; deny the operator home, Keychain, other session directories, and direct network egress. Seatbelt restrictions add filesystem, IPC, and network limits. On the accepted socket the broker calls `getpeereid`, maps the returned effective UID to its live launcher record, and rejects anything else. XPC audit tokens and code-signing requirements can add checks for the packaged helper, but signing identifies an executable, not arbitrary agent code running inside it. A plain Seatbelt sandbox under the operator's UID is not a distinct principal.

This needs a privileged installation and an agent compatibility test. Existing editor processes cannot be retroactively moved to a different UID. Access to files under the operator's home must be granted deliberately, and native agent login will need a broker-owned model transport or another supported sign-in path.

## Linux

Run each concurrent agent in a system-managed unit with a distinct UID, for example a systemd system service with `DynamicUser=` or a provisioned account. A system-managed transient unit can set `PrivateNetwork=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`, and restricted namespaces. Bind only the approved workspace, required runtime files, and a session-specific filesystem Unix socket into its private mount namespace. The private network namespace has loopback for an agent-local forwarder but no direct service egress. The broker stays in the host/user service outside that unit and keeps the store private.

For an accepted Unix socket the broker reads `SO_PEERCRED` (PID, UID, GID), checks the UID and the launcher's active unit/cgroup record, and binds it to a session. Keep each connection tied to the active unit and close it before the UID can be recycled; a dynamic UID alone must never authorize a durable grant. Do not rely on a user namespace that maps the agent back to the operator's host UID as the sole identity boundary.

If a native model client only speaks HTTP, an agent-local forwarder can connect to the broker over the authenticated Unix socket. Its TCP listener must be isolated inside that session's network namespace. The broker makes upstream TLS connections and authorizes requests based on the forwarder's verified Unix peer, not a token sent over HTTP.

## Windows

Prefer a distinct AppContainer SID for each concurrent agent session. Create a session profile with `CreateAppContainerProfile` and launch the agent using `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`; test a less-privileged AppContainer where the CLI supports it. Use a Job Object to terminate the process tree, explicit filesystem ACLs, and Windows Filtering Platform rules tied to the SID. The Job Object controls lifetime but is not the authorization identity. The broker runs at normal full trust outside the AppContainer and keeps its store and credential access under the operator account. If a CLI cannot run correctly in AppContainer, use a dedicated local account for the session with equivalent ACL and network restrictions; this requires a privileged setup path.

Expose a local named pipe with an explicit security descriptor granting only the intended agent SID and broker identity; use `PIPE_REJECT_REMOTE_CLIENTS` and the `LOCAL\\` pipe namespace where required. After reading a request, the server calls `ImpersonateNamedPipeClient`, opens the client token, inspects its account or AppContainer SID, and matches it to an active launcher record. It checks impersonation success before processing and always calls `RevertToSelf`. `GetNamedPipeClientProcessId` is useful for diagnostics but is not the authorization identity. Do not use the default named-pipe ACL, which grants broader read access.

An agent-local HTTP forwarder may be needed for stock model clients; it must use the named pipe for broker requests, with its listener reachable only inside the agent boundary. Windows named-pipe/AppContainer support and CLI compatibility need native Windows acceptance testing.

## Acceptance and rollout

Use synthetic credentials and two concurrent agents with different OS identities. Prove that each can request its own approved action, cannot claim the other's principal by changing MCP names/environment/request fields, cannot connect as the other identity, cannot read the broker store or the other's private files, and cannot reach protected services directly. Kill a session during a reusable action and prove revocation. Test real native model sessions and owned HTTPS/SSH under the same profile on macOS, Linux, and Windows before enabling it by default.

Ordinary MCP name-based approvals and the current same-user Anthropic launcher remain compatibility paths until a separate, explicit migration is approved. A partial peer-credential helper added to the current same-UID launcher would not establish managed-agent identity.

## Platform references

- Apple: [ServiceManagement `SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice), [`getpeereid`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getpeereid.3.html), and [XPC peer requirements](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement).
- Linux: [`unix(7)` peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html) and [systemd execution isolation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
- Microsoft: [`CreateAppContainerProfile`](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile), [AppContainer process launch](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute), [named-pipe client impersonation](https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client), [named-pipe access control](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), and [`PIPE_REJECT_REMOTE_CLIENTS`](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew).
