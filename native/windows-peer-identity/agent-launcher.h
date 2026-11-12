#ifndef SGW_WINDOWS_AGENT_LAUNCHER_H
#define SGW_WINDOWS_AGENT_LAUNCHER_H

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>

typedef struct {
    wchar_t executable_name[MAX_PATH];
    wchar_t arguments[4096];
} SGW_WINDOWS_AGENT_COMMAND;

typedef struct {
    wchar_t session_id[33];
    wchar_t profile_name[48];
    wchar_t profile_path[MAX_PATH];
    wchar_t broker_sid[184];
    wchar_t user_sid[184];
    wchar_t package_sid[184];
    wchar_t job_name[64];
    wchar_t logon_luid[17];
    DWORD windows_session_id;
    DWORD process_id;
} SGW_WINDOWS_AGENT_IDENTITY;

typedef struct {
    DWORD (*prepare)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity,
        SGW_WINDOWS_AGENT_COMMAND *command);
    DWORD (*register_session)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity);
    // In-process and nonblocking: synchronously deny new broker work and abort active requests.
    // Do not wait for helpers or the child here.
    DWORD (*begin_revoke)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity);
    // Confirm that helpers and broker callbacks have settled before WFP is released.
    DWORD (*revoke_session)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity);
} SGW_WINDOWS_AGENT_HOOKS;

typedef struct SGW_WINDOWS_AGENT_BOUNDARY SGW_WINDOWS_AGENT_BOUNDARY;

typedef struct {
    // Called only by the broker while the child is suspended. The boundary pointer
    // stays valid until revoke_session has confirmed callback drain.
    DWORD (*register_session)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity,
        const SGW_WINDOWS_AGENT_BOUNDARY *boundary);
    // The broker must verify DNS isolation from host policy, not an agent report.
    BOOL (*dns_boundary_ready)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity);
} SGW_WINDOWS_AGENT_BOUNDARY_HOOKS;

// This reads the launcher's retained child, Job and WFP handles, then calls the
// broker's synchronous DNS guard. An identity, PID or Job name alone is not proof.
BOOL sgw_windows_agent_boundary_healthy(const SGW_WINDOWS_AGENT_BOUNDARY *boundary);

// Returns zero unless the retained child handle still names a live process in
// an active launch. The callback's recorded process_id is not used here.
DWORD sgw_windows_agent_boundary_child_pid(const SGW_WINDOWS_AGENT_BOUNDARY *boundary);

// Source-only opt-in handoff for an in-process broker bridge. The boundary may
// be probed during registration and while the session runs, but not after drain.
DWORD sgw_windows_agent_run_bound(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    const SGW_WINDOWS_AGENT_BOUNDARY_HOOKS *boundary_hooks, void *context,
    DWORD *child_exit_code);

// The caller must be the broker. It owns stop_event and must keep its registration
// callback live until this function returns. No agent-controlled IPC calls this API.
DWORD sgw_windows_agent_run(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    void *context, DWORD *child_exit_code);

#endif
