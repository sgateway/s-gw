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
    DWORD (*revoke_session)(void *context, const SGW_WINDOWS_AGENT_IDENTITY *identity);
} SGW_WINDOWS_AGENT_HOOKS;

// The caller must be the broker. It owns stop_event and must keep its registration
// callback live until this function returns. No agent-controlled IPC calls this API.
DWORD sgw_windows_agent_run(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    void *context, DWORD *child_exit_code);

#endif
