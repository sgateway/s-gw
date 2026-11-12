#include "agent-launcher.h"
#include "wfp-boundary.h"
#include <objbase.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <userenv.h>
#include <wchar.h>

static size_t bounded_length(const wchar_t *text, size_t limit) {
    size_t length = 0;
    while (length < limit && text[length]) length++;
    return length;
}

static void *token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD bytes = 0;
    GetTokenInformation(token, kind, NULL, 0, &bytes);
    if (!bytes || bytes > 4096) return NULL;
    void *result = LocalAlloc(LMEM_FIXED, bytes);
    if (!result) return NULL;
    if (GetTokenInformation(token, kind, result, bytes, &bytes)) return result;
    LocalFree(result);
    return NULL;
}

static DWORD make_session_id(wchar_t out[33]) {
    GUID id;
    if (CoCreateGuid(&id) != S_OK) return ERROR_GEN_FAILURE;
    int size = swprintf(out, 33, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
        (unsigned long)id.Data1, (unsigned)id.Data2, (unsigned)id.Data3,
        (unsigned)id.Data4[0], (unsigned)id.Data4[1], (unsigned)id.Data4[2],
        (unsigned)id.Data4[3], (unsigned)id.Data4[4], (unsigned)id.Data4[5],
        (unsigned)id.Data4[6], (unsigned)id.Data4[7]);
    return size == 32 ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

static DWORD broker_identity(SGW_WINDOWS_AGENT_IDENTITY *identity, PSID *user_sid) {
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    DWORD is_appcontainer = 1, bytes = 0;
    LPWSTR sid_text = NULL;
    DWORD result = ERROR_INVALID_DATA;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
    user = token_info(token, TokenUser);
    if (!user || !GetTokenInformation(token, TokenIsAppContainer,
        &is_appcontainer, sizeof(is_appcontainer), &bytes) || is_appcontainer ||
        !ConvertSidToStringSidW(user->User.Sid, &sid_text)) goto done;
    size_t length = wcslen(sid_text);
    if (length >= sizeof(identity->broker_sid) / sizeof(wchar_t)) goto done;
    wmemcpy(identity->broker_sid, sid_text, length + 1);
    wmemcpy(identity->user_sid, sid_text, length + 1);
    *user_sid = LocalAlloc(LMEM_FIXED, GetLengthSid(user->User.Sid));
    if (!*user_sid) { result = ERROR_OUTOFMEMORY; goto done; }
    if (!CopySid(GetLengthSid(user->User.Sid), *user_sid, user->User.Sid)) {
        result = GetLastError();
        LocalFree(*user_sid);
        *user_sid = NULL;
        goto done;
    }
    result = ERROR_SUCCESS;
done:
    if (sid_text) LocalFree(sid_text);
    if (user) LocalFree(user);
    CloseHandle(token);
    return result;
}

static DWORD create_private_job(const SGW_WINDOWS_AGENT_IDENTITY *identity, HANDLE *job) {
    wchar_t sddl[512];
    int size = swprintf(sddl, sizeof(sddl) / sizeof(wchar_t),
        L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)(A;;RC;;;OW)", identity->broker_sid);
    if (size < 1 || (size_t)size >= sizeof(sddl) / sizeof(wchar_t)) return ERROR_INVALID_DATA;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
        &descriptor, NULL)) return GetLastError();
    SECURITY_ATTRIBUTES security = { sizeof(security), descriptor, FALSE };
    *job = CreateJobObjectW(&security, identity->job_name);
    DWORD result = GetLastError();
    LocalFree(descriptor);
    if (!*job) return result;
    if (result == ERROR_ALREADY_EXISTS) {
        CloseHandle(*job);
        *job = NULL;
        return ERROR_ALREADY_EXISTS;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(*job, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits))) return GetLastError();
    return ERROR_SUCCESS;
}

static BOOL job_is_confined(HANDLE job, HANDLE process) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    BOOL member = FALSE;
    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
        &limits, sizeof(limits), NULL) ||
        !IsProcessInJob(process, job, &member)) return FALSE;
    DWORD flags = limits.BasicLimitInformation.LimitFlags;
    return member && (flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) &&
        !(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK));
}

struct SGW_WINDOWS_AGENT_BOUNDARY {
    HANDLE child;
    HANDLE job;
    HANDLE stop_event;
    const SGW_WFP_BOUNDARY *wfp;
    const SGW_WINDOWS_AGENT_IDENTITY *identity;
    const SGW_WINDOWS_AGENT_BOUNDARY_HOOKS *hooks;
    void *context;
    volatile LONG active;
};

static BOOL boundary_controls_healthy(const SGW_WINDOWS_AGENT_BOUNDARY *boundary) {
    return boundary->hooks->dns_boundary_ready(boundary->context, boundary->identity) == TRUE &&
        job_is_confined(boundary->job, boundary->child) &&
        sgw_wfp_healthy(boundary->wfp);
}

BOOL sgw_windows_agent_boundary_healthy(const SGW_WINDOWS_AGENT_BOUNDARY *boundary) {
    if (!boundary || InterlockedCompareExchange((volatile LONG *)&boundary->active, 0, 0) != 1 ||
        !boundary->child || !boundary->job || !boundary->stop_event ||
        boundary->stop_event == INVALID_HANDLE_VALUE || !boundary->wfp || !boundary->hooks ||
        !boundary->hooks->dns_boundary_ready || !boundary->identity ||
        WaitForSingleObject(boundary->stop_event, 0) != WAIT_TIMEOUT ||
        WaitForSingleObject(boundary->child, 0) != WAIT_TIMEOUT ||
        !boundary_controls_healthy(boundary) ||
        WaitForSingleObject(boundary->child, 0) != WAIT_TIMEOUT) return FALSE;
    return InterlockedCompareExchange((volatile LONG *)&boundary->active, 0, 0) == 1 &&
        WaitForSingleObject(boundary->stop_event, 0) == WAIT_TIMEOUT;
}

static DWORD child_identity(HANDLE process, PSID broker_sid, PSID package_sid,
    SGW_WINDOWS_AGENT_IDENTITY *identity) {
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    TOKEN_APPCONTAINER_INFORMATION *package = NULL;
    TOKEN_MANDATORY_LABEL *integrity = NULL;
    TOKEN_STATISTICS stats = { 0 };
    DWORD is_appcontainer = 0, session = 0, bytes = 0;
    DWORD result = ERROR_INVALID_DATA;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    user = token_info(token, TokenUser);
    package = token_info(token, TokenAppContainerSid);
    integrity = token_info(token, TokenIntegrityLevel);
    if (!user || !package || !package->TokenAppContainer || !integrity ||
        !IsValidSid(integrity->Label.Sid) || !*GetSidSubAuthorityCount(integrity->Label.Sid) ||
        *GetSidSubAuthority(integrity->Label.Sid,
            *GetSidSubAuthorityCount(integrity->Label.Sid) - 1) > SECURITY_MANDATORY_LOW_RID ||
        !GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer,
            sizeof(is_appcontainer), &bytes) || is_appcontainer != 1 ||
        !GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &bytes) ||
        !GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &bytes) ||
        !EqualSid(user->User.Sid, broker_sid) ||
        !EqualSid(package->TokenAppContainer, package_sid) ||
        (!stats.AuthenticationId.HighPart && !stats.AuthenticationId.LowPart)) goto done;
    identity->windows_session_id = session;
    int length = swprintf(identity->logon_luid, 17, L"%08lx%08lx",
        (unsigned long)(DWORD)stats.AuthenticationId.HighPart,
        (unsigned long)stats.AuthenticationId.LowPart);
    if (length != 16) goto done;
    result = ERROR_SUCCESS;
done:
    if (integrity) LocalFree(integrity);
    if (package) LocalFree(package);
    if (user) LocalFree(user);
    CloseHandle(token);
    return result;
}

static BOOL command_ok(const SGW_WINDOWS_AGENT_COMMAND *command) {
    size_t length = bounded_length(command->executable_name, MAX_PATH);
    if (length < 5 || length >= MAX_PATH ||
        bounded_length(command->arguments, sizeof(command->arguments) / sizeof(wchar_t)) >=
            sizeof(command->arguments) / sizeof(wchar_t)) return FALSE;
    if (_wcsicmp(command->executable_name + length - 4, L".exe") != 0) return FALSE;
    for (size_t i = 0; i < length; i++) {
        wchar_t ch = command->executable_name[i];
        if ((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') ||
            (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'-' || ch == L'.') continue;
        return FALSE;
    }
    return TRUE;
}

static DWORD make_environment(wchar_t *environment, size_t capacity) {
    wchar_t system_root[MAX_PATH];
    DWORD size = GetSystemWindowsDirectoryW(system_root, MAX_PATH);
    if (!size || size >= MAX_PATH) return ERROR_BAD_PATHNAME;
    int first = swprintf(environment, capacity, L"SystemRoot=%ls", system_root);
    if (first < 0 || (size_t)first + 2 >= capacity) return ERROR_INSUFFICIENT_BUFFER;
    int second = swprintf(environment + first + 1, capacity - (size_t)first - 1,
        L"WINDIR=%ls", system_root);
    if (second < 0 || (size_t)first + (size_t)second + 2 >= capacity)
        return ERROR_INSUFFICIENT_BUFFER;
    environment[first + second + 2] = 0;
    return ERROR_SUCCESS;
}

static void drain_job(HANDLE job) {
    if (!job) return;
    // An uncertain Job state must keep this process and its WFP session alive.
    for (;;) {
        TerminateJobObject(job, 1);
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION usage = { 0 };
        if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
            &usage, sizeof(usage), NULL) && usage.ActiveProcesses == 0) return;
        Sleep(50);
    }
}

static void request_job_stop(HANDLE job) {
    if (!job) return;
    for (;;) {
        if (TerminateJobObject(job, 1)) return;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION usage = { 0 };
        if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
            &usage, sizeof(usage), NULL) && usage.ActiveProcesses == 0) return;
        Sleep(50);
    }
}

static void drain_process(HANDLE process) {
    if (!process) return;
    // Job accounting alone is not enough if membership became uncertain.
    for (;;) {
        DWORD waited = WaitForSingleObject(process, 50);
        if (waited == WAIT_OBJECT_0) return;
        TerminateProcess(process, 1);
        if (waited == WAIT_FAILED) Sleep(50);
    }
}

static void revoke_until_confirmed(const SGW_WINDOWS_AGENT_HOOKS *hooks, void *context,
    const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    while (hooks->revoke_session(context, identity) != ERROR_SUCCESS) Sleep(50);
}

static void begin_revoke_until_confirmed(const SGW_WINDOWS_AGENT_HOOKS *hooks, void *context,
    const SGW_WINDOWS_AGENT_IDENTITY *identity, HANDLE job) {
    while (hooks->begin_revoke(context, identity) != ERROR_SUCCESS) {
        request_job_stop(job);
        Sleep(50);
    }
}

static DWORD run_agent(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    const SGW_WINDOWS_AGENT_BOUNDARY_HOOKS *boundary_hooks, void *context,
    DWORD *child_exit_code) {
    if (!stop_event || stop_event == INVALID_HANDLE_VALUE || !hooks ||
        !hooks->prepare || !hooks->begin_revoke || !hooks->revoke_session ||
        (boundary_hooks ? (!boundary_hooks->register_session ||
            !boundary_hooks->dns_boundary_ready) : !hooks->register_session) ||
        !child_exit_code || WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT)
        return ERROR_INVALID_PARAMETER;

    HANDLE thread_token = NULL;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &thread_token)) {
        CloseHandle(thread_token);
        return ERROR_BAD_IMPERSONATION_LEVEL;
    }
    if (GetLastError() != ERROR_NO_TOKEN) return ERROR_BAD_IMPERSONATION_LEVEL;

    *child_exit_code = STILL_ACTIVE;
    SGW_WINDOWS_AGENT_IDENTITY identity = { 0 };
    SGW_WINDOWS_AGENT_COMMAND command = { 0 };
    SGW_WFP_BOUNDARY wfp = { 0 };
    PSID broker_sid = NULL, package_sid = NULL;
    LPWSTR package_text = NULL, profile_path = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    HANDLE job = NULL;
    PROCESS_INFORMATION process = { 0 };
    SGW_WINDOWS_AGENT_BOUNDARY boundary = { 0 };
    BOOL profile_created = FALSE, registration_attempted = FALSE, attrs_initialized = FALSE;
    DWORD result = broker_identity(&identity, &broker_sid);
    if (result) goto done;
    result = make_session_id(identity.session_id);
    if (result) goto done;
    int length = swprintf(identity.profile_name, sizeof(identity.profile_name) / sizeof(wchar_t),
        L"sgwagent_%ls", identity.session_id);
    if (length < 1 || (size_t)length >= sizeof(identity.profile_name) / sizeof(wchar_t)) {
        result = ERROR_INVALID_DATA; goto done;
    }
    length = swprintf(identity.job_name, sizeof(identity.job_name) / sizeof(wchar_t),
        L"Local\\s-gw-agent-%ls", identity.session_id);
    if (length < 1 || (size_t)length >= sizeof(identity.job_name) / sizeof(wchar_t)) {
        result = ERROR_INVALID_DATA; goto done;
    }
    HRESULT status = CreateAppContainerProfile(identity.profile_name, L"s-gw agent",
        L"Isolated s-gw agent session", NULL, 0, &package_sid);
    if (status != S_OK) { result = status == S_FALSE ? ERROR_ALREADY_EXISTS : (DWORD)status; goto done; }
    profile_created = TRUE;
    if (!ConvertSidToStringSidW(package_sid, &package_text)) {
        result = GetLastError(); goto done;
    }
    length = (int)wcslen(package_text);
    if ((size_t)length >= sizeof(identity.package_sid) / sizeof(wchar_t)) {
        result = ERROR_INVALID_SID; goto done;
    }
    wmemcpy(identity.package_sid, package_text, (size_t)length + 1);
    status = GetAppContainerFolderPath(package_text, &profile_path);
    if (status != S_OK || !profile_path || wcslen(profile_path) >= MAX_PATH) {
        result = status != S_OK ? (DWORD)status : ERROR_BAD_PATHNAME; goto done;
    }
    wmemcpy(identity.profile_path, profile_path, wcslen(profile_path) + 1);
    result = hooks->prepare(context, &identity, &command);
    if (result) goto done;
    if (!command_ok(&command)) { result = ERROR_INVALID_DATA; goto done; }
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) {
        result = ERROR_OPERATION_ABORTED; goto done;
    }
    result = create_private_job(&identity, &job);
    if (result) goto done;
    result = sgw_wfp_start(package_sid, &wfp);
    if (result) goto done;
    if (!sgw_wfp_healthy(&wfp)) { result = ERROR_NETWORK_ACCESS_DENIED; goto done; }

    SIZE_T attr_bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_bytes);
    if (!attr_bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        result = ERROR_INVALID_DATA; goto done;
    }
    attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)LocalAlloc(LMEM_FIXED, attr_bytes);
    if (!attrs) { result = ERROR_OUTOFMEMORY; goto done; }
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_bytes)) {
        result = GetLastError(); goto done;
    }
    attrs_initialized = TRUE;
    SECURITY_CAPABILITIES capabilities = { package_sid, NULL, 0, 0 };
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &capabilities, sizeof(capabilities), NULL, NULL)) {
        result = GetLastError(); goto done;
    }

    wchar_t image[MAX_PATH * 2];
    length = swprintf(image, sizeof(image) / sizeof(wchar_t), L"%ls\\%ls",
        identity.profile_path, command.executable_name);
    if (length < 1 || (size_t)length >= sizeof(image) / sizeof(wchar_t)) {
        result = ERROR_BAD_PATHNAME; goto done;
    }
    wchar_t command_line[8192];
    length = swprintf(command_line, sizeof(command_line) / sizeof(wchar_t),
        L"\"%ls\" %ls", image, command.arguments);
    if (length < 1 || (size_t)length >= sizeof(command_line) / sizeof(wchar_t)) {
        result = ERROR_INSUFFICIENT_BUFFER; goto done;
    }
    wchar_t environment[MAX_PATH * 2 + 32];
    result = make_environment(environment, sizeof(environment) / sizeof(wchar_t));
    if (result) goto done;
    STARTUPINFOEXW startup = { 0 };
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs;
    if (!CreateProcessW(image, command_line, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        environment, identity.profile_path, &startup.StartupInfo, &process)) {
        result = GetLastError(); goto done;
    }
    identity.process_id = process.dwProcessId;
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        !job_is_confined(job, process.hProcess)) {
        result = ERROR_INVALID_DATA; goto done;
    }
    result = child_identity(process.hProcess, broker_sid, package_sid, &identity);
    if (result) goto done;
    if (!sgw_wfp_healthy(&wfp)) { result = ERROR_NETWORK_ACCESS_DENIED; goto done; }
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) {
        result = ERROR_OPERATION_ABORTED; goto done;
    }
    if (boundary_hooks) {
        boundary.child = process.hProcess;
        boundary.job = job;
        boundary.stop_event = stop_event;
        boundary.wfp = &wfp;
        boundary.identity = &identity;
        boundary.hooks = boundary_hooks;
        boundary.context = context;
        InterlockedExchange(&boundary.active, 1);
        if (!sgw_windows_agent_boundary_healthy(&boundary)) {
            result = ERROR_NETWORK_ACCESS_DENIED; goto done;
        }
    }
    registration_attempted = TRUE;
    result = boundary_hooks
        ? boundary_hooks->register_session(context, &identity, &boundary)
        : hooks->register_session(context, &identity);
    if (result) goto done;
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) {
        result = ERROR_OPERATION_ABORTED; goto done;
    }
    if (boundary_hooks ? !sgw_windows_agent_boundary_healthy(&boundary)
        : (!sgw_wfp_healthy(&wfp) || !job_is_confined(job, process.hProcess))) {
        result = ERROR_NETWORK_ACCESS_DENIED; goto done;
    }
    if (WaitForSingleObject(stop_event, 0) != WAIT_TIMEOUT) {
        result = ERROR_OPERATION_ABORTED; goto done;
    }
    if (ResumeThread(process.hThread) == (DWORD)-1) {
        result = GetLastError(); goto done;
    }
    HANDLE watched[2] = { process.hProcess, stop_event };
    for (;;) {
        DWORD child_waited = WaitForSingleObject(process.hProcess, 0);
        if (child_waited == WAIT_OBJECT_0) {
            result = (boundary_hooks ? boundary_controls_healthy(&boundary)
                : (sgw_wfp_healthy(&wfp) && job_is_confined(job, process.hProcess))) &&
                GetExitCodeProcess(process.hProcess, child_exit_code)
                ? ERROR_SUCCESS : ERROR_NETWORK_ACCESS_DENIED;
            break;
        }
        if (child_waited != WAIT_TIMEOUT) { result = GetLastError(); break; }
        if (boundary_hooks ? !boundary_controls_healthy(&boundary)
            : (!sgw_wfp_healthy(&wfp) || !job_is_confined(job, process.hProcess))) {
            result = ERROR_NETWORK_ACCESS_DENIED; break;
        }
        DWORD waited = WaitForMultipleObjects(2, watched, FALSE, 100);
        if (waited == WAIT_OBJECT_0) {
            result = (boundary_hooks ? boundary_controls_healthy(&boundary)
                : (sgw_wfp_healthy(&wfp) && job_is_confined(job, process.hProcess))) &&
                GetExitCodeProcess(process.hProcess, child_exit_code)
                ? ERROR_SUCCESS : ERROR_NETWORK_ACCESS_DENIED;
            break;
        }
        if (waited == WAIT_OBJECT_0 + 1) { result = ERROR_OPERATION_ABORTED; break; }
        if (waited != WAIT_TIMEOUT) { result = GetLastError(); break; }
    }

done:
    InterlockedExchange(&boundary.active, 0);
    if (process.hProcess && !job) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    if (registration_attempted) {
        // A known boundary failure takes priority over the normal broker-first teardown.
        if (result == ERROR_NETWORK_ACCESS_DENIED || !sgw_wfp_healthy(&wfp))
            request_job_stop(job);
        begin_revoke_until_confirmed(hooks, context, &identity, job);
    }
    drain_job(job);
    drain_process(process.hProcess);
    if (registration_attempted) revoke_until_confirmed(hooks, context, &identity);
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) CloseHandle(process.hProcess);
    if (attrs_initialized) DeleteProcThreadAttributeList(attrs);
    if (attrs) LocalFree(attrs);
    if (job) CloseHandle(job);
    sgw_wfp_stop(&wfp);
    if (profile_path) CoTaskMemFree(profile_path);
    if (package_text) LocalFree(package_text);
    if (package_sid) FreeSid(package_sid);
    if (broker_sid) LocalFree(broker_sid);
    if (profile_created) {
        HRESULT deleted = DeleteAppContainerProfile(identity.profile_name);
        if (deleted != S_OK) deleted = DeleteAppContainerProfile(identity.profile_name);
        if (result == ERROR_SUCCESS && deleted != S_OK) result = (DWORD)deleted;
    }
    return result;
}

DWORD sgw_windows_agent_run(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    void *context, DWORD *child_exit_code) {
    return run_agent(stop_event, hooks, NULL, context, child_exit_code);
}

DWORD sgw_windows_agent_run_bound(HANDLE stop_event, const SGW_WINDOWS_AGENT_HOOKS *hooks,
    const SGW_WINDOWS_AGENT_BOUNDARY_HOOKS *boundary_hooks, void *context,
    DWORD *child_exit_code) {
    if (!boundary_hooks) return ERROR_INVALID_PARAMETER;
    return run_agent(stop_event, hooks, boundary_hooks, context, child_exit_code);
}
