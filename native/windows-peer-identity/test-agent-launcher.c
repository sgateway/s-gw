#include "agent-launcher.h"
#include <stdio.h>
#include <wchar.h>

typedef struct {
    const wchar_t *source;
    int mode;
    int registered;
    int began;
    int revoked;
    int marker_at_revoke;
    int live_on_first_begin;
    int stopped_on_retry;
    int drained_at_revoke;
    int child_stopped_at_revoke;
    int begin_count_at_revoke;
    int dns_ready;
    int dns_checks;
    int boundary_checked;
    int stopped_boundary_rejected;
    int killed_during_dns;
    int retained_pid_matches;
    int retained_pid_independent;
    int stopped_pid_rejected;
    int dead_pid_rejected;
    int inactive_pid_rejected;
    const SGW_WINDOWS_AGENT_BOUNDARY *boundary;
    HANDLE stop_event;
} TEST_CONTEXT;

static BOOL launched_child_live(const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
        FALSE, identity->process_id);
    HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, identity->job_name);
    BOOL member = FALSE;
    BOOL live = process && job && IsProcessInJob(process, job, &member) && member &&
        WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (job) CloseHandle(job);
    if (process) CloseHandle(process);
    return live;
}

static BOOL job_drained(const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, identity->job_name);
    if (!job) return FALSE;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION usage = { 0 };
    BOOL drained = QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
        &usage, sizeof(usage), NULL) && usage.ActiveProcesses == 0;
    CloseHandle(job);
    return drained;
}

static BOOL launched_child_stopped(const SGW_WINDOWS_AGENT_IDENTITY *identity, DWORD timeout_ms) {
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, identity->process_id);
    if (!process) return FALSE;
    BOOL stopped = WaitForSingleObject(process, timeout_ms) == WAIT_OBJECT_0;
    CloseHandle(process);
    return stopped;
}

static DWORD stage_file(const wchar_t *source, const wchar_t *target) {
    HANDLE input = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) return GetLastError();
    HANDLE output = CreateFileW(target, GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        CloseHandle(input);
        return error;
    }
    DWORD result = ERROR_SUCCESS;
    BYTE buffer[8192];
    DWORD read = 0, written = 0;
    for (;;) {
        if (!ReadFile(input, buffer, sizeof(buffer), &read, NULL)) {
            result = GetLastError();
            break;
        }
        if (!read) break;
        if (!WriteFile(output, buffer, read, &written, NULL) || written != read) {
            result = GetLastError();
            if (!result) result = ERROR_WRITE_FAULT;
            break;
        }
    }
    if (!result && !FlushFileBuffers(output)) result = GetLastError();
    CloseHandle(output);
    CloseHandle(input);
    return result;
}

static DWORD prepare(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity,
    SGW_WINDOWS_AGENT_COMMAND *command) {
    TEST_CONTEXT *context = opaque;
    wchar_t target[MAX_PATH * 2];
    int size = swprintf(target, sizeof(target) / sizeof(wchar_t), L"%ls\\sgw-probe.exe",
        identity->profile_path);
    if (size < 1 || (size_t)size >= sizeof(target) / sizeof(wchar_t))
        return ERROR_BAD_PATHNAME;
    DWORD result = stage_file(context->source, target);
    if (result) return result;
    wcscpy_s(command->executable_name, MAX_PATH, L"sgw-probe.exe");
    return ERROR_SUCCESS;
}

static DWORD register_session(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    TEST_CONTEXT *context = opaque;
    context->registered++;
    if (!identity->process_id || !identity->package_sid[0] ||
        !identity->broker_sid[0] || !identity->user_sid[0] ||
        !identity->logon_luid[0] || !identity->session_id[0]) return ERROR_INVALID_DATA;
    if (!launched_child_live(identity)) return ERROR_INVALID_DATA;
    if (context->mode == 1) return ERROR_ACCESS_DENIED;
    if (context->mode == 2 || context->mode == 3) SetEvent(context->stop_event);
    return ERROR_SUCCESS;
}

static BOOL dns_boundary_ready(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    TEST_CONTEXT *context = opaque;
    if (!identity->package_sid[0]) return FALSE;
    context->dns_checks++;
    if (context->mode == 7 && context->dns_checks == 1) SetEvent(context->stop_event);
    if (context->mode == 8 && context->dns_checks == 1) {
        HANDLE child = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, identity->process_id);
        if (!child) return FALSE;
        context->killed_during_dns = TerminateProcess(child, 1) &&
            WaitForSingleObject(child, 5000) == WAIT_OBJECT_0;
        CloseHandle(child);
        if (!context->killed_during_dns) return FALSE;
    }
    return context->dns_ready ? TRUE : FALSE;
}

static DWORD register_bound(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity,
    const SGW_WINDOWS_AGENT_BOUNDARY *boundary) {
    TEST_CONTEXT *context = opaque;
    context->boundary = boundary;
    context->boundary_checked = sgw_windows_agent_boundary_healthy(boundary);
    if (!context->boundary_checked) return ERROR_NETWORK_ACCESS_DENIED;
    DWORD retained_pid = sgw_windows_agent_boundary_child_pid(boundary);
    context->retained_pid_matches = retained_pid != 0 && retained_pid == identity->process_id;

    // Spoof only the callback record to prove the accessor reads the retained handle.
    SGW_WINDOWS_AGENT_IDENTITY *mutable_identity = (SGW_WINDOWS_AGENT_IDENTITY *)identity;
    DWORD recorded_pid = identity->process_id;
    mutable_identity->process_id = 0;
    context->retained_pid_independent =
        sgw_windows_agent_boundary_child_pid(boundary) == recorded_pid;
    mutable_identity->process_id = recorded_pid;

    if (context->mode == 9) {
        HANDLE child = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, recorded_pid);
        if (!child) return ERROR_INVALID_HANDLE;
        BOOL stopped = TerminateProcess(child, 1) &&
            WaitForSingleObject(child, 5000) == WAIT_OBJECT_0;
        CloseHandle(child);
        context->dead_pid_rejected = stopped &&
            sgw_windows_agent_boundary_child_pid(boundary) == 0;
        return ERROR_NETWORK_ACCESS_DENIED;
    }
    DWORD result = register_session(opaque, identity);
    if (context->mode == 5 && result == ERROR_SUCCESS) context->dns_ready = 0;
    if ((context->mode == 2 || context->mode == 3) && result == ERROR_SUCCESS) {
        context->stopped_boundary_rejected = !sgw_windows_agent_boundary_healthy(boundary);
        context->stopped_pid_rejected = sgw_windows_agent_boundary_child_pid(boundary) == 0;
    }
    return result;
}

static DWORD begin_revoke(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    TEST_CONTEXT *context = opaque;
    context->began++;
    if (context->began == 1) context->live_on_first_begin = launched_child_live(identity);
    if (context->mode == 3 && context->began == 1) return ERROR_RETRY;
    if (context->mode == 3) context->stopped_on_retry = launched_child_stopped(identity, 5000);
    return ERROR_SUCCESS;
}

static DWORD revoke_session(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    TEST_CONTEXT *context = opaque;
    context->revoked++;
    if (context->boundary)
        context->inactive_pid_rejected = sgw_windows_agent_boundary_child_pid(context->boundary) == 0;
    context->drained_at_revoke = job_drained(identity);
    context->child_stopped_at_revoke = launched_child_stopped(identity, 0);
    context->begin_count_at_revoke = context->began;
    wchar_t marker[MAX_PATH * 2];
    int size = swprintf(marker, sizeof(marker) / sizeof(wchar_t), L"%ls\\marker.txt",
        identity->profile_path);
    if (size > 0 && (size_t)size < sizeof(marker) / sizeof(wchar_t))
        context->marker_at_revoke = GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES;
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    if (sgw_windows_agent_boundary_child_pid(NULL) != 0) return 1;
    SGW_WINDOWS_AGENT_HOOKS hooks = { prepare, register_session, begin_revoke, revoke_session };
    SGW_WINDOWS_AGENT_BOUNDARY_HOOKS boundary_hooks = { register_bound, dns_boundary_ready };
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop) return 2;
    DWORD result = ERROR_SUCCESS, child_exit = STILL_ACTIVE;
    SGW_WINDOWS_AGENT_BOUNDARY_HOOKS missing_dns = { register_bound, NULL };
    TEST_CONTEXT rejected = { 0 };
    if (sgw_windows_agent_run_bound(stop, &hooks, &missing_dns, &rejected,
        &child_exit) != ERROR_INVALID_PARAMETER || rejected.registered) {
        CloseHandle(stop);
        return 1;
    }
    for (int mode = 0; mode < 10; mode++) {
        TEST_CONTEXT context = { 0 };
        context.source = argv[1];
        context.mode = mode;
        context.dns_ready = mode != 4;
        context.stop_event = stop;
        ResetEvent(stop);
        result = mode == 0
            ? sgw_windows_agent_run(stop, &hooks, &context, &child_exit)
            : sgw_windows_agent_run_bound(stop, &hooks, &boundary_hooks, &context, &child_exit);
        int before_registration = mode == 4 || mode == 7 || mode == 8;
        int has_boundary = mode != 0 && !before_registration;
        int expected_begins = before_registration ? 0 : mode == 3 ? 2 : 1;
        if (context.registered != ((before_registration || mode == 9) ? 0 : 1) ||
            context.began != expected_begins ||
            context.revoked != (before_registration ? 0 : 1) ||
            (!before_registration &&
                (!context.drained_at_revoke || !context.child_stopped_at_revoke ||
                context.begin_count_at_revoke != expected_begins)) ||
            (mode == 0 && (context.dns_checks || context.boundary_checked)) ||
            (mode != 0 && (!context.dns_checks ||
                context.boundary_checked != !before_registration)) ||
            (context.retained_pid_matches != has_boundary ||
                context.retained_pid_independent != has_boundary ||
                context.inactive_pid_rejected != has_boundary) ||
            (context.stopped_pid_rejected != (mode == 2 || mode == 3)) ||
            (context.dead_pid_rejected != (mode == 9)) ||
            (context.stopped_boundary_rejected != (mode == 2 || mode == 3)) ||
            (context.killed_during_dns != (mode == 8)) ||
            (mode == 0 && (result || child_exit || !context.marker_at_revoke)) ||
            (mode == 6 && (result || child_exit || !context.marker_at_revoke)) ||
            (mode == 1 && (result != ERROR_ACCESS_DENIED || context.marker_at_revoke)) ||
            ((mode == 2 || mode == 3) &&
                (result != ERROR_OPERATION_ABORTED || context.marker_at_revoke)) ||
            ((mode == 4 || mode == 5 || mode == 7 || mode == 8 || mode == 9) &&
                (result != ERROR_NETWORK_ACCESS_DENIED || context.marker_at_revoke)) ||
            ((mode == 1 || mode == 2 || mode == 3) && !context.live_on_first_begin) ||
            (mode == 6 && context.live_on_first_begin) ||
            (mode == 3 && !context.stopped_on_retry)) {
            fprintf(stderr, "Launcher mode %d failed: result=%lu exit=%lu register=%d begin=%d revoke=%d marker=%d live=%d retry_stopped=%d drained=%d child_stopped=%d dns=%d boundary=%d stop_rejected=%d killed=%d pid_match=%d pid_independent=%d pid_stop=%d pid_dead=%d pid_inactive=%d\n",
                mode, (unsigned long)result, (unsigned long)child_exit, context.registered,
                context.began, context.revoked, context.marker_at_revoke,
                context.live_on_first_begin, context.stopped_on_retry, context.drained_at_revoke,
                context.child_stopped_at_revoke, context.dns_checks, context.boundary_checked,
                context.stopped_boundary_rejected, context.killed_during_dns,
                context.retained_pid_matches, context.retained_pid_independent,
                context.stopped_pid_rejected, context.dead_pid_rejected,
                context.inactive_pid_rejected);
            CloseHandle(stop);
            return 1;
        }
    }
    CloseHandle(stop);
    puts("LAUNCHER-SUSPEND-REGISTER-REVOKE-BOUNDARY-PASSED");
    return 0;
}
