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
    if (context->mode >= 2) SetEvent(context->stop_event);
    return ERROR_SUCCESS;
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
    SGW_WINDOWS_AGENT_HOOKS hooks = { prepare, register_session, begin_revoke, revoke_session };
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop) return 2;
    DWORD result = ERROR_SUCCESS, child_exit = STILL_ACTIVE;
    for (int mode = 0; mode < 4; mode++) {
        TEST_CONTEXT context = { 0 };
        context.source = argv[1];
        context.mode = mode;
        context.stop_event = stop;
        ResetEvent(stop);
        result = sgw_windows_agent_run(stop, &hooks, &context, &child_exit);
        int expected_begins = mode == 3 ? 2 : 1;
        if (context.registered != 1 || context.began != expected_begins ||
            context.revoked != 1 || !context.drained_at_revoke ||
            !context.child_stopped_at_revoke ||
            context.begin_count_at_revoke != expected_begins ||
            (mode == 0 && (result || child_exit || !context.marker_at_revoke)) ||
            (mode == 1 && (result != ERROR_ACCESS_DENIED || context.marker_at_revoke)) ||
            (mode >= 2 && (result != ERROR_OPERATION_ABORTED || context.marker_at_revoke)) ||
            (mode != 0 && !context.live_on_first_begin) ||
            (mode == 3 && !context.stopped_on_retry)) {
            fprintf(stderr, "Launcher mode %d failed: result=%lu exit=%lu register=%d begin=%d revoke=%d marker=%d live=%d retry_stopped=%d drained=%d child_stopped=%d\n",
                mode, (unsigned long)result, (unsigned long)child_exit, context.registered,
                context.began, context.revoked, context.marker_at_revoke,
                context.live_on_first_begin, context.stopped_on_retry, context.drained_at_revoke,
                context.child_stopped_at_revoke);
            CloseHandle(stop);
            return 1;
        }
    }
    CloseHandle(stop);
    puts("LAUNCHER-SUSPEND-REGISTER-REVOKE-PASSED");
    return 0;
}
