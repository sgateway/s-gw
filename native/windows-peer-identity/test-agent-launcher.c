#include "agent-launcher.h"
#include <stdio.h>
#include <wchar.h>

typedef struct {
    const wchar_t *source;
    int mode;
    int registered;
    int revoked;
    int marker_at_revoke;
    HANDLE stop_event;
} TEST_CONTEXT;

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
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, identity->process_id);
    HANDLE job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, identity->job_name);
    BOOL member = FALSE;
    BOOL valid = process && job && IsProcessInJob(process, job, &member) && member &&
        WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (job) CloseHandle(job);
    if (process) CloseHandle(process);
    if (!valid) return ERROR_INVALID_DATA;
    if (context->mode == 1) return ERROR_ACCESS_DENIED;
    if (context->mode == 2) SetEvent(context->stop_event);
    return ERROR_SUCCESS;
}

static DWORD revoke_session(void *opaque, const SGW_WINDOWS_AGENT_IDENTITY *identity) {
    TEST_CONTEXT *context = opaque;
    context->revoked++;
    wchar_t marker[MAX_PATH * 2];
    int size = swprintf(marker, sizeof(marker) / sizeof(wchar_t), L"%ls\\marker.txt",
        identity->profile_path);
    if (size > 0 && (size_t)size < sizeof(marker) / sizeof(wchar_t))
        context->marker_at_revoke = GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES;
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 2) return 2;
    SGW_WINDOWS_AGENT_HOOKS hooks = { prepare, register_session, revoke_session };
    HANDLE stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop) return 2;
    DWORD result = ERROR_SUCCESS, child_exit = STILL_ACTIVE;
    for (int mode = 0; mode < 3; mode++) {
        TEST_CONTEXT context = { argv[1], mode, 0, 0, 0, stop };
        ResetEvent(stop);
        result = sgw_windows_agent_run(stop, &hooks, &context, &child_exit);
        if (context.registered != 1 || context.revoked != 1 ||
            (mode == 0 && (result || child_exit || !context.marker_at_revoke)) ||
            (mode == 1 && (result != ERROR_ACCESS_DENIED || context.marker_at_revoke)) ||
            (mode == 2 && (result != ERROR_OPERATION_ABORTED || context.marker_at_revoke))) {
            fprintf(stderr, "Launcher mode %d failed: result=%lu exit=%lu register=%d revoke=%d marker=%d\n",
                mode, (unsigned long)result, (unsigned long)child_exit, context.registered,
                context.revoked, context.marker_at_revoke);
            CloseHandle(stop);
            return 1;
        }
    }
    CloseHandle(stop);
    puts("LAUNCHER-SUSPEND-REGISTER-REVOKE-PASSED");
    return 0;
}
