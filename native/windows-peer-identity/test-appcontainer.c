#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define PIPE_CLIENT_RIGHTS (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)

static int create_profile(const wchar_t *name) {
    PSID sid = NULL;
    LPSTR text = NULL;
    HRESULT status = CreateAppContainerProfile(name, L"s-gw pipe test", L"Temporary CI identity", NULL, 0, &sid);
    if (FAILED(status)) {
        fprintf(stderr, "CreateAppContainerProfile failed: 0x%08lx\n", (unsigned long)status);
        return 1;
    }
    if (!ConvertSidToStringSidA(sid, &text)) {
        DeleteAppContainerProfile(name);
        FreeSid(sid);
        return 1;
    }
    puts(text);
    LocalFree(text);
    FreeSid(sid);
    return 0;
}

static int run_client(const wchar_t *pipe_name) {
    HANDLE token = NULL;
    DWORD is_appcontainer = 0, size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 1;
    int isolated = GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer,
        sizeof(is_appcontainer), &size) && is_appcontainer == 1;
    CloseHandle(token);
    if (!isolated) return 1;

    HANDLE pipe = CreateFileW(pipe_name, PIPE_CLIENT_RIGHTS, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "AppContainer pipe open failed: %lu\n", GetLastError());
        return 1;
    }
    const char request[] = "appcontainer probe";
    const char expected[] = "broker reply";
    char response[sizeof(expected)];
    DWORD amount = 0;
    int result = 1;
    if (WriteFile(pipe, request, sizeof(request) - 1, &amount, NULL) &&
        amount == (DWORD)(sizeof(request) - 1) &&
        ReadFile(pipe, response, sizeof(expected) - 1, &amount, NULL) &&
        amount == (DWORD)(sizeof(expected) - 1) &&
        memcmp(response, expected, sizeof(expected) - 1) == 0) result = 0;
    if (result) fprintf(stderr, "AppContainer exchange failed: %lu\n", GetLastError());
    CloseHandle(pipe);
    return result;
}

static int launch_client(const wchar_t *name, const wchar_t *pipe_name) {
    PSID sid = NULL;
    HRESULT status = DeriveAppContainerSidFromAppContainerName(name, &sid);
    if (FAILED(status)) return 1;

    SIZE_T bytes = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    if (!bytes || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        FreeSid(sid);
        return 1;
    }
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = malloc(bytes);
    if (!attrs) {
        FreeSid(sid);
        return 1;
    }
    int initialized = InitializeProcThreadAttributeList(attrs, 1, 0, &bytes);
    SECURITY_CAPABILITIES capabilities = { sid, NULL, 0, 0 };
    int result = 1;
    if (!initialized || !UpdateProcThreadAttribute(attrs, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities, sizeof(capabilities), NULL, NULL)) goto done;

    wchar_t executable[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (!length || length >= MAX_PATH) goto done;
    wchar_t command[MAX_PATH + 256];
    if (swprintf(command, sizeof(command) / sizeof(command[0]), L"\"%ls\" client \"%ls\"",
        executable, pipe_name) < 0) goto done;

    STARTUPINFOEXW startup = { 0 };
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs;
    PROCESS_INFORMATION process = { 0 };
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL,
        &startup.StartupInfo, &process)) {
        fprintf(stderr, "AppContainer process launch failed: %lu\n", GetLastError());
        goto done;
    }
    DWORD waited = WaitForSingleObject(process.hProcess, 30000);
    DWORD exit_code = 1;
    if (waited != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
    else if (GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0) result = 0;
    if (result) fprintf(stderr, "AppContainer child failed: %lu\n", (unsigned long)exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

done:
    if (initialized) DeleteProcThreadAttributeList(attrs);
    free(attrs);
    FreeSid(sid);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"create") == 0) return create_profile(argv[2]);
    if (argc == 3 && wcscmp(argv[1], L"delete") == 0) {
        HRESULT status = DeleteAppContainerProfile(argv[2]);
        if (FAILED(status)) fprintf(stderr, "DeleteAppContainerProfile failed: 0x%08lx\n", (unsigned long)status);
        return FAILED(status) ? 1 : 0;
    }
    if (argc == 3 && wcscmp(argv[1], L"client") == 0) return run_client(argv[2]);
    if (argc == 4 && wcscmp(argv[1], L"launch") == 0) return launch_client(argv[2], argv[3]);
    return 1;
}
