#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>
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
    LPWSTR wide_sid = NULL;
    PWSTR folder = NULL;
    char *folder_utf8 = NULL;
    HRESULT status = CreateAppContainerProfile(name, L"s-gw pipe test", L"Temporary CI identity", NULL, 0, &sid);
    if (FAILED(status)) {
        fprintf(stderr, "CreateAppContainerProfile failed: 0x%08lx\n", (unsigned long)status);
        return 1;
    }
    int result = 1;
    if (!ConvertSidToStringSidA(sid, &text) || !ConvertSidToStringSidW(sid, &wide_sid)) goto done;
    status = GetAppContainerFolderPath(wide_sid, &folder);
    if (FAILED(status) || !folder) goto done;
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, folder, -1, NULL, 0, NULL, NULL);
    if (bytes < 2) goto done;
    folder_utf8 = malloc((size_t)bytes);
    if (!folder_utf8 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, folder, -1,
        folder_utf8, bytes, NULL, NULL)) goto done;
    printf("%s\n%s\n", text, folder_utf8);
    result = 0;

done:
    if (result) DeleteAppContainerProfile(name);
    free(folder_utf8);
    if (folder) CoTaskMemFree(folder);
    if (wide_sid) LocalFree(wide_sid);
    LocalFree(text);
    FreeSid(sid);
    return result;
}

static int loopback_blocked(const wchar_t *port_text, int family) {
    wchar_t *end = NULL;
    unsigned long port = wcstoul(port_text, &end, 10);
    if (!end || *end || port < 1 || port > 65535) return 0;
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 0;
    SOCKET probe = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (probe == INVALID_SOCKET) {
        int error = WSAGetLastError();
        WSACleanup();
        return error == WSAEACCES;
    }
    int blocked;
    if (family == AF_INET6) {
        struct sockaddr_in6 target = { 0 };
        IN6_ADDR loopback = IN6ADDR_LOOPBACK_INIT;
        target.sin6_family = AF_INET6;
        target.sin6_port = htons((u_short)port);
        target.sin6_addr = loopback;
        blocked = connect(probe, (const struct sockaddr *)&target, sizeof(target)) == SOCKET_ERROR;
    } else {
        struct sockaddr_in target = { 0 };
        target.sin_family = AF_INET;
        target.sin_port = htons((u_short)port);
        target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        blocked = connect(probe, (const struct sockaddr *)&target, sizeof(target)) == SOCKET_ERROR;
    }
    int error = blocked ? WSAGetLastError() : 0;
    closesocket(probe);
    WSACleanup();
    if (error == WSAEINVAL || error == WSAEAFNOSUPPORT || error == WSAENOTSOCK) return 0;
    return blocked;
}

static int can_read_fixture(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    const char expected[] = "agent-readable fixture\n";
    char content[sizeof(expected) - 1];
    DWORD amount = 0;
    int readable = ReadFile(file, content, sizeof(content), &amount, NULL) &&
        amount == sizeof(content) && memcmp(content, expected, sizeof(content)) == 0;
    CloseHandle(file);
    return readable;
}

static int canary_access_denied(const wchar_t *path, DWORD rights, const char *operation) {
    HANDLE file = CreateFileW(path, rights, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
        fprintf(stderr, "AppContainer broker canary allowed %s.\n", operation);
        return 0;
    }
    DWORD error = GetLastError();
    if (error == ERROR_ACCESS_DENIED) return 1;
    fprintf(stderr, "AppContainer broker canary %s failed unexpectedly: %lu\n", operation, error);
    return 0;
}

static int canary_delete_denied(const wchar_t *path) {
    if (DeleteFileW(path)) {
        fputs("AppContainer deleted the broker canary.\n", stderr);
        return 0;
    }
    DWORD error = GetLastError();
    if (error == ERROR_ACCESS_DENIED) return 1;
    fprintf(stderr, "AppContainer broker canary delete failed unexpectedly: %lu\n", error);
    return 0;
}

static int run_client(const wchar_t *pipe_name, const wchar_t *ipv4_port,
    const wchar_t *ipv6_port, const wchar_t *shared_path,
    const wchar_t *canary_path, const wchar_t *profile) {
    PSID expected_sid = NULL;
    if (FAILED(DeriveAppContainerSidFromAppContainerName(profile, &expected_sid))) return 1;
    HANDLE token = NULL;
    DWORD is_appcontainer = 0, size = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        FreeSid(expected_sid);
        return 1;
    }
    int isolated = GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer,
        sizeof(is_appcontainer), &size) && is_appcontainer == 1;
    GetTokenInformation(token, TokenAppContainerSid, NULL, 0, &size);
    TOKEN_APPCONTAINER_INFORMATION *package = size && size <= 4096 ? malloc(size) : NULL;
    isolated = isolated && package && GetTokenInformation(token, TokenAppContainerSid, package, size, &size) &&
        package->TokenAppContainer && EqualSid(package->TokenAppContainer, expected_sid);
    free(package);
    CloseHandle(token);
    FreeSid(expected_sid);
    if (!isolated) return 1;
    if (!loopback_blocked(ipv4_port, AF_INET) || !loopback_blocked(ipv6_port, AF_INET6)) {
        fputs("AppContainer reached forbidden IPv4 or IPv6 host loopback.\n", stderr);
        return 1;
    }
    if (!can_read_fixture(shared_path)) {
        fputs("AppContainer could not read its shared-file control.\n", stderr);
        return 1;
    }
    if (!canary_access_denied(canary_path, GENERIC_READ, "read") ||
        !canary_access_denied(canary_path, GENERIC_WRITE, "write") ||
        !canary_access_denied(canary_path, DELETE, "delete") ||
        !canary_access_denied(canary_path, WRITE_DAC, "ACL change") ||
        !canary_delete_denied(canary_path)) {
        return 1;
    }

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

static int launch_client(const wchar_t *name, const wchar_t *pipe_name,
    const wchar_t *ipv4_port, const wchar_t *ipv6_port,
    const wchar_t *shared_path, const wchar_t *canary_path, int stop_job) {
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
    wchar_t command[MAX_PATH * 4 + 256];
    if (swprintf(command, sizeof(command) / sizeof(command[0]),
        L"\"%ls\" client \"%ls\" %ls %ls \"%ls\" \"%ls\" \"%ls\"",
        executable, pipe_name, ipv4_port, ipv6_port, shared_path, canary_path, name) < 0) goto done;

    STARTUPINFOEXW startup = { 0 };
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs;
    PROCESS_INFORMATION process = { 0 };
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        goto done;
    }
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
        &startup.StartupInfo, &process)) {
        fprintf(stderr, "AppContainer process launch failed: %lu\n", GetLastError());
        CloseHandle(job);
        goto done;
    }
    BOOL assigned = FALSE;
    if (!AssignProcessToJobObject(job, process.hProcess) ||
        !IsProcessInJob(process.hProcess, job, &assigned) || !assigned ||
        ResumeThread(process.hThread) == (DWORD)-1) {
        fprintf(stderr, "AppContainer job assignment failed: %lu\n", GetLastError());
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        goto done;
    }
    DWORD exit_code = 1;
    if (stop_job) {
        char signal = 0;
        DWORD amount = 0;
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input != INVALID_HANDLE_VALUE && ReadFile(input, &signal, 1, &amount, NULL) &&
            amount == 1 && signal == 'K' && WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT) {
            CloseHandle(job);
            job = NULL;
            if (WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0 &&
                GetExitCodeProcess(process.hProcess, &exit_code) && exit_code != 0) result = 0;
        }
        if (result) TerminateProcess(process.hProcess, 1);
    } else {
        DWORD waited = WaitForSingleObject(process.hProcess, 30000);
        if (waited != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
        else if (GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0) result = 0;
    }
    if (result) fprintf(stderr, "AppContainer child failed: %lu\n", (unsigned long)exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (job) CloseHandle(job);

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
    if (argc == 8 && wcscmp(argv[1], L"client") == 0)
        return run_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (argc == 8 && wcscmp(argv[1], L"launch") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], 0);
    if (argc == 8 && wcscmp(argv[1], L"launch-stop") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], 1);
    return 1;
}
