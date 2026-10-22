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
#include <errno.h>
#include <fwpmu.h>
#include "wfp-boundary.h"

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
        if (error == WSAEACCES) return 1;
        fprintf(stderr, "AppContainer loopback socket failed without access denial: %d\n", error);
        return 0;
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
    if (error == WSAEACCES) return 1;
    if (blocked) fprintf(stderr, "AppContainer loopback connect failed without access denial: %d\n", error);
    return 0;
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

static int system_path_matches(const wchar_t *key, const wchar_t *system_dir) {
    wchar_t value[MAX_PATH];
    DWORD size = GetEnvironmentVariableW(key, value, MAX_PATH);
    return size && size < MAX_PATH && _wcsicmp(value, system_dir) == 0;
}

static int agent_environment_is_clean(void) {
    wchar_t value[MAX_PATH];
    wchar_t system_dir[MAX_PATH];
    DWORD system_size = GetSystemWindowsDirectoryW(system_dir, MAX_PATH);
    if (!system_size || system_size >= MAX_PATH) return 0;

    if (!system_path_matches(L"SystemRoot", system_dir) ||
        !system_path_matches(L"WINDIR", system_dir)) {
        fputs("AppContainer lost a required trusted system path.\n", stderr);
        return 0;
    }
    SetLastError(ERROR_SUCCESS);
    if (GetEnvironmentVariableW(L"SGW_WIN_FIXTURE_PARENT_CANARY", value, MAX_PATH) != 0 ||
        GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
        fputs("AppContainer inherited the broker environment canary.\n", stderr);
        return 0;
    }

    wchar_t current_dir[MAX_PATH], executable[MAX_PATH];
    DWORD current_size = GetCurrentDirectoryW(MAX_PATH, current_dir);
    DWORD executable_size = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (!current_size || current_size >= MAX_PATH || !executable_size || executable_size >= MAX_PATH) return 0;
    wchar_t *last_slash = wcsrchr(executable, L'\\');
    if (!last_slash) return 0;
    *last_slash = 0;
    if (_wcsicmp(current_dir, executable) != 0) {
        fputs("AppContainer inherited the broker working directory.\n", stderr);
        return 0;
    }
    return 1;
}

static int process_handle_denied(const wchar_t *pid_text, const char *target) {
    wchar_t *end = NULL;
    errno = 0;
    unsigned long pid = wcstoul(pid_text, &end, 10);
    if (errno == ERANGE || end == pid_text || *end || !pid) {
        fprintf(stderr, "Invalid %s process ID.\n", target);
        return 0;
    }
    HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);
    if (process) {
        CloseHandle(process);
        fprintf(stderr, "AppContainer acquired PROCESS_DUP_HANDLE for %s.\n", target);
        return 0;
    }
    DWORD error = GetLastError();
    if (error == ERROR_ACCESS_DENIED) return 1;
    fprintf(stderr, "AppContainer %s process probe failed unexpectedly: %lu\n", target, error);
    return 0;
}

static int job_control_denied(const wchar_t *job_name) {
    const DWORD rights[] = {
        JOB_OBJECT_QUERY, JOB_OBJECT_ASSIGN_PROCESS, JOB_OBJECT_SET_ATTRIBUTES,
        JOB_OBJECT_TERMINATE, WRITE_DAC, WRITE_OWNER
    };
    for (size_t i = 0; i < sizeof(rights) / sizeof(rights[0]); i++) {
        HANDLE job = OpenJobObjectW(rights[i], FALSE, job_name);
        if (job) {
            CloseHandle(job);
            fprintf(stderr, "AppContainer opened the launcher Job with rights 0x%08lx.\n",
                (unsigned long)rights[i]);
            return 0;
        }
        DWORD error = GetLastError();
        if (error != ERROR_ACCESS_DENIED) {
            fprintf(stderr, "AppContainer Job access failed unexpectedly: %lu\n", error);
            return 0;
        }
    }
    return 1;
}

static int connected_pipe_transfer_denied(HANDLE pipe, const wchar_t *pid_text) {
    wchar_t *end = NULL;
    errno = 0;
    unsigned long pid = wcstoul(pid_text, &end, 10);
    if (errno == ERANGE || end == pid_text || *end || !pid) return 0;
    HANDLE target = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)pid);
    if (!target) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) return 1;
        fprintf(stderr, "Connected-pipe transfer target could not be opened: %lu\n", error);
        return 0;
    }
    HANDLE copy = NULL;
    BOOL transferred = DuplicateHandle(GetCurrentProcess(), pipe, target, &copy, 0,
        FALSE, DUPLICATE_SAME_ACCESS);
    DWORD error = transferred ? ERROR_SUCCESS : GetLastError();
    CloseHandle(target);
    if (transferred) {
        fputs("AppContainer copied its connected broker pipe outside the Job.\n", stderr);
        return 0;
    }
    if (error == ERROR_ACCESS_DENIED) return 1;
    fprintf(stderr, "Connected-pipe duplication failed unexpectedly: %lu\n", error);
    return 0;
}

static int run_client(const wchar_t *pipe_name, const wchar_t *ipv4_port,
    const wchar_t *ipv6_port, const wchar_t *shared_path,
    const wchar_t *canary_path, const wchar_t *profile, const wchar_t *job_name,
    const wchar_t *other_agent_pid, const wchar_t *broker_pid,
    const wchar_t *transfer_target_pid) {
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
    if (!agent_environment_is_clean()) return 1;
    if (!job_control_denied(job_name)) return 1;
    if (other_agent_pid) {
        int other_denied = process_handle_denied(other_agent_pid, "other agent");
        int broker_denied = process_handle_denied(broker_pid, "broker");
        return other_denied && broker_denied ? 0 : 1;
    }
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
    if (transfer_target_pid && !connected_pipe_transfer_denied(pipe, transfer_target_pid)) {
        CloseHandle(pipe);
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

static HANDLE create_private_job(const wchar_t *name) {
    HANDLE token = NULL;
    DWORD size = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    HANDLE job = NULL;
    DWORD status = ERROR_SUCCESS;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (!size || size > 4096) goto done;
    user = malloc(size);
    if (!user || !GetTokenInformation(token, TokenUser, user, size, &size) ||
        !ConvertSidToStringSidW(user->User.Sid, &sid)) goto done;

    wchar_t sddl[512];
    int length = swprintf(sddl, sizeof(sddl) / sizeof(sddl[0]),
        L"D:P(A;;GA;;;SY)(A;;GA;;;%ls)(A;;RC;;;OW)", sid);
    if (length < 1 || (size_t)length >= sizeof(sddl) / sizeof(sddl[0]) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
            &descriptor, NULL)) goto done;
    SECURITY_ATTRIBUTES security = { sizeof(security), descriptor, FALSE };
    job = CreateJobObjectW(&security, name);

done:
    status = GetLastError();
    if (descriptor) LocalFree(descriptor);
    if (sid) LocalFree(sid);
    free(user);
    CloseHandle(token);
    SetLastError(status);
    return job;
}

static int launch_client(const wchar_t *name, const wchar_t *pipe_name,
    const wchar_t *ipv4_port, const wchar_t *ipv6_port,
    const wchar_t *shared_path, const wchar_t *canary_path, const wchar_t *job_name,
    int stop_job, int pause_start, int without_job,
    const wchar_t *other_agent_pid, const wchar_t *broker_pid,
    const wchar_t *transfer_target_pid) {
    wchar_t parent_canary[64];
    DWORD canary_size = GetEnvironmentVariableW(L"SGW_WIN_FIXTURE_PARENT_CANARY",
        parent_canary, sizeof(parent_canary) / sizeof(parent_canary[0]));
    if (canary_size != 32) {
        fputs("The fixture launcher has no parent environment canary.\n", stderr);
        return 1;
    }
    PSID sid = NULL;
    SGW_WFP_BOUNDARY wfp = { 0 };
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
    wchar_t agent_dir[MAX_PATH];
    wmemcpy(agent_dir, executable, length + 1);
    wchar_t *last_slash = wcsrchr(agent_dir, L'\\');
    if (!last_slash) goto done;
    *last_slash = 0;

    wchar_t system_dir[MAX_PATH];
    DWORD system_size = GetSystemWindowsDirectoryW(system_dir, MAX_PATH);
    if (!system_size || system_size >= MAX_PATH) goto done;
    wchar_t environment[MAX_PATH * 2 + 32];
    size_t environment_size = sizeof(environment) / sizeof(environment[0]);
    int root_size = swprintf(environment, environment_size, L"SystemRoot=%ls", system_dir);
    if (root_size < 0 || (size_t)root_size + 2 >= environment_size) goto done;
    int windir_size = swprintf(environment + root_size + 1,
        environment_size - (size_t)root_size - 1, L"WINDIR=%ls", system_dir);
    if (windir_size < 0 || (size_t)root_size + (size_t)windir_size + 2 >= environment_size) goto done;
    environment[root_size + windir_size + 2] = 0;

    wchar_t command[MAX_PATH * 4 + 256];
    if (other_agent_pid) {
        if (swprintf(command, sizeof(command) / sizeof(command[0]),
            L"\"%ls\" client \"%ls\" %ls %ls \"%ls\" \"%ls\" \"%ls\" \"%ls\" %ls %ls",
            executable, pipe_name, ipv4_port, ipv6_port, shared_path, canary_path,
            name, job_name, other_agent_pid, broker_pid) < 0) goto done;
    } else if (transfer_target_pid) {
        if (swprintf(command, sizeof(command) / sizeof(command[0]),
            L"\"%ls\" client-transfer \"%ls\" %ls %ls \"%ls\" \"%ls\" \"%ls\" \"%ls\" %ls",
            executable, pipe_name, ipv4_port, ipv6_port, shared_path, canary_path,
            name, job_name, transfer_target_pid) < 0) goto done;
    } else if (swprintf(command, sizeof(command) / sizeof(command[0]),
        L"\"%ls\" client \"%ls\" %ls %ls \"%ls\" \"%ls\" \"%ls\" \"%ls\"",
        executable, pipe_name, ipv4_port, ipv6_port, shared_path, canary_path, name, job_name) < 0) goto done;

    STARTUPINFOEXW startup = { 0 };
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attrs;
    PROCESS_INFORMATION process = { 0 };
    HANDLE job = NULL;
    if (without_job) {
        job = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, job_name);
        if (!job) goto done;
    } else {
        job = create_private_job(job_name);
        if (!job || GetLastError() == ERROR_ALREADY_EXISTS) {
            if (job) CloseHandle(job);
            goto done;
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            CloseHandle(job);
            goto done;
        }
    }
    DWORD wfp_error = sgw_wfp_start(sid, &wfp);
    if (wfp_error != ERROR_SUCCESS) {
        fprintf(stderr, "AppContainer WFP deny setup failed: 0x%08lx\n", (unsigned long)wfp_error);
        CloseHandle(job);
        goto done;
    }
    if (!sgw_wfp_healthy(&wfp)) {
        fputs("AppContainer WFP deny disappeared before launch.\n", stderr);
        CloseHandle(job);
        goto done;
    }
    if (!CreateProcessW(executable, command, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        environment, agent_dir,
        &startup.StartupInfo, &process)) {
        fprintf(stderr, "AppContainer process launch failed: %lu\n", GetLastError());
        CloseHandle(job);
        goto done;
    }
    BOOL assigned = FALSE;
    if ((!without_job && !AssignProcessToJobObject(job, process.hProcess)) ||
        !IsProcessInJob(process.hProcess, job, &assigned) ||
        (!without_job && !assigned) || (without_job && assigned)) {
        fprintf(stderr, "AppContainer job assignment failed: %lu\n", GetLastError());
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        goto done;
    }
    if (without_job) {
        puts("OUT-OF-JOB-ATTESTED");
        fflush(stdout);
    }
    if (pause_start) {
        puts("WFP-READY");
        puts("JOB-READY");
        fflush(stdout);
    }
    if (!other_agent_pid && !stop_job && !without_job) {
        printf("CHILD-PID=%lu\n", (unsigned long)process.dwProcessId);
        fflush(stdout);
    }
    if (pause_start) {
        char signal = 0;
        DWORD amount = 0;
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        if (input == INVALID_HANDLE_VALUE || !ReadFile(input, &signal, 1, &amount, NULL) ||
            amount != 1 || signal != 'G') {
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
            goto done;
        }
    }
    if (ResumeThread(process.hThread) == (DWORD)-1) {
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
        DWORD waited = WAIT_TIMEOUT;
        for (int i = 0; i < 120 && waited == WAIT_TIMEOUT; i++) {
            waited = WaitForSingleObject(process.hProcess, 250);
            if (waited == WAIT_TIMEOUT && !sgw_wfp_healthy(&wfp)) {
                fputs("AppContainer WFP deny disappeared during execution.\n", stderr);
                TerminateJobObject(job, 1);
                break;
            }
        }
        if (waited != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 1);
        else if (GetExitCodeProcess(process.hProcess, &exit_code) && exit_code == 0) result = 0;
    }
    if (result) fprintf(stderr, "AppContainer child failed: %lu\n", (unsigned long)exit_code);
    if (other_agent_pid && !result) puts("PROCESS-DUP-DENIED");
    if (transfer_target_pid && !result) puts("CONNECTED-PIPE-TRANSFER-DENIED");
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (job) CloseHandle(job);

done:
    sgw_wfp_stop(&wfp);
    if (initialized) DeleteProcThreadAttributeList(attrs);
    free(attrs);
    FreeSid(sid);
    return result;
}

static int hold_empty_job(const wchar_t *name, DWORD flags) {
    HANDLE job = create_private_job(name);
    if (!job) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(job);
        return 1;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = { 0 };
    limits.BasicLimitInformation.LimitFlags = flags;
    if (flags && !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return 1;
    }
    puts("JOB-READY");
    fflush(stdout);
    char signal;
    DWORD amount = 0;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (input != INVALID_HANDLE_VALUE) ReadFile(input, &signal, 1, &amount, NULL);
    CloseHandle(job);
    return 0;
}

static int test_wfp_revocation(const wchar_t *first_profile, const wchar_t *second_profile) {
    PSID first_sid = NULL, second_sid = NULL;
    if (FAILED(DeriveAppContainerSidFromAppContainerName(first_profile, &first_sid)) ||
        FAILED(DeriveAppContainerSidFromAppContainerName(second_profile, &second_sid))) {
        if (first_sid) FreeSid(first_sid);
        if (second_sid) FreeSid(second_sid);
        return 1;
    }
    if (EqualSid(first_sid, second_sid)) {
        FreeSid(first_sid);
        FreeSid(second_sid);
        return 1;
    }
    SGW_WFP_BOUNDARY first = { 0 }, second = { 0 };
    DWORD result = sgw_wfp_start(first_sid, &first);
    if (result == ERROR_SUCCESS) result = sgw_wfp_start(second_sid, &second);
    FreeSid(first_sid);
    FreeSid(second_sid);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "WFP policy self-test setup failed: 0x%08lx\n", (unsigned long)result);
        sgw_wfp_stop(&first);
        return 1;
    }
    int healthy = sgw_wfp_healthy(&first) && sgw_wfp_healthy(&second);
    result = FwpmFilterDeleteById0(first.engine, first.filters[0]);
    int revoked = healthy && result == ERROR_SUCCESS &&
        !sgw_wfp_healthy(&first) && sgw_wfp_healthy(&second);
    UINT64 second_filter = second.filters[0];
    sgw_wfp_stop(&first);
    if (revoked) revoked = sgw_wfp_healthy(&second);
    sgw_wfp_stop(&second);
    HANDLE audit_engine = NULL;
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &audit_engine);
    if (result == ERROR_SUCCESS) {
        FWPM_FILTER0 *leftover = NULL;
        result = FwpmFilterGetById0(audit_engine, second_filter, &leftover);
        if (leftover) FwpmFreeMemory0((void **)&leftover);
        if (result != (DWORD)FWP_E_FILTER_NOT_FOUND) revoked = 0;
        FwpmEngineClose0(audit_engine);
    } else revoked = 0;
    if (!revoked) {
        fputs("WFP deletion did not revoke only the selected package boundary.\n", stderr);
        return 1;
    }
    puts("WFP-REVOCATION-DETECTED");
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"create") == 0) return create_profile(argv[2]);
    if (argc == 3 && wcscmp(argv[1], L"delete") == 0) {
        HRESULT status = DeleteAppContainerProfile(argv[2]);
        if (FAILED(status)) fprintf(stderr, "DeleteAppContainerProfile failed: 0x%08lx\n", (unsigned long)status);
        return FAILED(status) ? 1 : 0;
    }
    if (argc == 3 && wcscmp(argv[1], L"job-host") == 0)
        return hold_empty_job(argv[2], JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE);
    if (argc == 4 && wcscmp(argv[1], L"wfp-selftest") == 0)
        return test_wfp_revocation(argv[2], argv[3]);
    if (argc == 3 && wcscmp(argv[1], L"job-host-breakaway") == 0)
        return hold_empty_job(argv[2], JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK);
    if (argc == 3 && wcscmp(argv[1], L"job-host-no-kill") == 0)
        return hold_empty_job(argv[2], 0);
    if ((argc == 9 || argc == 11) && wcscmp(argv[1], L"client") == 0)
        return run_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            argc == 11 ? argv[9] : NULL, argc == 11 ? argv[10] : NULL, NULL);
    if (argc == 10 && wcscmp(argv[1], L"client-transfer") == 0)
        return run_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            NULL, NULL, argv[9]);
    if (argc == 9 && wcscmp(argv[1], L"launch") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            0, 0, 0, NULL, NULL, NULL);
    if (argc == 9 && (wcscmp(argv[1], L"launch-paused") == 0 ||
        wcscmp(argv[1], L"launch-stop-paused") == 0))
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            wcscmp(argv[1], L"launch-stop-paused") == 0, 1, 0, NULL, NULL, NULL);
    if (argc == 9 && wcscmp(argv[1], L"launch-unassigned") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            0, 0, 1, NULL, NULL, NULL);
    if (argc == 11 && wcscmp(argv[1], L"launch-process-probe") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            0, 0, 0, argv[9], argv[10], NULL);
    if (argc == 10 && wcscmp(argv[1], L"launch-transfer-paused") == 0)
        return launch_client(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8],
            0, 1, 0, NULL, NULL, argv[9]);
    return 1;
}
