#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

#define MAX_MESSAGE 32768
#define CLIENT_PIPE_RIGHTS (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)

static int numeric_sid(const wchar_t *value) {
    size_t size = wcslen(value);
    if (size < 5 || size > 183 || wcsncmp(value, L"S-1-", 4) != 0) return 0;
    for (size_t i = 2; i < size; i++) {
        if ((value[i] < L'0' || value[i] > L'9') && value[i] != L'-') return 0;
    }
    PSID sid = NULL;
    int valid = ConvertStringSidToSidW(value, &sid) && IsValidSid(sid);
    if (sid) LocalFree(sid);
    return valid;
}

static int pipe_name_ok(const wchar_t *name) {
    const wchar_t *prefix = L"\\\\.\\pipe\\LOCAL\\s-gw-";
    size_t prefix_size = wcslen(prefix);
    if (wcsncmp(name, prefix, prefix_size) != 0 || wcslen(name) != prefix_size + 32) return 0;
    for (const wchar_t *item = name + prefix_size; *item; item++) {
        if ((*item < L'0' || *item > L'9') && (*item < L'a' || *item > L'f')) return 0;
    }
    return 1;
}

static int parse_luid(const wchar_t *value, LUID *result) {
    if (wcslen(value) != 16) return 0;
    unsigned long long number = 0;
    for (const wchar_t *item = value; *item; item++) {
        unsigned digit;
        if (*item >= L'0' && *item <= L'9') digit = (unsigned)(*item - L'0');
        else if (*item >= L'a' && *item <= L'f') digit = (unsigned)(*item - L'a') + 10;
        else if (*item >= L'A' && *item <= L'F') digit = (unsigned)(*item - L'A') + 10;
        else return 0;
        number = (number << 4) | digit;
    }
    result->HighPart = (LONG)(number >> 32);
    result->LowPart = (DWORD)number;
    return 1;
}

static int parse_session(const wchar_t *value, DWORD *result) {
    unsigned long long number = 0;
    if (!*value) return 0;
    for (const wchar_t *item = value; *item; item++) {
        if (*item < L'0' || *item > L'9') return 0;
        number = number * 10 + (unsigned)(*item - L'0');
        if (number > 0xffffffffULL) return 0;
    }
    *result = (DWORD)number;
    return 1;
}

static void *get_token_info(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD needed = 0;
    GetTokenInformation(token, kind, NULL, 0, &needed);
    if (needed == 0 || needed > 4096) return NULL;
    void *info = LocalAlloc(LMEM_FIXED, needed);
    if (!info) return NULL;
    if (!GetTokenInformation(token, kind, info, needed, &needed)) {
        LocalFree(info);
        return NULL;
    }
    return info;
}

static int current_broker_is(PSID broker_sid) {
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    TOKEN_USER *user = get_token_info(token, TokenUser);
    DWORD is_appcontainer = 1;
    DWORD size = 0;
    int matches = user && EqualSid(user->User.Sid, broker_sid) &&
        GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer, sizeof(is_appcontainer), &size) &&
        is_appcontainer == 0;
    if (user) LocalFree(user);
    CloseHandle(token);
    return matches;
}

static int client_is(HANDLE pipe, PSID user_sid, PSID package_sid, LUID logon, DWORD session) {
    if (!ImpersonateNamedPipeClient(pipe)) return 0;

    HANDLE token = NULL;
    int matches = 0;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        SECURITY_IMPERSONATION_LEVEL level;
        DWORD size = 0;
        DWORD is_appcontainer = 0;
        DWORD token_session = 0;
        TOKEN_USER *user = get_token_info(token, TokenUser);
        TOKEN_STATISTICS *stats = get_token_info(token, TokenStatistics);
        TOKEN_APPCONTAINER_INFORMATION *package = package_sid
            ? get_token_info(token, TokenAppContainerSid) : NULL;
        int queried = GetTokenInformation(token, TokenImpersonationLevel, &level, sizeof(level), &size) &&
            GetTokenInformation(token, TokenIsAppContainer, &is_appcontainer, sizeof(is_appcontainer), &size) &&
            GetTokenInformation(token, TokenSessionId, &token_session, sizeof(token_session), &size);
        matches = queried && level >= SecurityImpersonation && user && stats &&
            EqualSid(user->User.Sid, user_sid) && token_session == session &&
            stats->AuthenticationId.HighPart == logon.HighPart &&
            stats->AuthenticationId.LowPart == logon.LowPart &&
            ((package_sid && is_appcontainer == 1 && package && package->TokenAppContainer &&
                EqualSid(package->TokenAppContainer, package_sid)) ||
             (!package_sid && is_appcontainer == 0));
        if (package) LocalFree(package);
        if (stats) LocalFree(stats);
        if (user) LocalFree(user);
        CloseHandle(token);
    }

    if (!RevertToSelf()) ExitProcess(4);
    return matches;
}

static int write_all(HANDLE output, const void *buffer, DWORD size) {
    const BYTE *next = buffer;
    while (size) {
        DWORD written = 0;
        if (!WriteFile(output, next, size, &written, NULL) || written == 0) return 0;
        next += written;
        size -= written;
    }
    return 1;
}

static int read_all(HANDLE input, void *buffer, DWORD size) {
    BYTE *next = buffer;
    while (size) {
        DWORD amount = 0;
        if (!ReadFile(input, next, size, &amount, NULL) || amount == 0) return 0;
        next += amount;
        size -= amount;
    }
    return 1;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 7 || !pipe_name_ok(argv[1]) || !numeric_sid(argv[2]) ||
        !numeric_sid(argv[3]) || (wcscmp(argv[4], L"-") != 0 && !numeric_sid(argv[4]))) return 1;

    LUID logon;
    DWORD session;
    if (!parse_luid(argv[5], &logon) || !parse_session(argv[6], &session)) return 1;

    PSID broker_sid = NULL, user_sid = NULL, package_sid = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    HANDLE pipe = INVALID_HANDLE_VALUE;
    int status = 1;
    if (!ConvertStringSidToSidW(argv[2], &broker_sid) ||
        !ConvertStringSidToSidW(argv[3], &user_sid)) goto done;
    if (wcscmp(argv[4], L"-") != 0 && !ConvertStringSidToSidW(argv[4], &package_sid)) goto done;
    if (!package_sid && EqualSid(broker_sid, user_sid)) goto done;
    if (!current_broker_is(broker_sid)) goto done;

    wchar_t sddl[1024];
    int size = package_sid
        ? swprintf(sddl, 1024,
            L"D:P(A;;FA;;;SY)(A;;FA;;;%ls)(A;;0x%08lx;;;%ls)(A;;0x%08lx;;;%ls)S:(ML;;NW;;;LW)",
            argv[2], CLIENT_PIPE_RIGHTS, argv[3], CLIENT_PIPE_RIGHTS, argv[4])
        : swprintf(sddl, 1024,
            L"D:P(A;;FA;;;SY)(A;;FA;;;%ls)(A;;0x%08lx;;;%ls)S:(ML;;NW;;;LW)",
            argv[2], CLIENT_PIPE_RIGHTS, argv[3]);
    if (size <= 0 || !ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &descriptor, NULL)) goto done;

    SECURITY_ATTRIBUTES security = { sizeof(security), descriptor, FALSE };
    pipe = CreateNamedPipeW(argv[1], PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, MAX_MESSAGE, MAX_MESSAGE, 0, &security);
    if (pipe == INVALID_HANDLE_VALUE) goto done;

    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (output == INVALID_HANDLE_VALUE || !write_all(output, "R", 1)) goto done;
    if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) goto done;

    BYTE request[MAX_MESSAGE + 1];
    DWORD request_size = 0;
    if (!ReadFile(pipe, request, sizeof(request), &request_size, NULL) ||
        request_size == 0 || request_size > MAX_MESSAGE) goto done;
    if (!client_is(pipe, user_sid, package_sid, logon, session)) goto done;

    if (!write_all(output, "Q", 1) ||
        !write_all(output, &request_size, sizeof(request_size)) ||
        !write_all(output, request, request_size)) goto done;

    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    BYTE header[5];
    if (input == INVALID_HANDLE_VALUE || !read_all(input, header, sizeof(header)) || header[0] != 'S') goto done;
    DWORD response_size = (DWORD)header[1] | ((DWORD)header[2] << 8) |
        ((DWORD)header[3] << 16) | ((DWORD)header[4] << 24);
    if (response_size == 0 || response_size > MAX_MESSAGE) goto done;
    BYTE response[MAX_MESSAGE];
    if (!read_all(input, response, response_size)) goto done;
    DWORD written = 0;
    if (!WriteFile(pipe, response, response_size, &written, NULL) || written != response_size) goto done;
    status = 0;

done:
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    if (descriptor) LocalFree(descriptor);
    if (package_sid) LocalFree(package_sid);
    if (user_sid) LocalFree(user_sid);
    if (broker_sid) LocalFree(broker_sid);
    return status;
}
