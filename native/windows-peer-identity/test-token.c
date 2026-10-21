#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    LPSTR sid = NULL;
    TOKEN_STATISTICS stats;
    DWORD session = 0, appcontainer = 1, size = 0;
    int result = 1;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    if (!size || size > 4096) goto done;
    user = malloc(size);
    if (!user || !GetTokenInformation(token, TokenUser, user, size, &size)) goto done;
    if (!ConvertSidToStringSidA(user->User.Sid, &sid)) goto done;
    if (!GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &size) ||
        !GetTokenInformation(token, TokenSessionId, &session, sizeof(session), &size) ||
        !GetTokenInformation(token, TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size)) goto done;

    printf("%s\n%08lx%08lx\n%lu\n%lu\n", sid,
        (unsigned long)(DWORD)stats.AuthenticationId.HighPart,
        (unsigned long)stats.AuthenticationId.LowPart,
        (unsigned long)session, (unsigned long)appcontainer);
    result = 0;

done:
    if (sid) LocalFree(sid);
    free(user);
    if (token) CloseHandle(token);
    return result;
}
