#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int wmain(void) {
    HANDLE marker = CreateFileW(L"marker.txt", GENERIC_WRITE, 0, NULL, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) return 1;
    DWORD written = 0;
    BOOL saved = WriteFile(marker, "ran", 3, &written, NULL) && written == 3 &&
        FlushFileBuffers(marker);
    CloseHandle(marker);
    return saved ? 0 : 1;
}
