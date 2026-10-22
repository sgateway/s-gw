#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <wctype.h>

#define ROOT_METADATA_RIGHTS (FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE)
#define DACL_CONTROL_BITS (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_PROTECTED | \
    SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ)

static int system_root(wchar_t root[4]) {
    wchar_t windows_dir[MAX_PATH];
    DWORD size = GetSystemWindowsDirectoryW(windows_dir, MAX_PATH);
    if (size < 3 || size >= MAX_PATH || windows_dir[1] != L':' || windows_dir[2] != L'\\') return 0;
    root[0] = towupper(windows_dir[0]);
    root[1] = L':';
    root[2] = L'\\';
    root[3] = 0;
    return 1;
}

static PSECURITY_DESCRIPTOR read_security(const wchar_t *path) {
    DWORD size = 0;
    GetFileSecurityW(path, DACL_SECURITY_INFORMATION, NULL, 0, &size);
    if (!size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return NULL;
    PSECURITY_DESCRIPTOR descriptor = malloc(size);
    if (!descriptor) return NULL;
    if (!GetFileSecurityW(path, DACL_SECURITY_INFORMATION, descriptor, size, &size)) {
        free(descriptor);
        return NULL;
    }
    return descriptor;
}

static PACL descriptor_dacl(PSECURITY_DESCRIPTOR descriptor) {
    BOOL present = FALSE, defaulted = FALSE;
    PACL dacl = NULL;
    if (!descriptor || !GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) ||
        !present || !dacl) return NULL;
    return dacl;
}

static int group_ace_state(PACL dacl, PSID sid) {
    int found = 0;
    for (DWORD i = 0; i < dacl->AceCount; i++) {
        void *entry = NULL;
        if (!GetAce(dacl, i, &entry)) return -1;
        ACE_HEADER *header = entry;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE && header->AceType != ACCESS_DENIED_ACE_TYPE)
            continue;
        ACCESS_ALLOWED_ACE *ace = entry;
        if (!EqualSid((PSID)&ace->SidStart, sid)) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || header->AceFlags != 0 ||
            ace->Mask != ROOT_METADATA_RIGHTS || found) return -1;
        found = 1;
    }
    return found;
}

static int print_security(const char *label, const wchar_t *path,
    PSECURITY_DESCRIPTOR descriptor) {
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    LPWSTR sddl = NULL;
    if (!GetSecurityDescriptorControl(descriptor, &control, &revision) ||
        !ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &sddl, NULL)) return 0;
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, sddl, -1, NULL, 0, NULL, NULL);
    char *utf8 = size > 1 ? malloc((size_t)size) : NULL;
    int success = utf8 && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        sddl, -1, utf8, size, NULL, NULL);
    DWORD serial = 0;
    wchar_t file_system[32];
    success = success && GetVolumeInformationW(path, NULL, 0, &serial, NULL, NULL,
        file_system, sizeof(file_system) / sizeof(file_system[0]));
    if (success) {
        printf("%s-ROOT=%lc:%c\n", label, path[0], '\\');
        printf("%s-SERIAL=%08lx\n", label, (unsigned long)serial);
        printf("%s-CONTROL=%04x\n", label, (unsigned)(control & DACL_CONTROL_BITS));
        printf("%s-DACL=%s\n", label, utf8);
    }
    free(utf8);
    LocalFree(sddl);
    return success;
}

static int metadata_ready(PSECURITY_DESCRIPTOR descriptor,
    PSID app_packages, PSID restricted_packages) {
    PACL dacl = descriptor_dacl(descriptor);
    return dacl && group_ace_state(dacl, app_packages) == 1 &&
        group_ace_state(dacl, restricted_packages) == 1;
}

static int fixed_local_volume(const wchar_t *root) {
    wchar_t file_system[32];
    DWORD attributes = GetFileAttributesW(root);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) || GetDriveTypeW(root) != DRIVE_FIXED ||
        !GetVolumeInformationW(root, NULL, 0, NULL, NULL, NULL,
            file_system, sizeof(file_system) / sizeof(file_system[0]))) return 0;
    return _wcsicmp(file_system, L"NTFS") == 0 || _wcsicmp(file_system, L"ReFS") == 0;
}

static int inspect_roots(const wchar_t *test_root) {
    wchar_t system[4];
    if (!system_root(system) || !fixed_local_volume(system)) {
        fputs("The Windows system drive is not a local fixed NTFS/ReFS volume.\n", stderr);
        return 1;
    }
    if (test_root && (wcslen(test_root) != 3 || !iswalpha(test_root[0]) ||
        test_root[1] != L':' || test_root[2] != L'\\' ||
        towupper(test_root[0]) == system[0] || !fixed_local_volume(test_root))) {
        fputs("Native acceptance needs a separate local fixed NTFS/ReFS volume root.\n", stderr);
        return 1;
    }
    PSECURITY_DESCRIPTOR system_acl = read_security(system);
    PSECURITY_DESCRIPTOR test_acl = test_root ? read_security(test_root) : NULL;
    PSID app_packages = NULL, restricted_packages = NULL;
    int result = 1;
    if (!system_acl || (test_root && !test_acl)) {
        fputs("Could not read a required root DACL.\n", stderr);
        goto done;
    }
    if (!ConvertStringSidToSidW(L"S-1-15-2-1", &app_packages) ||
        !ConvertStringSidToSidW(L"S-1-15-2-2", &restricted_packages) ||
        !print_security("SYSTEM", system, system_acl) ||
        (test_root && !print_security("TEST", test_root, test_acl))) goto done;
    if (test_root && (!metadata_ready(system_acl, app_packages, restricted_packages) ||
        !metadata_ready(test_acl, app_packages, restricted_packages))) {
        fputs("Prepared roots lack exact AppContainer metadata ACEs; no ACL was changed.\n", stderr);
        goto done;
    }
    if (test_root) puts("ROOT-READY");
    result = 0;

done:
    if (app_packages) LocalFree(app_packages);
    if (restricted_packages) LocalFree(restricted_packages);
    free(test_acl);
    free(system_acl);
    return result;
}

static int read_null_acl(void) {
    HANDLE device = CreateFileW(L"\\\\.\\NUL", READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) return 1;
    DWORD size = 0;
    GetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION, NULL, 0, &size);
    PSECURITY_DESCRIPTOR descriptor = size && GetLastError() == ERROR_INSUFFICIENT_BUFFER
        ? malloc(size) : NULL;
    LPWSTR sddl = NULL;
    int result = 1;
    if (!descriptor || !GetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION,
        descriptor, size, &size) ||
        !ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &sddl, NULL)) goto done;
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, sddl, -1, NULL, 0, NULL, NULL);
    char *utf8 = bytes > 1 ? malloc((size_t)bytes) : NULL;
    if (!utf8 || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
        sddl, -1, utf8, bytes, NULL, NULL)) {
        free(utf8);
        goto done;
    }
    printf("NUL-DACL=%s\n", utf8);
    free(utf8);
    result = 0;

done:
    if (result) fprintf(stderr, "NUL device DACL read failed: %lu\n", GetLastError());
    if (sddl) LocalFree(sddl);
    free(descriptor);
    CloseHandle(device);
    return result;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"root-snapshot") == 0) return inspect_roots(NULL);
    if (argc == 3 && wcscmp(argv[1], L"prepared-host") == 0) return inspect_roots(argv[2]);
    if (argc == 2 && wcscmp(argv[1], L"null-acl") == 0) return read_null_acl();
    return 1;
}
