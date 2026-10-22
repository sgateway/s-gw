#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

#define ROOT_METADATA_RIGHTS (FILE_READ_ATTRIBUTES | FILE_READ_EA | READ_CONTROL | SYNCHRONIZE)
#define DACL_CONTROL_BITS (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_DACL_PROTECTED | \
    SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ)

static int system_root(wchar_t root[4]) {
    wchar_t windows_dir[MAX_PATH];
    DWORD size = GetSystemWindowsDirectoryW(windows_dir, MAX_PATH);
    if (size < 3 || size >= MAX_PATH || windows_dir[1] != L':' || windows_dir[2] != L'\\') return 0;
    root[0] = windows_dir[0];
    root[1] = L':';
    root[2] = L'\\';
    root[3] = 0;
    return 1;
}

static PSECURITY_DESCRIPTOR read_root_security(const wchar_t *root) {
    DWORD size = 0;
    GetFileSecurityW(root, DACL_SECURITY_INFORMATION, NULL, 0, &size);
    if (!size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) return NULL;
    PSECURITY_DESCRIPTOR descriptor = malloc(size);
    if (!descriptor) return NULL;
    if (!GetFileSecurityW(root, DACL_SECURITY_INFORMATION, descriptor, size, &size)) {
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

static int dacl_matches(PACL expected, PACL actual) {
    if (!expected || !actual || expected->AceCount != actual->AceCount ||
        expected->AclRevision != actual->AclRevision) return 0;
    for (DWORD i = 0; i < expected->AceCount; i++) {
        void *left = NULL, *right = NULL;
        if (!GetAce(expected, i, &left) || !GetAce(actual, i, &right)) return 0;
        ACE_HEADER *left_header = left, *right_header = right;
        if (left_header->AceSize != right_header->AceSize ||
            memcmp(left, right, left_header->AceSize) != 0) return 0;
    }
    return 1;
}

static int dacl_state_matches(PSECURITY_DESCRIPTOR baseline, PACL expected,
    PSECURITY_DESCRIPTOR actual) {
    SECURITY_DESCRIPTOR_CONTROL baseline_control = 0, actual_control = 0;
    DWORD baseline_revision = 0, actual_revision = 0;
    return GetSecurityDescriptorControl(baseline, &baseline_control, &baseline_revision) &&
        GetSecurityDescriptorControl(actual, &actual_control, &actual_revision) &&
        (baseline_control & DACL_CONTROL_BITS) == (actual_control & DACL_CONTROL_BITS) &&
        dacl_matches(expected, descriptor_dacl(actual));
}

static void report_dacl_difference(const char *stage, PSECURITY_DESCRIPTOR baseline,
    PACL expected, PSECURITY_DESCRIPTOR actual) {
    SECURITY_DESCRIPTOR_CONTROL before = 0, after = 0;
    DWORD revision = 0;
    GetSecurityDescriptorControl(baseline, &before, &revision);
    if (!actual || !GetSecurityDescriptorControl(actual, &after, &revision)) {
        fprintf(stderr, "%s: system-drive DACL readback unavailable (expected control 0x%04x).\n",
            stage, (unsigned)(before & DACL_CONTROL_BITS));
        return;
    }
    fprintf(stderr, "%s: DACL control expected 0x%04x, actual 0x%04x.\n",
        stage, (unsigned)(before & DACL_CONTROL_BITS),
        (unsigned)(after & DACL_CONTROL_BITS));
    PACL observed = descriptor_dacl(actual);
    if (!expected || !observed) {
        fprintf(stderr, "%s: DACL missing in readback.\n", stage);
        return;
    }
    if (expected->AclRevision != observed->AclRevision ||
        expected->AceCount != observed->AceCount) {
        fprintf(stderr, "%s: ACL revision/count expected %u/%u, actual %u/%u.\n", stage,
            (unsigned)expected->AclRevision, (unsigned)expected->AceCount,
            (unsigned)observed->AclRevision, (unsigned)observed->AceCount);
    }
    DWORD shared = expected->AceCount < observed->AceCount
        ? expected->AceCount : observed->AceCount;
    for (DWORD i = 0; i < shared; i++) {
        void *left = NULL, *right = NULL;
        if (!GetAce(expected, i, &left) || !GetAce(observed, i, &right)) {
            fprintf(stderr, "%s: ACE %lu could not be inspected.\n", stage, (unsigned long)i);
            return;
        }
        ACE_HEADER *a = left, *b = right;
        if (a->AceSize != b->AceSize || memcmp(a, b, a->AceSize) != 0) {
            fprintf(stderr, "%s: first ACE mismatch at index %lu.\n", stage, (unsigned long)i);
            return;
        }
    }
    if (expected->AceCount != observed->AceCount)
        fprintf(stderr, "%s: first ACE mismatch at index %lu (one ACL ends).\n",
            stage, (unsigned long)shared);
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

static PACL prepared_dacl(PACL original, PSID app_packages, PSID restricted_packages,
    int add_app, int add_restricted) {
    DWORD extra = 0;
    if (add_app) extra += (DWORD)(sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(app_packages));
    if (add_restricted) extra += (DWORD)(sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(restricted_packages));
    if ((DWORD)original->AclSize + extra > 65535) return NULL;
    DWORD size = (DWORD)original->AclSize + extra;
    PACL prepared = malloc(size);
    if (!prepared || !InitializeAcl(prepared, size, original->AclRevision)) {
        free(prepared);
        return NULL;
    }
    for (DWORD i = 0; i < original->AceCount; i++) {
        void *entry = NULL;
        if (!GetAce(original, i, &entry) || !AddAce(prepared, original->AclRevision,
            MAXDWORD, entry, ((ACE_HEADER *)entry)->AceSize)) {
            free(prepared);
            return NULL;
        }
    }
    if ((add_app && !AddAccessAllowedAceEx(prepared, original->AclRevision, 0,
        ROOT_METADATA_RIGHTS, app_packages)) ||
        (add_restricted && !AddAccessAllowedAceEx(prepared, original->AclRevision, 0,
        ROOT_METADATA_RIGHTS, restricted_packages))) {
        free(prepared);
        return NULL;
    }
    return prepared;
}

static int write_root_dacl(const wchar_t *root, PACL dacl, PSECURITY_DESCRIPTOR original) {
    SECURITY_DESCRIPTOR descriptor;
    SECURITY_DESCRIPTOR_CONTROL old_control = 0;
    DWORD revision = 0;
    BOOL present = FALSE, defaulted = FALSE;
    PACL old_dacl = NULL;
    const SECURITY_DESCRIPTOR_CONTROL control_bits =
        SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
    if (!GetSecurityDescriptorControl(original, &old_control, &revision) ||
        !GetSecurityDescriptorDacl(original, &present, &old_dacl, &defaulted) || !present ||
        !InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) ||
        !SetSecurityDescriptorDacl(&descriptor, TRUE, dacl, defaulted) ||
        !SetSecurityDescriptorControl(&descriptor, control_bits, old_control & control_bits)) return 0;
    return SetFileSecurityW(root, DACL_SECURITY_INFORMATION, &descriptor);
}

static int remove_guard_grants(const wchar_t *root, PSECURITY_DESCRIPTOR current,
    PSID app_packages, PSID restricted_packages, int added_app, int added_restricted) {
    PACL existing = descriptor_dacl(current);
    if (!existing) return 0;
    PACL cleaned = malloc(existing->AclSize);
    if (!cleaned || !InitializeAcl(cleaned, existing->AclSize, existing->AclRevision)) {
        free(cleaned);
        return 0;
    }
    int success = 1;
    int found_app = 0, found_restricted = 0;
    for (DWORD i = 0; i < existing->AceCount; i++) {
        void *entry = NULL;
        if (!GetAce(existing, i, &entry)) {
            success = 0;
            break;
        }
        ACE_HEADER *header = entry;
        ACCESS_ALLOWED_ACE *ace = entry;
        int exact_grant = header->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            header->AceFlags == 0 && ace->Mask == ROOT_METADATA_RIGHTS;
        int app_grant = exact_grant && added_app &&
            EqualSid((PSID)&ace->SidStart, app_packages);
        int restricted_grant = exact_grant && added_restricted &&
            EqualSid((PSID)&ace->SidStart, restricted_packages);
        found_app += app_grant;
        found_restricted += restricted_grant;
        int ours = app_grant || restricted_grant;
        if (!ours && !AddAce(cleaned, existing->AclRevision, MAXDWORD, entry, header->AceSize)) {
            success = 0;
            break;
        }
    }
    if (found_app > 1 || found_restricted > 1) {
        fputs("Ambiguous duplicate system-drive metadata grants; refusing cleanup.\n", stderr);
        success = 0;
    }
    if (success && (found_app || found_restricted)) success = write_root_dacl(root, cleaned, current);
    PSECURITY_DESCRIPTOR after = success ? read_root_security(root) : NULL;
    success = success && dacl_state_matches(current, cleaned, after);
    if (!success) report_dacl_difference("Grant removal", current, cleaned, after);
    if (success) fputs("System-drive metadata grants removed; external DACL changes preserved.\n", stderr);
    free(after);
    free(cleaned);
    return success;
}

static int restore_root_dacl(const wchar_t *root, PSECURITY_DESCRIPTOR original,
    PACL old_dacl, PACL prepared, PSECURITY_DESCRIPTOR current,
    PSID app_packages, PSID restricted_packages, int added_app, int added_restricted) {
    if (dacl_state_matches(original, old_dacl, current)) return 1;
    if (current && !dacl_matches(prepared, descriptor_dacl(current))) {
        fputs("System-drive DACL changed outside the guard; preserving the other changes.\n", stderr);
        if (!remove_guard_grants(root, current, app_packages, restricted_packages,
            added_app, added_restricted)) fputs("System-drive grant removal failed.\n", stderr);
        return 0;
    }
    if (!SetFileSecurityW(root, DACL_SECURITY_INFORMATION, original)) {
        fprintf(stderr, "System-drive baseline restore write failed: %lu\n", GetLastError());
    }
    PSECURITY_DESCRIPTOR after = read_root_security(root);
    if (dacl_state_matches(original, old_dacl, after)) {
        free(after);
        return 1;
    }
    report_dacl_difference("Baseline restore", original, old_dacl, after);
    if (after && !dacl_matches(old_dacl, descriptor_dacl(after)) &&
        !remove_guard_grants(root, after, app_packages, restricted_packages,
            added_app, added_restricted)) fputs("System-drive grant removal failed.\n", stderr);
    free(after);
    return 0;
}

static int disposable_dacl_check(const wchar_t *system_drive,
    PSECURITY_DESCRIPTOR root_baseline, PACL root_dacl,
    PSID app_packages, PSID restricted_packages, int add_app, int add_restricted) {
    wchar_t temp_root[MAX_PATH], scratch[MAX_PATH];
    DWORD length = GetTempPathW(MAX_PATH, temp_root);
    if (!length || length >= MAX_PATH) {
        fputs("Could not locate a disposable DACL probe directory.\n", stderr);
        return 0;
    }
    if (temp_root[1] != L':' || towupper(temp_root[0]) != towupper(system_drive[0])) {
        length = GetSystemWindowsDirectoryW(temp_root, MAX_PATH);
        const wchar_t suffix[] = L"\\Temp\\";
        if (!length || length + sizeof(suffix) / sizeof(suffix[0]) > MAX_PATH) return 0;
        memcpy(temp_root + length, suffix, sizeof(suffix));
    }
    if (!GetTempFileNameW(temp_root, L"sgw", 0, scratch)) {
        fputs("Could not create a disposable DACL probe path.\n", stderr);
        return 0;
    }
    int result = 0, file_exists = 1, directory_exists = 0;
    int mirror_attempted = 0, grant_attempted = 0;
    PSECURITY_DESCRIPTOR original = NULL, mirrored = NULL, current = NULL, restored = NULL;
    PACL prepared = NULL, old_dacl = NULL;
    if (!DeleteFileW(scratch)) goto done;
    file_exists = 0;
    if (!CreateDirectoryW(scratch, NULL)) goto done;
    directory_exists = 1;
    original = read_root_security(scratch);
    old_dacl = descriptor_dacl(original);
    if (!old_dacl) goto done;
    mirror_attempted = 1;
    if (!SetFileSecurityW(scratch, DACL_SECURITY_INFORMATION, root_baseline)) {
        fprintf(stderr, "Disposable DACL mirror write failed: %lu\n", GetLastError());
        goto done;
    }
    mirrored = read_root_security(scratch);
    if (!dacl_state_matches(root_baseline, root_dacl, mirrored)) {
        report_dacl_difference("Disposable mirror", root_baseline, root_dacl, mirrored);
        goto done;
    }
    prepared = prepared_dacl(root_dacl, app_packages, restricted_packages,
        add_app, add_restricted);
    if (!prepared) goto done;
    grant_attempted = 1;
    int grant_ok = write_root_dacl(scratch, prepared, mirrored);
    DWORD grant_error = grant_ok ? 0 : GetLastError();
    current = read_root_security(scratch);
    int exact_grant = dacl_state_matches(root_baseline, prepared, current);
    if (!grant_ok || !exact_grant) {
        if (!grant_ok) fprintf(stderr, "Disposable DACL grant failed: %lu\n", grant_error);
        report_dacl_difference("Disposable grant", root_baseline, prepared, current);
    }
    if (!SetFileSecurityW(scratch, DACL_SECURITY_INFORMATION, mirrored))
        fprintf(stderr, "Disposable DACL restore write failed: %lu\n", GetLastError());
    restored = read_root_security(scratch);
    int exact_restore = dacl_state_matches(root_baseline, root_dacl, restored);
    if (!exact_restore) report_dacl_difference("Disposable restore", root_baseline, root_dacl, restored);
    result = grant_ok && exact_grant && exact_restore;

done:
    if (directory_exists && grant_attempted) {
        PSECURITY_DESCRIPTOR live = read_root_security(scratch);
        if (!live || (!dacl_matches(root_dacl, descriptor_dacl(live)) &&
            !remove_guard_grants(scratch, live, app_packages, restricted_packages,
                add_app, add_restricted))) result = 0;
        free(live);
    }
    if (directory_exists && mirror_attempted && original) {
        if (!SetFileSecurityW(scratch, DACL_SECURITY_INFORMATION, original)) {
            fprintf(stderr, "Disposable original DACL restore failed: %lu\n", GetLastError());
            result = 0;
        }
        PSECURITY_DESCRIPTOR final = read_root_security(scratch);
        if (!dacl_state_matches(original, old_dacl, final)) {
            report_dacl_difference("Disposable original restore", original, old_dacl, final);
            result = 0;
        }
        free(final);
    }
    free(restored);
    free(current);
    free(prepared);
    free(mirrored);
    free(original);
    if (directory_exists && !RemoveDirectoryW(scratch)) {
        fprintf(stderr, "Disposable DACL probe directory removal failed: %lu\n", GetLastError());
        result = 0;
    }
    if (file_exists && !DeleteFileW(scratch)) result = 0;
    return result;
}

static int root_guard(void) {
    wchar_t root[4];
    if (!system_root(root)) {
        fputs("The Windows system drive has no local root.\n", stderr);
        return 1;
    }
    PSID app_packages = NULL, restricted_packages = NULL;
    PSECURITY_DESCRIPTOR original = NULL, current = NULL;
    PACL prepared = NULL;
    int result = 1, changed = 0;
    if (!ConvertStringSidToSidW(L"S-1-15-2-1", &app_packages) ||
        !ConvertStringSidToSidW(L"S-1-15-2-2", &restricted_packages)) goto done;
    original = read_root_security(root);
    PACL old_dacl = descriptor_dacl(original);
    if (!old_dacl) goto done;
    int app_state = group_ace_state(old_dacl, app_packages);
    int restricted_state = group_ace_state(old_dacl, restricted_packages);
    if (app_state < 0 || restricted_state < 0) {
        fputs("The system-drive root has conflicting AppContainer ACEs.\n", stderr);
        goto done;
    }
    if ((!app_state || !restricted_state) &&
        !disposable_dacl_check(root, original, old_dacl, app_packages,
            restricted_packages, !app_state, !restricted_state)) {
        fputs("Disposable DACL probe failed; system-drive root was not changed.\n", stderr);
        goto done;
    }
    prepared = prepared_dacl(old_dacl, app_packages, restricted_packages,
        !app_state, !restricted_state);
    if (!prepared) goto done;
    changed = !app_state || !restricted_state;
    if (changed && !write_root_dacl(root, prepared, original)) {
        DWORD error = GetLastError();
        fprintf(stderr, "System-drive metadata grant failed: %lu\n", error);
        current = read_root_security(root);
        report_dacl_difference("Grant write", original, prepared, current);
        restore_root_dacl(root, original, old_dacl, prepared, current, app_packages,
            restricted_packages, !app_state, !restricted_state);
        goto done;
    }
    current = read_root_security(root);
    if (!dacl_state_matches(original, prepared, current)) {
        fputs("System-drive metadata grant did not read back exactly.\n", stderr);
        report_dacl_difference("Grant readback", original, prepared, current);
        if (changed) restore_root_dacl(root, original, old_dacl, prepared, current,
            app_packages, restricted_packages, !app_state, !restricted_state);
        goto done;
    }
    free(current);
    current = NULL;
    puts("ROOT-READY");
    fflush(stdout);

    char signal = 0;
    DWORD amount = 0;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    BOOL read_ok = input != INVALID_HANDLE_VALUE && ReadFile(input, &signal, 1, &amount, NULL);
    current = read_root_security(root);
    if (!dacl_state_matches(original, prepared, current)) {
        fputs("System-drive DACL changed while the fixture was running.\n", stderr);
        report_dacl_difference("Guard release", original, prepared, current);
        if (changed) restore_root_dacl(root, original, old_dacl, prepared, current,
            app_packages, restricted_packages, !app_state, !restricted_state);
        goto done;
    }
    if (changed && !restore_root_dacl(root, original, old_dacl, prepared, current,
        app_packages, restricted_packages, !app_state, !restricted_state)) {
        fputs("System-drive original DACL did not read back after rollback.\n", stderr);
        goto done;
    }
    if (!read_ok || (amount && signal != 'R')) {
        fputs("System-drive fixture guard ended without its expected release signal.\n", stderr);
        goto done;
    }
    puts("ROOT-RESTORED");
    result = 0;

done:
    free(current);
    free(prepared);
    free(original);
    if (app_packages) LocalFree(app_packages);
    if (restricted_packages) LocalFree(restricted_packages);
    return result;
}

static int read_null_acl(void) {
    HANDLE device = CreateFileW(L"\\\\.\\NUL", READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (device == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "NUL device open failed: %lu\n", GetLastError());
        return 1;
    }
    DWORD size = 0;
    GetKernelObjectSecurity(device, DACL_SECURITY_INFORMATION, NULL, 0, &size);
    PSECURITY_DESCRIPTOR descriptor = size && GetLastError() == ERROR_INSUFFICIENT_BUFFER
        ? malloc(size) : NULL;
    int result = 1;
    LPWSTR sddl = NULL;
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
    if (argc == 2 && wcscmp(argv[1], L"root-guard") == 0) return root_guard();
    if (argc == 2 && wcscmp(argv[1], L"null-acl") == 0) return read_null_acl();
    return 1;
}
