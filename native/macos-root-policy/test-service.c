#define main sgw_policy_service_entry
#include "policy-service.c"
#undef main

static int entitlement_cases(void) {
    const void *allowed[] = { CFSTR("content-filter-provider-systemextension") };
    const void *wrong[] = { CFSTR("content-filter-provider") };
    CFArrayRef expected = CFArrayCreate(NULL, allowed, 1, &kCFTypeArrayCallBacks);
    CFArrayRef other = CFArrayCreate(NULL, wrong, 1, &kCFTypeArrayCallBacks);
    CFMutableDictionaryRef values = CFDictionaryCreateMutable(NULL, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!expected || !other || !values) return 10;
    CFDictionarySetValue(values, CFSTR("com.apple.developer.networking.networkextension"), expected);
    if (!provider_entitlements_valid(values)) return 11;
    CFDictionarySetValue(values, CFSTR("com.apple.security.get-task-allow"), kCFBooleanTrue);
    if (provider_entitlements_valid(values)) return 12;
    CFDictionarySetValue(values, CFSTR("com.apple.security.get-task-allow"), kCFBooleanFalse);
    if (!provider_entitlements_valid(values)) return 13;
    CFDictionarySetValue(values, CFSTR("com.apple.developer.networking.networkextension"), other);
    if (provider_entitlements_valid(values)) return 14;
    CFRelease(values);
    CFRelease(other);
    CFRelease(expected);
    return 0;
}

int main(int argc, char **argv) {
    int entitlement_result = entitlement_cases();
    if (entitlement_result) return entitlement_result;
    if (argc == 3 && !strcmp(argv[1], "--tree"))
        return provider_bundle_contents_safe(argv[2], getuid()) ? 0 : 18;
    if (argc == 2) {
        if (provider_signature_at(argv[1], "identifier com.sgw.test-provider",
                                  "com.sgw.test-provider", "NOTAREALTEAM")) return 8;
        return 0;
    }
    if (argc != 1 || signed_provider_bundle()) return 9;
    struct sgw_policy_state state = {0};
    struct sgw_policy_agent agents[2] = {
        { .uid = 231000, .gid = 231000, .session = "alpha" },
        { .uid = 231001, .gid = 231001, .session = "beta" }
    };
    if (sgw_policy_register(&state, agents)) return 1;
    struct sgw_policy_proof proof = provider_proof(231000, "alpha");
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 2;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 3;
    if (signed_peer(sockets[0], getuid(), "")) return 6;
    struct runner_connection runner = { .fd = sockets[0], .peer_uid = 0 };
    if (reply_check(&runner, &state, "CHECK-V1 231000 alpha\n")) return 4;
    char result[128] = {0};
    ssize_t count = recv(sockets[1], result, sizeof(result), 0);
    close(sockets[0]);
    close(sockets[1]);
    if (count != (ssize_t)strlen("DENIED-V1 231000 alpha\n") ||
        strcmp(result, "DENIED-V1 231000 alpha\n")) return 5;
    return 0;
}
