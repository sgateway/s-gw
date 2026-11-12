#define main sgw_policy_service_entry
#include "policy-service.c"
#undef main

#include <signal.h>
#include <sys/wait.h>

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

static int exchange_cases(const struct sgw_policy_state *state) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 20;
    pid_t child = fork();
    if (child < 0) return 21;
    if (child == 0) {
        close(sockets[0]);
        char frame[512] = {0};
        size_t used = 0;
        while (used < sizeof(frame) - 1 && recv(sockets[1], frame + used, 1, 0) == 1) {
            if (frame[used++] == '\n') break;
        }
        const char prefix[] = "CHALLENGE-V1 ";
        if (strncmp(frame, prefix, sizeof(prefix) - 1)) _exit(22);
        char reply[512];
        int length = snprintf(reply, sizeof(reply), "ATTEST-V1 %s", frame + sizeof(prefix) - 1);
        if (length < 1 || length >= (int)sizeof(reply) ||
            send(sockets[1], reply, (size_t)length, 0) != length) _exit(23);
        close(sockets[1]);
        _exit(0);
    }
    close(sockets[1]);
    struct sgw_policy_proof proof = {0};
    int exchanged = provider_exchange(sockets[0], state, 231000, "alpha", &proof);
    close(sockets[0]);
    int child_status = 0;
    proof.signed_provider = 1;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0 || exchanged || !proof.provider_alive ||
        sgw_policy_ready(state, 0, 231000, "alpha", &proof)) return 24;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 25;
    const char *stale = "ATTEST-V1 00000000000000000000000000000000 231000 alpha "
                        "231000 231000 alpha 231001 231001 beta\n";
    if (send(sockets[1], stale, strlen(stale), 0) != (ssize_t)strlen(stale)) return 26;
    proof.provider_alive = 1;
    int accepted_stale = provider_exchange(sockets[0], state, 231000, "alpha", &proof);
    close(sockets[0]);
    close(sockets[1]);
    if (accepted_stale == 0 || proof.provider_alive) return 27;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 28;
    close(sockets[1]);
    proof.provider_alive = 1;
    int accepted_closed = provider_exchange(sockets[0], state, 231000, "alpha", &proof);
    close(sockets[0]);
    return accepted_closed == 0 || proof.provider_alive ? 29 : 0;
}

static int peer_connect_case(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 30;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        return 31;
    }
    strcpy(address.sun_path, socket_path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        close(fd);
        return 32;
    }
    char ignored;
    recv(fd, &ignored, 1, 0);
    close(fd);
    return 0;
}

static int live_path_case(const char *self_path, const char *expected_path) {
    char directory[] = "/tmp/sgw-policy-peer-XXXXXX";
    if (!mkdtemp(directory)) return 33;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    char socket_path[sizeof(address.sun_path)];
    int path_len = snprintf(socket_path, sizeof(socket_path), "%s/peer.sock", directory);
    if (path_len < 0 || path_len >= (int)sizeof(socket_path)) {
        rmdir(directory);
        return 34;
    }
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    strcpy(address.sun_path, socket_path);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 1)) {
        if (listener >= 0) close(listener);
        unlink(socket_path);
        rmdir(directory);
        return 35;
    }
    pid_t child = fork();
    if (child == 0) {
        close(listener);
        execl(self_path, self_path, "--connect", socket_path, NULL);
        _exit(36);
    }
    struct pollfd ready = { .fd = listener, .events = POLLIN };
    int peer = child > 0 && poll(&ready, 1, 3000) == 1 && (ready.revents & POLLIN) ?
        accept(listener, NULL, NULL) : -1;
    int matched = peer >= 0 && signed_peer(peer, getuid(),
        "identifier \"com.sgw.test-service\"", expected_path);
    if (peer >= 0) close(peer);
    if (peer < 0 && child > 0) kill(child, SIGKILL);
    close(listener);
    int child_status = 0;
    int waited = child > 0 ? waitpid(child, &child_status, 0) : -1;
    unlink(socket_path);
    rmdir(directory);
    if (waited != child || !WIFEXITED(child_status) || WEXITSTATUS(child_status)) return 37;
    return matched ? 0 : 38;
}

int main(int argc, char **argv) {
    int entitlement_result = entitlement_cases();
    if (entitlement_result) return entitlement_result;
    if (argc == 3 && !strcmp(argv[1], "--live-path")) return live_path_case(argv[0], argv[2]);
    if (argc == 3 && !strcmp(argv[1], "--connect")) return peer_connect_case(argv[2]);
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
    int exchange_result = exchange_cases(&state);
    if (exchange_result) return exchange_result;
    struct sgw_policy_proof proof = provider_proof(-1, &state, 231000, "alpha");
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 2;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) return 3;
    if (signed_peer(sockets[0], getuid(), "", NULL)) return 6;
    struct runner_connection runner = { .fd = sockets[0], .peer_uid = 0 };
    if (reply_check(&runner, -1, &state, "CHECK-V1 231000 alpha\n")) return 4;
    char result[128] = {0};
    ssize_t count = recv(sockets[1], result, sizeof(result), 0);
    close(sockets[0]);
    close(sockets[1]);
    if (count != (ssize_t)strlen("DENIED-V1 231000 alpha\n") ||
        strcmp(result, "DENIED-V1 231000 alpha\n")) return 5;
    return 0;
}
