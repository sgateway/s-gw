#if !defined(__APPLE__)
#error This source-only policy service is for macOS.
#endif

#include "policy-core.h"

#include <Security/SecRandom.h>
#include <Security/Security.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <fts.h>
#include <poll.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define BROKER_CONTROL_SOCKET "/private/var/db/s-gw/agent-launch-control.sock"
#define POLICY_SOCKET "/private/var/db/s-gw/agent-network-policy.sock"
#define PROVIDER_SOCKET "/private/var/db/s-gw/agent-provider-attestation.sock"

#ifndef SGW_POLICY_SERVICE_REQUIREMENT
#define SGW_POLICY_SERVICE_REQUIREMENT ""
#endif
#ifndef SGW_POLICY_BROKER_REQUIREMENT
#define SGW_POLICY_BROKER_REQUIREMENT ""
#endif
#ifndef SGW_POLICY_RUNNER_REQUIREMENT
#define SGW_POLICY_RUNNER_REQUIREMENT ""
#endif
#ifndef SGW_POLICY_PROVIDER_PATH
#define SGW_POLICY_PROVIDER_PATH ""
#endif
#ifndef SGW_POLICY_PROVIDER_REQUIREMENT
#define SGW_POLICY_PROVIDER_REQUIREMENT ""
#endif
#ifndef SGW_POLICY_PROVIDER_BUNDLE_ID
#define SGW_POLICY_PROVIDER_BUNDLE_ID ""
#endif
#ifndef SGW_POLICY_PROVIDER_TEAM_ID
#define SGW_POLICY_PROVIDER_TEAM_ID ""
#endif

struct runner_connection {
    int fd;
    uid_t peer_uid;
    size_t used;
    char input[256];
};

static int no_acl_allow(const char *location) {
    errno = 0;
    acl_t acl = acl_get_file(location, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT ? 0 : -1;
    acl_entry_t entry;
    int next = ACL_FIRST_ENTRY;
    int safe = 0;
    for (;;) {
        errno = 0;
        if (acl_get_entry(acl, next, &entry)) {
            if (errno != EINVAL) safe = -1;
            break;
        }
        acl_tag_t tag;
        if (acl_get_tag_type(entry, &tag) || tag != ACL_EXTENDED_DENY) {
            safe = -1;
            break;
        }
        next = ACL_NEXT_ENTRY;
    }
    acl_free(acl);
    return safe;
}

static int checked_socket(const char *location, uid_t owner, mode_t mode) {
    char resolved[PATH_MAX], parent[PATH_MAX];
    struct stat info;
    if (!realpath(location, resolved) || strcmp(location, resolved) ||
        lstat(location, &info) || !S_ISSOCK(info.st_mode) || info.st_uid != owner ||
        (info.st_mode & 0777) != mode || no_acl_allow(location) ||
        strlen(location) >= sizeof(parent)) return -1;
    strcpy(parent, location);
    for (;;) {
        char *slash = strrchr(parent, '/');
        if (!slash) return -1;
        if (slash == parent) parent[1] = '\0';
        else *slash = '\0';
        if (!realpath(parent, resolved) || strcmp(parent, resolved) || lstat(parent, &info) ||
            !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022) ||
            no_acl_allow(parent)) return -1;
        if (!strcmp(parent, "/")) return 0;
    }
}

static int root_owned_provider_path(const char *location) {
    if (!location || location[0] != '/' || !location[1]) return 0;
    char resolved[PATH_MAX], parent[PATH_MAX];
    struct stat info;
    if (strlen(location) >= sizeof(parent) || !realpath(location, resolved) ||
        strcmp(location, resolved) || lstat(location, &info) || !S_ISDIR(info.st_mode) ||
        info.st_uid != 0 || (info.st_mode & 022) || no_acl_allow(location)) return 0;
    strcpy(parent, location);
    for (;;) {
        char *slash = strrchr(parent, '/');
        if (!slash) return 0;
        if (slash == parent) parent[1] = '\0';
        else *slash = '\0';
        if (!realpath(parent, resolved) || strcmp(parent, resolved) || lstat(parent, &info) ||
            !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022) ||
            no_acl_allow(parent)) return 0;
        if (!strcmp(parent, "/")) return 1;
    }
}

static int provider_bundle_contents_safe(const char *location, uid_t owner) {
    if (!location || !location[0]) return 0;
    char *root = strdup(location);
    if (!root) return 0;
    char *paths[] = { root, NULL };
    FTS *tree = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
    if (!tree) {
        free(root);
        return 0;
    }
    int safe = 1;
    for (;;) {
        errno = 0;
        FTSENT *entry = fts_read(tree);
        if (!entry) {
            if (errno) safe = 0;
            break;
        }
        if (entry->fts_info == FTS_DP) continue;
        if ((entry->fts_info != FTS_D && entry->fts_info != FTS_F) ||
            !entry->fts_statp || entry->fts_statp->st_uid != owner ||
            (entry->fts_statp->st_mode & 022) || no_acl_allow(entry->fts_path)) {
            safe = 0;
            break;
        }
    }
    if (fts_close(tree)) safe = 0;
    free(root);
    return safe;
}

static int provider_entitlements_valid(CFTypeRef value) {
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) return 0;
    CFDictionaryRef entitlements = (CFDictionaryRef)value;
    CFTypeRef capabilities = CFDictionaryGetValue(entitlements,
        CFSTR("com.apple.developer.networking.networkextension"));
    CFTypeRef debug = CFDictionaryGetValue(entitlements, CFSTR("com.apple.security.get-task-allow"));
    if (!capabilities || CFGetTypeID(capabilities) != CFArrayGetTypeID() ||
        (debug && debug != kCFBooleanFalse)) return 0;
    CFStringRef required = CFSTR("content-filter-provider-systemextension");
    return CFArrayContainsValue(capabilities, CFRangeMake(0, CFArrayGetCount(capabilities)), required);
}

static int provider_signature_at(const char *location, const char *requirement_string,
                                 const char *expected_id, const char *expected_team) {
    if (!location || !location[0] || !requirement_string || !requirement_string[0] ||
        !expected_id || !expected_id[0] || !expected_team || !expected_team[0]) return 0;
    CFStringRef requirement_text = CFStringCreateWithCString(NULL, requirement_string,
                                                              kCFStringEncodingUTF8);
    CFStringRef bundle_id = CFStringCreateWithCString(NULL, expected_id,
                                                      kCFStringEncodingUTF8);
    CFStringRef team_id = CFStringCreateWithCString(NULL, expected_team,
                                                    kCFStringEncodingUTF8);
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL,
        (const UInt8 *)location, strlen(location), true);
    SecRequirementRef requirement = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef signing = NULL;
    int valid = 0;
    if (!requirement_text || !bundle_id || !team_id || !url ||
        SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags, &requirement) != errSecSuccess ||
        SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) != errSecSuccess ||
        SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures |
                                    kSecCSCheckNestedCode, requirement) != errSecSuccess ||
        SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing) != errSecSuccess ||
        !signing) goto done;
    CFTypeRef actual_id = CFDictionaryGetValue(signing, kSecCodeInfoIdentifier);
    CFTypeRef actual_team = CFDictionaryGetValue(signing, kSecCodeInfoTeamIdentifier);
    CFTypeRef entitlements = CFDictionaryGetValue(signing, kSecCodeInfoEntitlementsDict);
    if (!actual_id || CFGetTypeID(actual_id) != CFStringGetTypeID() ||
        !CFEqual(actual_id, bundle_id) || !actual_team ||
        CFGetTypeID(actual_team) != CFStringGetTypeID() || !CFEqual(actual_team, team_id)) goto done;
    valid = provider_entitlements_valid(entitlements);
done:
    if (signing) CFRelease(signing);
    if (code) CFRelease(code);
    if (requirement) CFRelease(requirement);
    if (url) CFRelease(url);
    if (team_id) CFRelease(team_id);
    if (bundle_id) CFRelease(bundle_id);
    if (requirement_text) CFRelease(requirement_text);
    return valid;
}

static int signed_provider_bundle(void) {
    return root_owned_provider_path(SGW_POLICY_PROVIDER_PATH) &&
        provider_bundle_contents_safe(SGW_POLICY_PROVIDER_PATH, 0) &&
        provider_signature_at(SGW_POLICY_PROVIDER_PATH, SGW_POLICY_PROVIDER_REQUIREMENT,
                              SGW_POLICY_PROVIDER_BUNDLE_ID, SGW_POLICY_PROVIDER_TEAM_ID);
}

static int socket_at(int fd, const char *location, int listening) {
    int type = 0, accepts = 0;
    socklen_t length = sizeof(type);
    struct sockaddr_un address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_STREAM ||
        getsockname(fd, (struct sockaddr *)&address, &address_len) ||
        address.sun_family != AF_UNIX ||
        address_len <= offsetof(struct sockaddr_un, sun_path) ||
        strnlen(address.sun_path, sizeof(address.sun_path)) >= sizeof(address.sun_path) ||
        strcmp(address.sun_path, location)) return -1;
    length = sizeof(accepts);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepts, &length) || !!accepts != !!listening)
        return -1;
    return 0;
}

static int signed_code_matches(CFDictionaryRef attributes, const char *requirement_text,
                               const char *expected_path) {
    if (!attributes || !requirement_text || !requirement_text[0]) return 0;
    CFStringRef text = CFStringCreateWithCString(NULL, requirement_text, kCFStringEncodingUTF8);
    if (!text) return 0;
    SecRequirementRef requirement = NULL;
    SecCodeRef code = NULL;
    int valid = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &requirement) == errSecSuccess &&
        SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &code) == errSecSuccess &&
        SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess;
    if (valid && expected_path) {
        CFURLRef code_url = NULL;
        char actual[PATH_MAX], actual_real[PATH_MAX], expected_real[PATH_MAX];
        valid = SecCodeCopyPath(code, kSecCSDefaultFlags, &code_url) == errSecSuccess &&
            code_url && CFURLGetFileSystemRepresentation(code_url, true,
                (UInt8 *)actual, sizeof(actual)) && realpath(actual, actual_real) &&
            realpath(expected_path, expected_real) && !strcmp(actual_real, expected_real);
        if (code_url) CFRelease(code_url);
    }
    if (code) CFRelease(code);
    if (requirement) CFRelease(requirement);
    CFRelease(text);
    return valid;
}

static int self_signed(void) {
    pid_t pid = getpid();
    CFNumberRef number = CFNumberCreate(NULL, kCFNumberSInt32Type, &pid);
    if (!number) return 0;
    const void *keys[] = { kSecGuestAttributePid };
    const void *values[] = { number };
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
                                                      &kCFTypeDictionaryKeyCallBacks,
                                                      &kCFTypeDictionaryValueCallBacks);
    int valid = signed_code_matches(attributes, SGW_POLICY_SERVICE_REQUIREMENT, NULL);
    if (attributes) CFRelease(attributes);
    CFRelease(number);
    return valid;
}

static int signed_peer(int fd, uid_t expected_uid, const char *requirement_text,
                       const char *expected_path) {
    uid_t uid;
    gid_t gid;
    audit_token_t token;
    socklen_t length = sizeof(token);
    if (getpeereid(fd, &uid, &gid) || uid != expected_uid ||
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &length) ||
        length != sizeof(token) || audit_token_to_euid(token) != expected_uid) return 0;
    CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
    if (!audit) return 0;
    const void *keys[] = { kSecGuestAttributeAudit };
    const void *values[] = { audit };
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 1,
                                                      &kCFTypeDictionaryKeyCallBacks,
                                                      &kCFTypeDictionaryValueCallBacks);
    int valid = signed_code_matches(attributes, requirement_text, expected_path);
    if (attributes) CFRelease(attributes);
    CFRelease(audit);
    return valid;
}

static int dedicated_accounts(const struct sgw_policy_agent agents[2], uid_t broker_uid) {
    for (int i = 0; i < 2; i++) {
        struct passwd *account = getpwuid(agents[i].uid);
        if (!account || strncmp(account->pw_name, "_sgwagent_", 10) ||
            account->pw_gid != agents[i].gid || agents[i].uid == broker_uid) return 0;
    }
    return 1;
}

static int read_registration(int fd, struct sgw_policy_state *state, uid_t broker_uid) {
    char frame[256];
    size_t used = 0;
    while (used < sizeof(frame) - 1) {
        struct pollfd ready = { .fd = fd, .events = POLLIN };
        if (poll(&ready, 1, 1500) != 1 || (ready.revents & (POLLERR | POLLHUP | POLLNVAL)) ||
            !(ready.revents & POLLIN)) return -1;
        ssize_t count = recv(fd, frame + used, 1, 0);
        if (count != 1) return -1;
        if (frame[used++] != '\n') continue;
        frame[used] = '\0';
        struct sgw_policy_agent agents[2];
        if (sgw_policy_parse_register(frame, agents) || !dedicated_accounts(agents, broker_uid) ||
            sgw_policy_register(state, agents)) return -1;
        return 0;
    }
    return -1;
}

static int64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int provider_exchange(int fd, const struct sgw_policy_state *state, uid_t uid,
                             const char *session, struct sgw_policy_proof *proof) {
    unsigned char random[16];
    if (!proof) return -1;
    memset(proof, 0, sizeof(*proof));
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random) != errSecSuccess) return -1;
    char nonce[33];
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(random); i++) {
        nonce[i * 2] = hex[random[i] >> 4];
        nonce[i * 2 + 1] = hex[random[i] & 15];
    }
    nonce[32] = '\0';
    char challenge[512];
    int length = sgw_policy_format_provider_challenge(challenge, sizeof(challenge), state,
                                                       nonce, uid, session);
    int no_sigpipe = 1;
    if (length < 0 || setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe)) ||
        send(fd, challenge, (size_t)length, MSG_DONTWAIT) != length) return -1;

    int64_t deadline = monotonic_ms();
    if (deadline < 0) return -1;
    deadline += 500;
    char frame[512];
    size_t used = 0;
    while (used < sizeof(frame) - 1) {
        int64_t current = monotonic_ms();
        if (current < 0) return -1;
        int64_t remaining = deadline - current;
        if (remaining <= 0) return -1;
        struct pollfd ready = { .fd = fd, .events = POLLIN };
        int polled = poll(&ready, 1, (int)remaining);
        if (polled < 0 && errno == EINTR) continue;
        if (polled != 1 || (ready.revents & (POLLERR | POLLNVAL)) ||
            !(ready.revents & POLLIN)) return -1;
        ssize_t count = recv(fd, frame + used, sizeof(frame) - used - 1, MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return -1;
        used += (size_t)count;
        char *newline = memchr(frame, '\n', used);
        if (!newline) continue;
        if (newline != frame + used - 1) return -1;
        frame[used] = '\0';
        return sgw_policy_parse_provider_reply(frame, nonce, state, uid, session, proof);
    }
    return -1;
}

static struct sgw_policy_proof provider_proof(int provider, const struct sgw_policy_state *state,
                                              uid_t uid, const char *session) {
    struct sgw_policy_proof proof = {0};
    if (!signed_provider_bundle() || provider_exchange(provider, state, uid, session, &proof))
        return (struct sgw_policy_proof){0};
    proof.signed_provider = 1;
    // The reply proves only a fresh signed peer response, not effective filtering.
    return proof;
}

static int reply_check(struct runner_connection *runner, int provider,
                       const struct sgw_policy_state *state, const char *frame) {
    uid_t uid;
    char session[SGW_POLICY_SESSION_MAX + 1];
    if (sgw_policy_parse_check(frame, &uid, session)) return -1;
    struct sgw_policy_proof proof = provider_proof(provider, state, uid, session);
    int ready = sgw_policy_ready(state, runner->peer_uid, uid, session, &proof);
    char response[128];
    int length = snprintf(response, sizeof(response), "%s-V1 %u %s\n",
                          ready ? "READY" : "DENIED", uid, session);
    if (length < 1 || length >= (int)sizeof(response)) return -1;
    return send(runner->fd, response, (size_t)length, 0) == length ? 0 : -1;
}

static int receive_checks(struct runner_connection *runner, int provider,
                          const struct sgw_policy_state *state) {
    ssize_t count = recv(runner->fd, runner->input + runner->used,
                         sizeof(runner->input) - runner->used - 1, 0);
    if (count <= 0) return -1;
    runner->used += (size_t)count;
    runner->input[runner->used] = '\0';
    char *newline;
    while ((newline = memchr(runner->input, '\n', runner->used))) {
        size_t frame_len = (size_t)(newline - runner->input) + 1;
        char frame[256];
        memcpy(frame, runner->input, frame_len);
        frame[frame_len] = '\0';
        if (reply_check(runner, provider, state, frame)) return -1;
        runner->used -= frame_len;
        memmove(runner->input, runner->input + frame_len, runner->used);
    }
    return runner->used < sizeof(runner->input) - 1 ? 0 : -1;
}

static int serve(int broker, int listener, int provider, uid_t broker_uid) {
    struct sgw_policy_state state = {0};
    struct runner_connection runners[2] = {{ .fd = -1 }, { .fd = -1 }};
    if (read_registration(broker, &state, broker_uid)) return -1;
    for (;;) {
        struct pollfd fds[4] = {
            { .fd = broker, .events = POLLIN },
            { .fd = listener, .events = POLLIN },
            { .fd = runners[0].fd, .events = POLLIN },
            { .fd = runners[1].fd, .events = POLLIN }
        };
        if (poll(fds, 4, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[0].revents) break;
        if (fds[1].revents & POLLIN) {
            int fd = accept(listener, NULL, NULL);
            if (fd < 0) break;
            int slot = runners[0].fd < 0 ? 0 : runners[1].fd < 0 ? 1 : -1;
            int no_sigpipe = 1;
            if (slot < 0 || !signed_peer(fd, 0, SGW_POLICY_RUNNER_REQUIREMENT, NULL) ||
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe))) close(fd);
            else runners[slot] = (struct runner_connection){ .fd = fd, .peer_uid = 0 };
        } else if (fds[1].revents) break;
        for (int i = 0; i < 2; i++) {
            if (runners[i].fd < 0 || !fds[i + 2].revents) continue;
            if (!(fds[i + 2].revents & POLLIN) || receive_checks(&runners[i], provider, &state)) {
                close(runners[i].fd);
                runners[i].fd = -1;
            }
        }
    }
    for (int i = 0; i < 2; i++) if (runners[i].fd >= 0) close(runners[i].fd);
    sgw_policy_reset(&state);
    return -1;
}

int main(void) {
    if (getuid() != 0 || geteuid() != 0) {
        fputs("s-gw root policy service requires root.\n", stderr);
        return 1;
    }
    struct stat broker_node;
    if (!self_signed() || lstat(BROKER_CONTROL_SOCKET, &broker_node) ||
        !broker_node.st_uid || checked_socket(BROKER_CONTROL_SOCKET, broker_node.st_uid, 0600) ||
        checked_socket(POLICY_SOCKET, 0, 0600) ||
        checked_socket(PROVIDER_SOCKET, 0, 0600) ||
        socket_at(3, BROKER_CONTROL_SOCKET, 0) || socket_at(4, POLICY_SOCKET, 1) ||
        socket_at(5, PROVIDER_SOCKET, 0) ||
        !signed_peer(3, broker_node.st_uid, SGW_POLICY_BROKER_REQUIREMENT, NULL) ||
        !signed_peer(5, 0, SGW_POLICY_PROVIDER_REQUIREMENT, SGW_POLICY_PROVIDER_PATH)) {
        fputs("s-gw root policy service has no trusted broker, socket, or signing requirement.\n", stderr);
        return 1;
    }
    return serve(3, 4, 5, broker_node.st_uid) == 0 ? 0 : 1;
}
