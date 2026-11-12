#define main sgw_policy_service_entry
#include "policy-service.c"
#undef main

int main(void) {
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
