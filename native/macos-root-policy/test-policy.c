#include "policy-core.h"

#include <stdio.h>
#include <string.h>

static int parse_cases(void) {
    struct sgw_policy_agent agents[2];
    const char *good = "REGISTER-V1 231000 231000 alpha_1 231001 231001 beta-2\n";
    if (sgw_policy_parse_register(good, agents) || agents[0].uid != 231000 ||
        agents[1].gid != 231001 || strcmp(agents[1].session, "beta-2")) return 1;
    const char *bad[] = {
        "REGISTER-V1 -1 231000 alpha 231001 231001 beta\n",
        "REGISTER-V1 231000 231000 alpha 231001 231001 beta extra\n",
        "REGISTER-V1 231000 231000 alpha 231001 231001 beta\nCHECK-V1 1 x\n",
        "REGISTER-V1 231000 231000 alpha 231001 231001 beta",
        "REGISTER-V1 231000 231000 alpha 231001 231001 bad/session\n",
        "REGISTER-V1 0 231000 alpha 231001 231001 beta\n"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (!sgw_policy_parse_register(bad[i], agents)) return 2;
    }
    uid_t uid;
    char session[SGW_POLICY_SESSION_MAX + 1];
    if (sgw_policy_parse_check("CHECK-V1 231000 alpha_1\n", &uid, session) ||
        uid != 231000 || strcmp(session, "alpha_1")) return 3;
    const char *bad_checks[] = {
        "CHECK-V1 -1 alpha\n", "CHECK-V1 231000 alpha extra\n",
        "CHECK-V1 231000 alpha", "CHECK-V1 231000 alpha\nCHECK-V1 1 beta\n",
        "CHECK-V1 231000 bad/session\n"
    };
    for (size_t i = 0; i < sizeof(bad_checks) / sizeof(bad_checks[0]); i++) {
        if (!sgw_policy_parse_check(bad_checks[i], &uid, session)) return 4;
    }
    return 0;
}

static int state_cases(void) {
    struct sgw_policy_state state = {0};
    struct sgw_policy_agent pair[2] = {
        { .uid = 231000, .gid = 231000, .session = "alpha" },
        { .uid = 231001, .gid = 231001, .session = "beta" }
    };
    struct sgw_policy_proof proof = {
        .checked_uid = 231000, .checked_session = "alpha",
        .signed_provider = 1, .enabled_socket_filter = 1, .provider_alive = 1,
        .exact_uid_policy = 1, .current_boot_probes = 1, .continuous_denial = 1
    };
    proof.policy_agents[0] = pair[0];
    proof.policy_agents[1] = pair[1];
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof) ||
        sgw_policy_register(&state, pair) || !sgw_policy_register(&state, pair)) return 1;
    if (!sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 2;
    proof.checked_uid = 231001;
    strcpy(proof.checked_session, "beta");
    if (!sgw_policy_ready(&state, 0, 231001, "beta", &proof)) return 2;
    proof.checked_uid = 231000;
    strcpy(proof.checked_session, "alpha");
    if (sgw_policy_ready(&state, 501, 231000, "alpha", &proof) ||
        sgw_policy_ready(&state, 0, 231000, "beta", &proof) ||
        sgw_policy_ready(&state, 0, 231002, "alpha", &proof) ||
        sgw_policy_ready(&state, 0, 231000, "alpha", NULL)) return 3;
    proof.checked_uid = 231001;
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 8;
    proof.checked_uid = 231000;
    strcpy(proof.checked_session, "beta");
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 9;
    strcpy(proof.checked_session, "alpha");
    proof.policy_agents[1].uid = 231002;
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 10;
    proof.policy_agents[1].uid = 231001;
    strcpy(proof.policy_agents[1].session, "wrong");
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 11;
    proof.policy_agents[1] = pair[1];
    int *parts[] = {
        &proof.signed_provider, &proof.enabled_socket_filter, &proof.provider_alive,
        &proof.exact_uid_policy, &proof.current_boot_probes, &proof.continuous_denial
    };
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
        *parts[i] = 0;
        if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 4;
        *parts[i] = 1;
    }
    sgw_policy_reset(&state);
    if (sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 5;
    pair[1].uid = pair[0].uid;
    if (!sgw_policy_register(&state, pair)) return 6;
    pair[1].uid = 231001;
    pair[1].gid = pair[0].gid;
    if (!sgw_policy_register(&state, pair)) return 7;
    pair[1].gid = 231001;
    strcpy(pair[1].session, "alpha");
    if (!sgw_policy_register(&state, pair)) return 8;
    return 0;
}

static int provider_reply_cases(void) {
    const char *nonce = "00112233445566778899aabbccddeeff";
    struct sgw_policy_agent pair[2] = {
        { .uid = 231000, .gid = 231000, .session = "alpha" },
        { .uid = 231001, .gid = 231001, .session = "beta" }
    };
    struct sgw_policy_state state = {0};
    struct sgw_policy_proof proof = {0};
    char challenge[512];
    if (sgw_policy_register(&state, pair)) return 1;
    if (sgw_policy_format_provider_challenge(challenge, sizeof(challenge), &state,
                                             nonce, 231000, "alpha") < 0 ||
        strcmp(challenge, "CHALLENGE-V1 00112233445566778899aabbccddeeff 231000 alpha "
                          "231000 231000 alpha 231001 231001 beta\n")) return 2;

    const char *valid = "ATTEST-V1 00112233445566778899aabbccddeeff 231000 alpha "
                        "231000 231000 alpha 231001 231001 beta\n";
    if (sgw_policy_parse_provider_reply(valid, nonce, &state, 231000, "alpha", &proof)) return 3;
    proof.signed_provider = 1;
    if (proof.checked_uid != 231000 || strcmp(proof.checked_session, "alpha") ||
        !proof.provider_alive || proof.enabled_socket_filter || proof.exact_uid_policy ||
        proof.current_boot_probes || proof.continuous_denial ||
        sgw_policy_ready(&state, 0, 231000, "alpha", &proof)) return 4;

    const char *bad[] = {
        "ATTEST-V1 00112233445566778899aabbccddee00 231000 alpha 231000 231000 alpha 231001 231001 beta\n",
        "ATTEST-V1 00112233445566778899aabbccddeeff 231001 alpha 231000 231000 alpha 231001 231001 beta\n",
        "ATTEST-V1 00112233445566778899aabbccddeeff 231000 beta 231000 231000 alpha 231001 231001 beta\n",
        "ATTEST-V1 00112233445566778899aabbccddeeff 231000 alpha 231000 231000 alpha 231002 231001 beta\n",
        "ATTEST-V1 00112233445566778899aabbccddeeff 231000 alpha 231000 231000 alpha 231001 231001 beta extra\n",
        "ATTEST-V1 00112233445566778899aabbccddeeff 231000 alpha 231000 231000 alpha 231001 231001 beta\nATTEST-V1 1 x\n"
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        proof.provider_alive = 1;
        if (!sgw_policy_parse_provider_reply(bad[i], nonce, &state, 231000, "alpha", &proof) ||
            proof.provider_alive) return 5;
    }
    if (sgw_policy_format_provider_challenge(challenge, sizeof(challenge), &state,
                                             nonce, 231002, "alpha") >= 0 ||
        sgw_policy_format_provider_challenge(challenge, 10, &state,
                                             nonce, 231000, "alpha") >= 0) return 6;
    return 0;
}

int main(void) {
    int parsed = parse_cases();
    int state = state_cases();
    int provider = provider_reply_cases();
    if (parsed || state || provider)
        fprintf(stderr, "policy core failed: parse=%d state=%d provider=%d\n", parsed, state, provider);
    return parsed || state || provider ? 1 : 0;
}
