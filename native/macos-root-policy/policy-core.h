#ifndef SGW_MACOS_POLICY_CORE_H
#define SGW_MACOS_POLICY_CORE_H

#include <sys/types.h>

#define SGW_POLICY_SESSION_MAX 64

struct sgw_policy_agent {
    uid_t uid;
    gid_t gid;
    char session[SGW_POLICY_SESSION_MAX + 1];
};

struct sgw_policy_state {
    struct sgw_policy_agent agents[2];
    int registered;
};

struct sgw_policy_proof {
    uid_t checked_uid;
    char checked_session[SGW_POLICY_SESSION_MAX + 1];
    struct sgw_policy_agent policy_agents[2];
    int signed_provider;
    int enabled_socket_filter;
    int provider_alive;
    int exact_uid_policy;
    int current_boot_probes;
    int continuous_denial;
};

int sgw_policy_parse_register(const char *frame, struct sgw_policy_agent agents[2]);
int sgw_policy_parse_check(const char *frame, uid_t *uid, char session[SGW_POLICY_SESSION_MAX + 1]);
int sgw_policy_register(struct sgw_policy_state *state, const struct sgw_policy_agent agents[2]);
int sgw_policy_ready(const struct sgw_policy_state *state, uid_t runner_uid, uid_t agent_uid,
                     const char *session, const struct sgw_policy_proof *proof);
void sgw_policy_reset(struct sgw_policy_state *state);

#endif
