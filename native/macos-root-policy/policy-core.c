#include "policy-core.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int valid_session(const char *value) {
    size_t len = strnlen(value, SGW_POLICY_SESSION_MAX + 1);
    if (!len || len > SGW_POLICY_SESSION_MAX) return 0;
    for (size_t i = 0; i < len; i++) {
        char ch = value[i];
        if ((ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') &&
            (ch < '0' || ch > '9') && ch != '-' && ch != '_') return 0;
    }
    return 1;
}

static int one_line(const char *frame) {
    size_t len = strnlen(frame, 256);
    if (!len || len >= 256 || frame[len - 1] != '\n') return 0;
    return memchr(frame, '\n', len - 1) == NULL;
}

static int next_id(const char **cursor, unsigned int *value) {
    if (**cursor < '0' || **cursor > '9') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(*cursor, &end, 10);
    if (errno || parsed == 0 || parsed > UINT_MAX || *end != ' ') return -1;
    *value = (unsigned int)parsed;
    *cursor = end + 1;
    return 0;
}

static int next_session(const char **cursor, char session[SGW_POLICY_SESSION_MAX + 1], int last) {
    const char *end = strchr(*cursor, last ? '\n' : ' ');
    if (!end || end == *cursor || end - *cursor > SGW_POLICY_SESSION_MAX) return -1;
    size_t length = (size_t)(end - *cursor);
    memcpy(session, *cursor, length);
    session[length] = '\0';
    if (!valid_session(session)) return -1;
    *cursor = end + 1;
    return last && **cursor != '\0' ? -1 : 0;
}

int sgw_policy_parse_register(const char *frame, struct sgw_policy_agent agents[2]) {
    if (!frame || !agents || !one_line(frame)) return -1;
    const char *cursor = frame;
    const char prefix[] = "REGISTER-V1 ";
    if (strncmp(cursor, prefix, sizeof(prefix) - 1)) return -1;
    cursor += sizeof(prefix) - 1;
    unsigned int uid_a, gid_a, uid_b, gid_b;
    char session_a[SGW_POLICY_SESSION_MAX + 1], session_b[SGW_POLICY_SESSION_MAX + 1];
    if (next_id(&cursor, &uid_a) || next_id(&cursor, &gid_a) ||
        next_session(&cursor, session_a, 0) || next_id(&cursor, &uid_b) ||
        next_id(&cursor, &gid_b) || next_session(&cursor, session_b, 1)) return -1;
    agents[0].uid = (uid_t)uid_a;
    agents[0].gid = (gid_t)gid_a;
    agents[1].uid = (uid_t)uid_b;
    agents[1].gid = (gid_t)gid_b;
    if ((unsigned int)agents[0].uid != uid_a || (unsigned int)agents[1].uid != uid_b ||
        (unsigned int)agents[0].gid != gid_a || (unsigned int)agents[1].gid != gid_b) return -1;
    strcpy(agents[0].session, session_a);
    strcpy(agents[1].session, session_b);
    return 0;
}

int sgw_policy_parse_check(const char *frame, uid_t *uid, char session[SGW_POLICY_SESSION_MAX + 1]) {
    if (!frame || !uid || !session || !one_line(frame)) return -1;
    const char *cursor = frame;
    const char prefix[] = "CHECK-V1 ";
    if (strncmp(cursor, prefix, sizeof(prefix) - 1)) return -1;
    cursor += sizeof(prefix) - 1;
    unsigned int raw_uid;
    if (next_id(&cursor, &raw_uid) || next_session(&cursor, session, 1)) return -1;
    *uid = (uid_t)raw_uid;
    if ((unsigned int)*uid != raw_uid) return -1;
    return 0;
}

int sgw_policy_register(struct sgw_policy_state *state, const struct sgw_policy_agent agents[2]) {
    if (!state || !agents || state->registered || !agents[0].uid || !agents[1].uid ||
        !agents[0].gid || !agents[1].gid || agents[0].uid == agents[1].uid ||
        agents[0].gid == agents[1].gid || !valid_session(agents[0].session) ||
        !valid_session(agents[1].session) || !strcmp(agents[0].session, agents[1].session)) return -1;
    state->agents[0] = agents[0];
    state->agents[1] = agents[1];
    state->registered = 1;
    return 0;
}

int sgw_policy_ready(const struct sgw_policy_state *state, uid_t runner_uid, uid_t agent_uid,
                     const char *session, const struct sgw_policy_proof *proof) {
    if (!state || !state->registered || runner_uid != 0 || !agent_uid ||
        !session || !valid_session(session) || !proof ||
        !proof->signed_provider || !proof->enabled_socket_filter || !proof->provider_alive ||
        !proof->exact_uid_policy || !proof->current_boot_probes || !proof->continuous_denial) return 0;
    for (int i = 0; i < 2; i++) {
        if (state->agents[i].uid == agent_uid && !strcmp(state->agents[i].session, session)) return 1;
    }
    return 0;
}

void sgw_policy_reset(struct sgw_policy_state *state) {
    if (state) memset(state, 0, sizeof(*state));
}
