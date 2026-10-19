#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    struct sockaddr_storage address;
    socklen_t address_len = sizeof(address);
    int socket_type = 0;
    socklen_t type_len = sizeof(socket_type);

    if (getsockname(3, (struct sockaddr *)&address, &address_len) != 0 ||
        address.ss_family != AF_UNIX ||
        getsockopt(3, SOL_SOCKET, SO_TYPE, &socket_type, &type_len) != 0 ||
        socket_type != SOCK_STREAM) {
        fputs("Expected a connected Unix stream socket on fd 3.\n", stderr);
        return 1;
    }

#if defined(__APPLE__)
    uid_t uid;
    gid_t gid;
    if (getpeereid(3, &uid, &gid) != 0) {
        fputs("Could not read Unix peer identity.\n", stderr);
        return 1;
    }
    printf("%lu %lu 0\n", (unsigned long)uid, (unsigned long)gid);
#elif defined(__linux__)
    struct ucred peer;
    socklen_t peer_len = sizeof(peer);
    if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 ||
        peer_len != sizeof(peer) || peer.pid <= 0) {
        fputs("Could not read Unix peer identity.\n", stderr);
        return 1;
    }
    printf("%lu %lu %ld\n", (unsigned long)peer.uid,
           (unsigned long)peer.gid, (long)peer.pid);
#else
    fputs("Unix peer identity is unsupported on this platform.\n", stderr);
    return 1;
#endif

    return fflush(stdout) == 0 ? 0 : 1;
}
