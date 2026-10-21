#define _GNU_SOURCE

#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/unix_diag.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

static int socket_vfs_inode(uint32_t socket_inode, struct unix_diag_vfs *vfs) {
    int diag = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (diag < 0) return 0;
    struct timeval deadline = { .tv_sec = 1 };
    if (setsockopt(diag, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof(deadline)) != 0) {
        close(diag);
        return 0;
    }

    struct {
        struct nlmsghdr header;
        struct unix_diag_req request;
    } query = { 0 };
    query.header.nlmsg_len = NLMSG_LENGTH(sizeof(query.request));
    query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    query.header.nlmsg_flags = NLM_F_REQUEST;
    query.header.nlmsg_seq = 1;
    query.request.sdiag_family = AF_UNIX;
    query.request.udiag_ino = socket_inode;
    query.request.udiag_show = UDIAG_SHOW_VFS;
    query.request.udiag_cookie[0] = UINT32_MAX;
    query.request.udiag_cookie[1] = UINT32_MAX;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(diag, &query, query.header.nlmsg_len, 0,
            (const struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)query.header.nlmsg_len) {
        close(diag);
        return 0;
    }

    _Alignas(struct nlmsghdr) char buffer[4096];
    struct sockaddr_nl sender = { 0 };
    struct iovec data = { .iov_base = buffer, .iov_len = sizeof(buffer) };
    struct msghdr message = { .msg_name = &sender, .msg_namelen = sizeof(sender),
        .msg_iov = &data, .msg_iovlen = 1 };
    ssize_t amount = recvmsg(diag, &message, 0);
    close(diag);
    if (amount < (ssize_t)NLMSG_LENGTH(sizeof(struct unix_diag_msg)) ||
        (message.msg_flags & MSG_TRUNC) || message.msg_namelen != sizeof(sender) ||
        sender.nl_family != AF_NETLINK || sender.nl_pid != 0) return 0;

    unsigned int remaining = (unsigned int)amount;
    struct nlmsghdr *header = (struct nlmsghdr *)buffer;
    if (!NLMSG_OK(header, remaining) || header->nlmsg_seq != 1 ||
        header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
        header->nlmsg_len < NLMSG_LENGTH(sizeof(struct unix_diag_msg))) return 0;
    struct unix_diag_msg *result = NLMSG_DATA(header);
    if (result->udiag_family != AF_UNIX || result->udiag_type != SOCK_STREAM ||
        result->udiag_ino != socket_inode) return 0;

    int left = (int)header->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*result));
    char *cursor = (char *)result + NLMSG_ALIGN(sizeof(*result));
    while (left >= (int)sizeof(struct nlattr)) {
        struct nlattr *attribute = (struct nlattr *)cursor;
        if (attribute->nla_len < sizeof(*attribute) || attribute->nla_len > left) return 0;
        if (attribute->nla_type == UNIX_DIAG_VFS) {
            if (attribute->nla_len != NLA_HDRLEN + sizeof(*vfs)) return 0;
            memcpy(vfs, cursor + NLA_HDRLEN, sizeof(*vfs));
            return 1;
        }
        int step = NLA_ALIGN(attribute->nla_len);
        if (step > left) return 0;
        cursor += step;
        left -= step;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/' || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fputs("Invalid activated socket path.\n", stderr);
        return 1;
    }
    struct stat listener;
    struct stat node;
    struct sockaddr_un address = { 0 };
    socklen_t address_len = sizeof(address);
    size_t path_len = strlen(argv[1]);
    int type = 0;
    int listening = 0;
    socklen_t type_len = sizeof(type);
    socklen_t listening_len = sizeof(listening);
    if (fstat(3, &listener) != 0 || !S_ISSOCK(listener.st_mode) ||
        listener.st_ino == 0 || listener.st_ino > UINT32_MAX ||
        getsockname(3, (struct sockaddr *)&address, &address_len) != 0 ||
        address.sun_family != AF_UNIX ||
        address_len > sizeof(address) ||
        address_len < offsetof(struct sockaddr_un, sun_path) + path_len + 1 ||
        memcmp(address.sun_path, argv[1], path_len) != 0 || address.sun_path[path_len] != '\0' ||
        getsockopt(3, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0 ||
        type_len != sizeof(type) || type != SOCK_STREAM ||
        getsockopt(3, SOL_SOCKET, SO_ACCEPTCONN, &listening, &listening_len) != 0 ||
        listening_len != sizeof(listening) || !listening ||
        lstat(argv[1], &node) != 0 || !S_ISSOCK(node.st_mode) || node.st_ino > UINT32_MAX) {
        fputs("Inherited descriptor or socket path is invalid.\n", stderr);
        return 1;
    }
    struct unix_diag_vfs vfs = { 0 };
    if (!socket_vfs_inode((uint32_t)listener.st_ino, &vfs) ||
        major(node.st_dev) > 0xfff || minor(node.st_dev) > 0xfffff ||
        vfs.udiag_vfs_ino != (uint32_t)node.st_ino ||
        vfs.udiag_vfs_dev != (((uint32_t)major(node.st_dev) << 20) | (uint32_t)minor(node.st_dev))) {
        fputs("Inherited listener is not bound to the current socket node.\n", stderr);
        return 1;
    }
    return 0;
}
