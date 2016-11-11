#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_log.h"

int
dv_sk_connect_v4(const char *dip, dv_u16 dport)
{
    struct sockaddr_in      dest = {
        .sin_family = AF_INET,
    };
    int                     sockfd = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        DV_LOG(DV_LOG_INFO, "Socket syscall failed(%s)!\n", strerror(errno));
        return DV_ERROR;
    }

    dest.sin_port = DV_HTONS(dport);
    dest.sin_addr.s_addr = inet_addr(dip);
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        DV_LOG(DV_LOG_INFO, "Connect to dest failed(%s)!\n", strerror(errno));
        return DV_ERROR;
    }
 
    return sockfd;
}

int
dv_sk_connect_v6(const char *dip, dv_u16 dport)
{
    struct sockaddr_in6     dest = {
        .sin6_family = AF_INET6,
    };
    int                     sockfd = 0;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return DV_ERROR;
    }

    dest.sin6_port = DV_HTONS(dport);
    inet_pton(AF_INET6, dip, &dest.sin6_addr);
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        DV_LOG(DV_LOG_INFO, "Connect to dest %s[%d] failed(%s)!\n",
                dip, dport, strerror(errno));
        return DV_ERROR;
    }
 
    return sockfd;
}

int
dv_sk_bind(const char *dip, dv_u16 dport)
{
    struct sockaddr_in6     dest = {
        .sin6_family = AF_INET6,
    };
    int                     sockfd = 0;
    int                     reuse = 1;

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return DV_ERROR;
    }

    dest.sin6_port = DV_HTONS(dport);

    if (dip == NULL || strlen(dip) == 0) {
        dest.sin6_addr = in6addr_any;
    } else {
        inet_pton(AF_INET6, dip, &dest.sin6_addr);
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (bind(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        DV_LOG(DV_LOG_INFO, "Bind to dest  failed(%s)!\n", strerror(errno));
        return DV_ERROR;
    }
 
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    return sockfd;
}
