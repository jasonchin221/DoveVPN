#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_log.h"

int
dv_sk_create_v4(const char *dip, dv_u16 dport)
{
    struct sockaddr_in      dest = {
        .sin_family = AF_INET,
    };
    int                     sockfd = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return DV_ERROR;
    }

    dest.sin_port = DV_HTONS(dport);
    dest.sin_addr.s_addr = inet_addr(dip);
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        DV_LOG(DV_LOG_INFO, "Connect to dest  failed(%s)!\n", strerror(errno));
        return DV_ERROR;
    }
 
    return sockfd;
}

int
dv_sk_create_v6(const char *dip, dv_u16 dport)
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
    //dest.sin6_addr.s_addr = inet_addr(dip);
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0) {
        DV_LOG(DV_LOG_INFO, "Connect to dest  failed(%s)!\n", strerror(errno));
        return DV_ERROR;
    }
 
    return sockfd;
}
