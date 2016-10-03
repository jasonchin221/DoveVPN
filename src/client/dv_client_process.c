#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "dv_types.h"
#include "dv_proto.h"
#include "dv_tun.h"
#include "dv_log.h"
#include "dv_errno.h"
#include "dv_client_conf.h"
#include "dv_socket.h"
#include "dv_lib.h"

#define DV_CLIENT_LOG_NAME  "DoveVPN-Client"

static dv_tun_t dv_client_tun;

int
dv_client_process(dv_client_conf_t *conf)
{
    int         sockfd = 0;
    int         ret = DV_ERROR;

    dv_log_init(DV_CLIENT_LOG_NAME);

    ret = dv_tun_init(&dv_client_tun, 1);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    if (dv_ip_version4(conf->cc_ip)) {
        sockfd = dv_sk_create_v4(conf->cc_ip, conf->cc_port);
    } else {
        sockfd = dv_sk_create_v6(conf->cc_ip, conf->cc_port);
    }

    if (sockfd < 0) {
        goto out;
    }

    /* get and set tunnel ip via TLS */
    /* add tun fd and sockfd to epoll */
    sleep(10);
    ret = DV_OK;
    close(sockfd);
out:
    dv_tun_exit(&dv_client_tun, 1);
    dv_log_exit();
    return ret;
}
