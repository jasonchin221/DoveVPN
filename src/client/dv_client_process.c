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
#include "dv_client_ssl.h"
#include "dv_client_vpn.h"
#include "dv_socket.h"
#include "dv_lib.h"
#include "dv_proto.h"

#define DV_CLIENT_LOG_NAME  "DoveVPN-Client"

static dv_tun_t dv_client_tun;

int
dv_client_process(dv_client_conf_t *conf)
{
    const dv_proto_suite_t      *suite = NULL;
    void                        *ssl = NULL;
    int                         client_sockfd = -1;
    int                         ret = DV_ERROR;

    dv_log_init(DV_CLIENT_LOG_NAME);

    ret = dv_tun_init(&dv_client_tun);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    suite = dv_proto_suite_find(conf->cc_proto.cc_proto_type);
    if (suite == NULL) {
        DV_LOG(DV_LOG_INFO, "Find suite failed!\n");
        return DV_ERROR;
    }
    
    ret = dv_client_ssl_init(suite, &conf->cc_proto);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Init proto failed!\n");
        goto out;
    }

    if (dv_ip_version4(conf->cc_ip)) {
        client_sockfd = dv_sk_connect_v4(conf->cc_ip, conf->cc_port);
    } else {
        client_sockfd = dv_sk_connect_v6(conf->cc_ip, conf->cc_port);
    }
    if (client_sockfd < 0) {
        DV_LOG(DV_LOG_INFO, "Sk create failed!\n");
        goto out;
    }

    ssl = dv_client_ssl_conn_create(suite, client_sockfd);
    if (ssl == NULL) {
        goto out;
    }

    /* get and set tunnel ip via TLS */
    ret = dv_client_set_tun_ip(suite, ssl);
    if (ret != DV_OK) {
        goto out;
    }

    /* add tun fd and sockfd to epoll */

    sleep(10);
    ret = DV_OK;
out:
    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
    }

    if (client_sockfd >= 0) {
        close(client_sockfd);
    }
    dv_client_ssl_exit(suite);
    dv_tun_exit(&dv_client_tun);
    dv_log_exit();
    return ret;
}
