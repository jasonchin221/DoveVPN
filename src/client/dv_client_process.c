#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/epoll.h>

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
#include "dv_trans.h"

#define DV_CLIENT_LOG_NAME  "DoveVPN-Client"
#define DV_EVENT_MAX_NUM    10

static dv_tun_t dv_client_tun;

static void
dv_add_epoll_event(int epfd, struct epoll_event *ev, int fd, int event)
{
    ev->data.fd = fd;
    ev->events = event|EPOLLET;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev);
}

static void
dv_add_epoll_read_event(int epfd, struct epoll_event *ev, int fd)
{
    dv_add_epoll_event(epfd, ev, fd, EPOLLIN);
}

static void
dv_add_epoll_write_event(int epfd, struct epoll_event *ev, int fd)
{
    dv_add_epoll_event(epfd, ev, fd, EPOLLOUT);
}

int
dv_client_process(dv_client_conf_t *conf)
{
    const dv_proto_suite_t      *suite = NULL;
    void                        *ssl = NULL;
    dv_u8                       *wbuf = NULL;
    size_t                      wbuf_len = 0;
    struct epoll_event          ev = {};
    struct epoll_event          events[DV_EVENT_MAX_NUM] = {};
    int                         epfd = -1;
    int                         efd = -1;
    int                         nfds = 0;
    int                         tun_fd = 0;
    int                         i = 0;
    int                         client_sockfd = -1;
    int                         ret = DV_ERROR;

    dv_log_init(DV_CLIENT_LOG_NAME);

    ret = dv_tun_init(&dv_client_tun);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    tun_fd = dv_client_tun.tn_fd;
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
    ret = dv_client_set_tun_ip(dv_client_tun.tn_name, suite, ssl);
    if (ret != DV_OK) {
        goto out;
    }

    /* add tun fd and sockfd to epoll */
    epfd = epoll_create(1);
    if (epfd < 0) {
        goto out;
    }
    dv_add_epoll_read_event(epfd, &ev, client_sockfd);
    dv_add_epoll_read_event(epfd, &ev, tun_fd);

    while (1) {
        nfds = epoll_wait(epfd, events, DV_EVENT_MAX_NUM, -1);
        for (i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN) {
                if ((efd = events[i].data.fd) < 0) {
                    continue;
                }

                /* Ciphertext arrived */
                if (efd == client_sockfd) {
                    dv_add_epoll_read_event(epfd, &ev, efd);
                    continue;
                }
                /* Plaintext arrived */
                if (efd == tun_fd) {
                    ret = dv_trans_data_client(tun_fd, ssl, wbuf, wbuf_len, suite);
                    if (ret == 0) {
                        dv_add_epoll_read_event(epfd, &ev, efd);
                    } else {
                        dv_add_epoll_write_event(epfd, &ev, efd);
                    }
                    continue;
                }
            }
            if (events[i].events & EPOLLOUT) {
            }
        }
    }
    ret = DV_OK;
    close(epfd);
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
