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
#include "dv_client_process.h"
#include "dv_socket.h"
#include "dv_lib.h"
#include "dv_proto.h"
#include "dv_trans.h"
#include "dv_event.h"

#define DV_CLIENT_LOG_NAME  "DoveVPN-Client"
#define DV_EVENT_MAX_NUM    10

static dv_tun_t dv_client_tun;
static int dv_cli_sockfd = -1;
static dv_event_t dv_cli_ssl_rev;
static dv_event_t dv_cli_ssl_wev;
static dv_event_t dv_cli_tun_rev;
static dv_event_t dv_cli_tun_wev;

static void
dv_cli_buf_to_ssl(int sock, short event, void *arg);
static void
dv_cli_ssl_to_tun(int sock, short event, void *arg);

static void *
dv_cli_ssl_create(dv_client_conf_t *conf, const dv_proto_suite_t *suite)
{  
    void        *ssl = NULL;
    int         ret = DV_OK;

    if (dv_ip_version4(conf->cc_ip)) {
        dv_cli_sockfd = dv_sk_connect_v4(conf->cc_ip, conf->cc_port);
    } else {
        dv_cli_sockfd = dv_sk_connect_v6(conf->cc_ip, conf->cc_port);
    }

    if (dv_cli_sockfd < 0) {
        DV_LOG(DV_LOG_INFO, "Sk create failed!\n");
        goto out;
    }

    ssl = dv_client_ssl_conn_create(suite, dv_cli_sockfd);
    if (ssl == NULL) {
        DV_LOG(DV_LOG_INFO, "SSL create failed!\n");
        goto out;
    }

    /* get and set tunnel ip via TLS */
    ret = dv_client_set_tun_ip(dv_client_tun.tn_name, suite, ssl);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Set tun failed!\n");
        goto out;
    }

    return ssl;

out:
    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
    }

    if (dv_cli_sockfd >= 0) {
        close(dv_cli_sockfd);
    }

    return NULL;
}

static int
dv_cli_ssl_err_handler(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    exit(1);
    return DV_OK;
}
 
static void
dv_cli_tun_to_ssl(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->cc_ssl;
    const dv_proto_suite_t  *suite = conn->cc_suite;
    int                     tun_fd = conn->cc_tun_fd;
    int                     ret = DV_ERROR;

    while (1) {
        ret = dv_trans_data_to_ssl(tun_fd, ssl, conn->cc_wbuf,
                suite, &dv_trans_buf, 0);
        switch (ret) {
            case DV_OK:
                continue;
            case -DV_EWANT_READ:
                if (dv_event_add(ev) != DV_OK) {
                }
                return;
            case -DV_EWANT_WRITE:
                if (dv_event_add(ev->et_peer_ev) != DV_OK) {
                }
                break;
            case -DV_ETUN:
                /* Do nothing */
                break;
            default:
                dv_cli_ssl_err_handler(sock, ev, suite);
                break;
        }
    }
}
 
static void
dv_cli_buf_to_ssl(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->cc_ssl;
    const dv_proto_suite_t  *suite = conn->cc_suite;
    int                     ret = DV_ERROR;

    while (1) {
        ret = dv_buf_data_to_ssl(ssl, conn->cc_wbuf, suite);
        switch (ret) {
            case DV_OK:
                dv_cli_tun_to_ssl(sock, event, ev->et_peer_ev);
                return;
            case -DV_EWANT_WRITE:
                if (dv_event_add(ev) != DV_OK) {
                    return;
                }
                return;
            default:
                dv_cli_ssl_err_handler(sock, ev, suite);
                break;
        }
    }
}

static void
dv_cli_buf_to_tun(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    dv_buffer_t             *wbuf = conn->cc_wbuf;
    size_t                  ip_tlen = 0;
    int                     data_len = 0;
    int                     tun_fd = conn->cc_tun_fd;
    int                     ret = DV_ERROR;

    data_len = wbuf->bf_head - wbuf->bf_tail;
    ip_tlen = dv_ip_datalen(wbuf->bf_head, data_len);
    ret = dv_trans_buf_to_tun(tun_fd, wbuf, ip_tlen);
    if (ret != DV_OK) {
        if (dv_event_add(ev) != DV_OK) {
            return;
        }
    }
}

static void
dv_cli_ssl_to_tun(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->cc_ssl;
    const dv_proto_suite_t  *suite = conn->cc_suite;
    dv_buffer_t             *rbuf = conn->cc_rbuf;
    int                     tun_fd = conn->cc_tun_fd;

    dv_ssl_read_handler(sock, event, arg, ssl, tun_fd, suite, rbuf,
        dv_cli_ssl_err_handler);
}

static void
dv_cli_conn_free(void *conn)
{
    dv_cli_conn_t           *c = conn;
    void                    *ssl = c->cc_ssl;
    const dv_proto_suite_t  *suite = c->cc_suite;

    if (ssl != NULL) {
        suite->ps_shutdown(ssl);
        suite->ps_ssl_free(ssl);
        c->cc_ssl = NULL;
    }

    dv_buf_free(c->cc_wbuf);
    dv_buf_free(c->cc_rbuf);
}

int
dv_client_process(dv_client_conf_t *conf)
{
    const dv_proto_suite_t      *suite = NULL;
    void                        *ssl = NULL;
    dv_event_t                  *ssl_rev = &dv_cli_ssl_rev;
    dv_event_t                  *ssl_wev = &dv_cli_ssl_wev;
    dv_event_t                  *tun_rev = &dv_cli_tun_rev;
    dv_event_t                  *tun_wev = &dv_cli_tun_wev;
    dv_cli_conn_t               conn = {};
    int                         tun_fd = 0;
    int                         ret = DV_ERROR;

    dv_log_init(DV_CLIENT_LOG_NAME);
    dv_log_print = 1;
    ret = dv_event_init();
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Event init failed!\n");
        return ret;
    }

    ret = dv_tun_init(&dv_client_tun);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Tun init failed!\n");
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

    ssl = dv_cli_ssl_create(conf, suite);
    if (ssl == NULL) {
        DV_LOG(DV_LOG_INFO, "Create ssl failed!\n");
        return DV_ERROR;
    }
    
    conn.cc_ssl = ssl;
    conn.cc_suite = suite;
    conn.cc_tun_fd = tun_fd;
    conn.cc_conf = conf;
    ssl = NULL;
    conn.cc_rbuf = dv_buf_alloc(conf->cc_buffer_size);
    if (conn.cc_rbuf == NULL) {
        DV_LOG(DV_LOG_INFO, "Buffer alloc failed!\n");
        goto out;
    }

    conn.cc_wbuf = dv_buf_alloc(conf->cc_buffer_size);
    if (conn.cc_wbuf == NULL) {
        DV_LOG(DV_LOG_INFO, "Buffer alloc failed!\n");
        goto out;
    }

    tun_rev->et_conn = tun_wev->et_conn = &conn;
    dv_event_set_read(tun_fd, tun_rev);
    tun_rev->et_handler = dv_cli_tun_to_ssl;
    dv_event_set_write(tun_fd, tun_wev);
    tun_wev->et_handler = dv_cli_buf_to_tun;
    if (dv_event_add(tun_rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Add event failed!\n");
        goto out;
    }

    ssl_rev->et_conn = ssl_wev->et_conn = &conn;
    ssl_rev->et_handler = dv_cli_ssl_to_tun;
    dv_event_set_read(dv_cli_sockfd, ssl_rev);
    ssl_wev->et_handler = dv_cli_buf_to_ssl;
    dv_event_set_write(dv_cli_sockfd, ssl_wev);
    if (dv_event_add(ssl_rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Add event failed!\n");
        goto out;
    }

    ssl_rev->et_peer_ev = tun_wev;
    tun_wev->et_peer_ev = ssl_rev;
    ssl_wev->et_peer_ev = tun_rev;
    tun_rev->et_peer_ev = ssl_wev;

    ret = dv_process_events();
    DV_LOG(DV_LOG_INFO, "After loop, ret = %d\n", ret);
    ret = DV_ERROR;

out:
    dv_cli_conn_free(&conn);
    dv_event_destroy(ssl_rev);
    dv_event_destroy(ssl_wev);
    dv_event_destroy(tun_rev);
    dv_event_destroy(tun_wev);
    if (ssl != NULL) {
        suite->ps_shutdown(ssl);
        suite->ps_ssl_free(ssl);
    }

    if (dv_cli_sockfd >= 0) {
        close(dv_cli_sockfd);
    }
    dv_client_ssl_exit(suite);
    dv_tun_exit(&dv_client_tun);
    dv_event_exit();
    dv_log_exit();
    return ret;
}
