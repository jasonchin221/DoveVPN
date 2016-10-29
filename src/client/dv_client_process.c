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

static void
dv_cli_tun_write_handler(int sock, short event, void *arg);

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
        goto out;
    }

    /* get and set tunnel ip via TLS */
    ret = dv_client_set_tun_ip(dv_client_tun.tn_name, suite, ssl);
    if (ret != DV_OK) {
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

static void *
dv_cli_ssl_recreate(dv_client_conf_t *conf, const dv_proto_suite_t *suite,
            void *ssl)
{  
    close(dv_cli_sockfd);
    suite->ps_ssl_free(ssl);

    return dv_cli_ssl_create(conf, suite);
}

static void
dv_cli_tun_read_handler(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->cc_ssl;
    const dv_proto_suite_t  *suite = conn->cc_suite;
    dv_client_conf_t        *conf = conn->cc_conf;
    int                     tun_fd = conn->cc_tun_fd;
    int                     ret = DV_ERROR;

    if (conn->cc_state == DV_CLI_CONN_STATE_RECONNECTING) {
        return;
    }

    ret = dv_trans_data_client(tun_fd, ssl, conn->cc_wbuf, suite);
    switch (ret) {
        case DV_OK:
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
        case -DV_EWANT_WRITE:
            ev->et_handler = dv_cli_tun_write_handler;
            dv_event_set_write(sock, ev);
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
        case -DV_ETUN:
            /* Do nothing */
            break;
        default:
            conn->cc_ssl = dv_cli_ssl_recreate(conf, suite, ssl);
            if (conn->cc_ssl == NULL) {
                dv_event_del(conn->cc_ev_ssl);
                conn->cc_state = DV_CLI_CONN_STATE_RECONNECTING;
                /* Add timer to try to rebuild ssl connection */
                return;
            }
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
    }
}
 
static void
dv_cli_tun_write_handler(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_cli_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->cc_ssl;
    const dv_proto_suite_t  *suite = conn->cc_suite;
    int                     tun_fd = conn->cc_tun_fd;
    int                     ret = DV_ERROR;

    ret = dv_buf_data_to_ssl(ssl, conn->cc_wbuf, suite);
    switch (ret) {
        case DV_OK:
            while (1) {
                ret = dv_trans_data_client(tun_fd, ssl,
                        conn->cc_wbuf, suite);
                if (ret == -DV_EWANT_READ) {
                    break;
                }

                /* proc return value */
                return;
            }
            ev->et_handler = dv_cli_tun_read_handler;
            dv_event_set_read(sock, ev);
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
        case -DV_EWANT_WRITE:
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
        default:
            break;
    }
}

static void
dv_cli_ssl_read_handler(int sock, short event, void *arg)
{
}

static void
dv_cli_conn_free(void *conn)
{
    dv_cli_conn_t           *c = conn;
    void                    *ssl = c->cc_ssl;
    const dv_proto_suite_t  *suite = c->cc_suite;

    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
    }
}

int
dv_client_process(dv_client_conf_t *conf)
{
    const dv_proto_suite_t      *suite = NULL;
    void                        *ssl = NULL;
    dv_event_t                  *ssl_ev = NULL;
    dv_event_t                  *tun_ev = NULL;
    dv_cli_conn_t               conn = {};
    int                         tun_fd = 0;
    int                         ret = DV_ERROR;

    dv_log_init(DV_CLIENT_LOG_NAME);

    ret = dv_event_init();
    if (ret != DV_OK) {
        return ret;
    }

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
        goto out;
    }

    conn.cc_wbuf = dv_buf_alloc(conf->cc_buffer_size);
    if (conn.cc_wbuf == NULL) {
        goto out;
    }

    tun_ev = dv_event_create();
    if (tun_ev == NULL) {
        goto out;
    }

    tun_ev->et_conn = &conn;
    dv_event_set_read(tun_fd, tun_ev);
    tun_ev->et_handler = dv_cli_tun_read_handler;
    if (dv_event_add(tun_ev) != DV_OK) {
        fprintf(stderr, "Add event failed!\n");
        goto out;
    }

    ssl_ev = dv_event_create();
    if (ssl_ev == NULL) {
        goto out;
    }

    ssl_ev->et_conn = &conn;
    ssl_ev->et_conn_free = dv_cli_conn_free;
    ssl_ev->et_handler = dv_cli_ssl_read_handler;
    conn.cc_ev_tun = tun_ev;
    conn.cc_ev_ssl = ssl_ev;
    dv_event_set_read(dv_cli_sockfd, ssl_ev);
    if (dv_event_add(ssl_ev) != DV_OK) {
        goto out;
    }

    ret = dv_process_events();
    printf("After loop, ret = %d\n", ret);
    ret = DV_ERROR;

out:
    dv_buf_free(conn.cc_wbuf);
    dv_buf_free(conn.cc_rbuf);
    dv_event_destroy(ssl_ev);
    dv_event_destroy(tun_ev);
    if (ssl != NULL) {
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
