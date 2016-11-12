#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "dv_types.h"
#include "dv_socket.h"
#include "dv_event.h"
#include "dv_errno.h"
#include "dv_mem.h"
#include "dv_server_socket.h"
#include "dv_server_core.h"
#include "dv_msg.h"
#include "dv_ip_pool.h"
#include "dv_server_cycle.h"
#include "dv_trans.h"
#include "dv_log.h"
#include "dv_server_tun.h"

#define DV_SERVER_LISTEN_NUM    100
#define DV_SERVER_BUF_SIZE      16384

static void dv_srv_ssl_to_tun(int sock, short event, void *arg);

dv_sk_conn_t *
dv_sk_conn_alloc(size_t buf_size)
{
    dv_sk_conn_t    *conn = NULL;

    if (buf_size > 65535) {
        return NULL;
    }

    conn = dv_calloc(sizeof(*conn));
    if (conn == NULL) {
        return NULL;
    }

    conn->sc_buf = dv_buf_alloc(buf_size);
    if (conn->sc_buf == NULL) {
        goto out;
    }

    conn->sc_ref = 1;

    return conn;
out:
    dv_sk_conn_free(conn);
    return NULL;
}

dv_sk_conn_t *
dv_sk_conn_get(dv_sk_conn_t *conn)
{
    conn->sc_ref++;

    return conn;
}

void 
dv_sk_conn_free(void *conn)
{
    dv_sk_conn_t            *c = conn;
    void                    *ssl = c->sc_ssl;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;

    if (c == NULL) {
        return;
    }

    if (--c->sc_ref != 0) {
        return;
    }

    if (c->sc_ip != NULL) {
        dv_subnet_ip_free(c->sc_ip);
    }

    if (c->sc_buf != NULL) {
        dv_buf_free(c->sc_buf);
    }

    if (c->sc_ssl != NULL) {
        suite->ps_shutdown(ssl);
        suite->ps_ssl_free(ssl);
    }

    dv_free(c);
}

static dv_event_t *
dv_srv_ssl_add_listenning(char *ip, dv_event_handler callback, int port)
{
    dv_event_t  *ev = NULL; 
    int         fd = 0;

    fd = dv_sk_bind(ip, port);
    if (fd < 0) {
        DV_LOG(DV_LOG_INFO, "Bind failed!\n");
        return NULL;
    }

    if (listen(fd, DV_SERVER_LISTEN_NUM) == -1) {
        close(fd);
        DV_LOG(DV_LOG_INFO, "Listen failed!\n");
        return NULL;
    }

    ev = dv_event_create();
    if (ev == NULL) {
        close(fd);
        DV_LOG(DV_LOG_INFO, "Event create failed!\n");
        return NULL;
    }

    ev->et_handler = callback;
    dv_event_set_persist_read(fd, ev);

    if (dv_event_add(ev) != DV_OK) {
        close(fd);
        dv_event_destroy(ev);
        return NULL;
    }

    return ev;
}

static int
dv_srv_ssl_err_handler(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_event_t              *wev = conn->sc_wev;

    close(sock);
    dv_event_destroy(ev);
    dv_event_del(wev);
    dv_event_destroy(wev);

    return DV_ERROR;
}

static void
dv_srv_ssl_to_tun(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_event_t              *peer_ev = ev->et_peer_ev; 
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_sk_conn_t            *peer_conn = peer_ev->et_conn;
    void                    *ssl = conn->sc_ssl;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    dv_buffer_t             *rbuf = peer_conn->sc_buf;
    int                     tun_fd = dv_srv_tun.tn_fd;

    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    dv_ssl_read_handler(sock, event, arg, ssl, tun_fd, suite, rbuf,
        dv_srv_ssl_err_handler);
}

static int
dv_srv_ssl_send_data(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_buffer_t             *wbuf = conn->sc_buf;
    dv_event_t              *wev = conn->sc_wev;
    void                    *ssl = conn->sc_ssl;
    int                     ret = DV_OK;

    ev->et_handler = dv_srv_ssl_to_tun;
    dv_event_set_read(sock, ev);
    ret = dv_buf_data_to_ssl(ssl, wbuf, suite);
    if (ret == DV_OK) {
        if (dv_event_add(ev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add read event failed!\n");
            return DV_ERROR;
        }
        return DV_OK;
    } 
    
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(ev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add read event failed!\n");
            return DV_ERROR;
        }
 
        if (dv_event_add(wev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add write event failed!\n");
            return DV_ERROR;
        }
        return DV_OK;
    }
 
    DV_LOG(DV_LOG_INFO, "Unknown return value %d!\n", ret);
    return DV_ERROR;
}

static int
dv_srv_ssl_handshake_done(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_buffer_t             *wbuf = conn->sc_buf;
    void                    *ssl = conn->sc_ssl;
    dv_subnet_ip_t          *ip = NULL;
    size_t                  mlen = 0;
    int                     ret = DV_ERROR;

    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Verify failed!\n");
        return DV_ERROR;
    }

    ip = dv_subnet_ip_alloc();
    if (ip == NULL) {
        DV_LOG(DV_LOG_INFO, "Alloc ip failed!\n");
        return DV_ERROR;
    }

    /* Send message to alloc ip address */
    conn->sc_ip = ip;

    mlen = dv_msg_ipalloc_build(wbuf->bf_head, wbuf->bf_bsize,
            ip->si_ip, strlen(ip->si_ip) + 1, dv_get_subnet_mask(),
            dv_get_subnet_mtu(), dv_route_net, dv_route_mask);
    if (mlen == 0) {
        DV_LOG(DV_LOG_INFO, "Build ipalloc msg failed!\n");
        return DV_ERROR;
    }

    wbuf->bf_tail += mlen;
    ip->si_wev = conn->sc_wev;

    dv_ip_hash_add(ip);

    ret = dv_srv_ssl_send_data(sock, ev, suite);
    if (ret != DV_OK) {
        return ret;
    }

    conn->sc_flags &= ~DV_SK_CONN_FLAG_HANDSHAKED;

    return DV_OK;
}

static void
dv_srv_ssl_handshake(int sock, short event, void *arg)
{
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    dv_event_t              *ev = arg; 
    dv_event_t              *wev = NULL; 
    dv_sk_conn_t            *conn = ev->et_conn;
    void                    *ssl = NULL;
    int                     ret = DV_OK;

    ssl = conn->sc_ssl;
    conn = ev->et_conn;

    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    if (ret == DV_OK) {
        ret = dv_srv_ssl_handshake_done(sock, ev, suite);
        if (ret == DV_ERROR) {
            DV_LOG(DV_LOG_INFO, "Handshake done proc failed!\n");
            goto out;
        }
        //conn->sc_flags |= DV_SK_CONN_FLAG_HANDSHAKED;
        return;
    }

    if (ret == -DV_EWANT_READ) {
        dv_event_set_read(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

    if (ret == -DV_EWANT_WRITE) {
        dv_event_set_write(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

out:
    wev = conn->sc_wev;
    dv_event_destroy(wev);
    dv_event_destroy(ev);
    close(sock);
}

static void
dv_srv_buf_to_ssl(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_event_t              *rev = conn->sc_rev; 
    dv_buffer_t             *wbuf = conn->sc_buf;
    void                    *ssl = conn->sc_ssl;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    int                     ret = DV_OK;

    ret = dv_buf_data_to_ssl(ssl, wbuf, suite);
    if (ret == DV_OK) {
        conn->sc_flags &= ~DV_SK_CONN_FLAG_HANDSHAKED;
        return;
    } 
    
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(ev) == DV_OK) {
            return;
        }
    }

    dv_event_destroy(ev);
    dv_event_del(rev);
    dv_event_destroy(rev);
}

static void
_dv_srv_ssl_accept(int sock, short event, void *arg, struct sockaddr *addr,
        socklen_t *addrlen)
{
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    void                    *ctx = dv_srv_ssl_ctx;
    dv_event_t              *rev = NULL; 
    dv_event_t              *wev = NULL; 
    dv_sk_conn_t            *conn = NULL;
    void                    *ssl = NULL;
    int                     accept_fd = 0;
    int                     ret = DV_OK;

    DV_LOG(DV_LOG_INFO, "Accept!\n");
    accept_fd = accept(sock, addr, addrlen); 
    if (accept_fd < 0) {
        DV_LOG(DV_LOG_INFO, "Accept failed!\n");
        return;
    }

    if (fcntl(accept_fd, F_SETFL, O_NONBLOCK) == -1) {
        DV_LOG(DV_LOG_INFO, "Set noblock failed!\n");
        return;
    }

    conn = dv_sk_conn_alloc(DV_SERVER_BUF_SIZE);
    if (conn == NULL) {
        DV_LOG(DV_LOG_INFO, "Alloc conn failed!\n");
        goto out;
    }

    ssl = suite->ps_ssl_new(ctx);
    if (ssl == NULL) {
        DV_LOG(DV_LOG_INFO, "New ssl failed!\n");
        goto out;
    }
    /* 将连接用户的 socket 加入到 SSL */
    suite->ps_set_fd(ssl, accept_fd);
    rev = dv_event_create();
    if (rev == NULL) {
        DV_LOG(DV_LOG_INFO, "Create event failed!\n");
        goto out;
    }

    conn->sc_ssl = ssl;
    conn->sc_rev = rev;
    rev->et_conn = conn;
    rev->et_conn_free = dv_sk_conn_free;
    rev->et_peer_ev = dv_srv_tun_wev;
    wev = dv_event_create();
    if (wev == NULL) {
        DV_LOG(DV_LOG_INFO, "Create event failed!\n");
        goto out;
    }

    wev->et_conn = dv_sk_conn_get(conn);
    wev->et_conn_free = dv_sk_conn_free;
    wev->et_handler = dv_srv_buf_to_ssl;
    dv_event_set_write(accept_fd, wev);
    conn->sc_wev = wev;

    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    DV_LOG(DV_LOG_INFO, "ssl accept ret = %d!\n", ret);
    conn->sc_flags |= DV_SK_CONN_FLAG_HANDSHAKED;
    switch (ret) {
        case DV_OK:
            ret = dv_srv_ssl_handshake_done(accept_fd, rev, suite);
            if (ret == DV_ERROR) {
                DV_LOG(DV_LOG_INFO, "Handshake done proc failed!\n");
                goto free_ev;
            }
            return;
        case -DV_EWANT_READ:
            rev->et_handler = dv_srv_ssl_handshake;
            dv_event_set_read(accept_fd, rev);
            break;
        case -DV_EWANT_WRITE:
            rev->et_handler = dv_srv_ssl_handshake;
            dv_event_set_write(accept_fd, rev);
            break;
        default:
            goto free_ev;
    }

    if (dv_event_add(rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Add rev failed!\n");
        goto free_ev;
    }
    return;
out:
    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
    }

free_ev:
    if (wev != NULL) {
        dv_event_destroy(wev);
    }

    if (rev != NULL) {
        dv_event_destroy(rev);
    }

    close(accept_fd);
}

static void
dv_srv_ssl_accept(int sock, short event, void *arg)
{
    struct sockaddr_in6     addr = {};
    socklen_t               addrlen = 0;

    _dv_srv_ssl_accept(sock, event, arg, (struct sockaddr *)&addr, &addrlen);
}

int
dv_srv_ssl_socket_init(char *ip, int port)
{
    dv_event_t  *ev = NULL; 
    int         ret = DV_ERROR;

    ret = dv_event_init();
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Event init failed!\n");
        return ret;
    }

    ev = dv_srv_ssl_add_listenning(ip, dv_srv_ssl_accept, port);
    if (ev == NULL) {
        DV_LOG(DV_LOG_INFO, "Add listenning failed!\n");
        dv_event_exit();
        return DV_ERROR;
    }

    return DV_OK;
}
