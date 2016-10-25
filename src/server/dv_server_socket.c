#include <unistd.h>
#include <string.h>

#include "dv_types.h"
#include "dv_socket.h"
#include "dv_event.h"
#include "dv_errno.h"
#include "dv_mem.h"
#include "dv_server_socket.h"
#include "dv_server_core.h"
#include "dv_msg.h"
#include "dv_ip_pool.h"

#define DV_SERVER_LISTEN_NUM    100
#define DV_SERVER_BUF_SIZE      16384

static void
dv_srv_write(int sock, short event, void *arg);
static void
dv_srv_write_handshake(int sock, short event, void *arg);

dv_sk_conn_t *
dv_sk_conn_alloc(size_t buf_size)
{
    dv_sk_conn_t    *conn = NULL;

    if (buf_size > 65535) {
        return NULL;
    }

    conn = dv_calloc(sizeof(*conn) + buf_size);
    if (conn == NULL) {
        return NULL;
    }

    conn->sc_buf = (void *)(conn + 1);
    conn->sc_buf_len = buf_size;
    return conn;
}


void 
dv_sk_conn_free(void *conn)
{
    dv_sk_conn_t    *c = conn;

    if (c == NULL) {
        return;
    }

    if (c->sc_ip != NULL) {
        dv_subnet_ip_free(c->sc_ip);
    }

    dv_free(c);
}

static dv_event_t *
dv_srv_add_listenning(char *ip, dv_event_handler callback, int port)
{
    dv_event_t  *ev = NULL; 
    int         fd = 0;

    fd = dv_sk_bind(ip, port);
    if (fd < 0) {
        return NULL;
    }

    if (listen(fd, DV_SERVER_LISTEN_NUM) == -1) {
        close(fd);
        return NULL;
    }

    ev = dv_event_create();
    if (ev == NULL) {
        close(fd);
        return NULL;
    }

    ev->et_handler = callback;
    dv_event_set_read(fd, ev);

    if (dv_event_add(ev) != DV_OK) {
        close(fd);
        dv_event_destroy(ev);
        return NULL;
    }

    return ev;
}

static void
dv_srv_read(int sock, short event, void *arg)
{
    const dv_proto_suite_t  *suite = dv_srv_proto_suite;
    dv_event_t              *ev = arg; 
    dv_sk_conn_t            *conn = ev->et_conn;
    void                    *ssl = conn->sc_ssl;
    char                    rbuf[100] = {};
    int                     rlen = 0;

    printf("Read!\n");
    rlen = suite->ps_read(ssl, rbuf, sizeof(rbuf));
    if (rlen <= 0) {
        close(sock);
        dv_event_del(ev);
        dv_event_destroy(ev);
    }
}

static int
dv_srv_send_data(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_sk_conn_t            *conn = ev->et_conn;
    void                    *ssl = conn->sc_ssl;
    size_t                  mlen = conn->sc_data_len;
    int                     data_len = 0;
    int                     wlen = 0;

    wlen = suite->ps_write(ssl, conn->sc_buf, mlen);
    if (wlen < 0) {
        if (wlen == -DV_EWANT_READ) {
            ev->et_handler = dv_srv_write;
            dv_event_set_read(sock, ev);
        } else if (wlen == -DV_EWANT_WRITE) {
            ev->et_handler = dv_srv_write;
            dv_event_set_write(sock, ev);
        } else {
            return DV_ERROR;
        } 

        if (dv_event_add(ev) != DV_OK) {
            return DV_ERROR;
        }
        return DV_OK;
    }

    data_len = mlen - wlen;
    if (data_len > 0) {
        /* Need use ring to avoid copy */
        memmove(conn->sc_buf, conn->sc_buf + wlen, data_len);
        ev->et_handler = dv_srv_write;
    } else {
        ev->et_handler = dv_srv_read;
    }
    conn->sc_data_len = data_len;

    return DV_OK;
}

static void
dv_srv_write(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    const dv_proto_suite_t  *suite = dv_srv_proto_suite;
    int                     ret = DV_OK;

    printf("Write!\n");
    ret = dv_srv_send_data(sock, ev, suite);
    if (ret != DV_OK) {
        close(sock);
        dv_event_del(ev);
        dv_event_destroy(ev);
    }
}

static int
dv_srv_handshake_done(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_subnet_ip_t          *ip = NULL;
    void                    *ssl = conn->sc_ssl;
    size_t                  mlen = 0;

    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        return DV_ERROR;
    }

    ip = dv_subnet_ip_alloc();
    if (ip == NULL) {
        return DV_ERROR;
    }

    /* Send message to alloc ip address */
    conn->sc_ip = ip;
    mlen = dv_msg_ipalloc_build(conn->sc_buf, conn->sc_buf_len, 
            ip->si_ip, strlen(ip->si_ip), dv_get_subnet_mask());
    if (mlen == 0) {
        return DV_ERROR;
    }

    return dv_srv_send_data(sock, ev, suite);
}

static void
dv_srv_read_handshake(int sock, short event, void *arg)
{
    const dv_proto_suite_t  *suite = dv_srv_proto_suite;
    dv_event_t              *ev = arg; 
    dv_sk_conn_t            *conn = NULL;
    void                    *ssl = NULL;
    int                     ret = DV_OK;

    ssl = conn->sc_ssl;
    printf("Handshake! conn = %p\n", conn);
    conn = ev->et_conn;

    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    if (ret == DV_OK) {
        ret = dv_srv_handshake_done(sock, ev, suite);
        if (ret != DV_OK) {
            printf("Client cert verify failed!\n");
            goto out;
        }
        //conn->sc_flags |= DV_SK_CONN_FLAG_HANDSHAKED;
        return;
    }

    if (ret == -DV_EWANT_READ) {
        return;
    }

    if (ret == -DV_EWANT_WRITE) {
        dv_event_del(ev);
        ev->et_handler = dv_srv_write_handshake;
        dv_event_set_write(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

out:
    close(sock);
    dv_event_del(ev);
    dv_event_destroy(ev);
}

static void
dv_srv_write_handshake(int sock, short event, void *arg)
{
    const dv_proto_suite_t  *suite = dv_srv_proto_suite;
    dv_event_t              *ev = arg; 
    dv_sk_conn_t            *conn = NULL;
    void                    *ssl = NULL;
    int                     ret = DV_OK;

    printf("Handshake!\n");
    ssl = conn->sc_ssl;
    conn = ev->et_conn;

    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    if (ret == DV_OK) {
        ret = dv_srv_handshake_done(sock, ev, suite);
        if (ret != DV_OK) {
            printf("Client cert verify failed!\n");
            goto out;
        }
        goto want_read;
    }

    if (ret == DV_EWANT_READ) {
        ev->et_handler = dv_srv_read_handshake;
want_read:
        dv_event_set_read(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }

        return;
    }

    if (ret == DV_EWANT_WRITE) {
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

out:
    close(sock);
    dv_event_del(ev);
    dv_event_destroy(ev);
}


static void
_dv_srv_accept(int sock, short event, void *arg, struct sockaddr *addr,
        socklen_t *addrlen)
{
    const dv_proto_suite_t  *suite = dv_srv_proto_suite;
    void                    *ctx = dv_srv_ctx;
    dv_event_t              *ev = NULL; 
    dv_sk_conn_t            *conn = NULL;
    void                    *ssl = NULL;
    int                     accept_fd = 0;
    int                     ret = DV_OK;

    printf("Accept!\n");
    accept_fd = accept(sock, addr, addrlen); 
    if (accept_fd < 0) {
        return;
    }

    conn = dv_sk_conn_alloc(DV_SERVER_BUF_SIZE);
    if (conn == NULL) {
        goto out;
    }

    ssl = suite->ps_ssl_new(ctx);
    if (ssl == NULL) {
        goto out;
    }
    /* 将连接用户的 socket 加入到 SSL */
    suite->ps_set_fd(ssl, accept_fd);
    ev = dv_event_create();
    if (ev == NULL) {
        goto out;
    }

    conn->sc_ssl = ssl;
    ev->et_conn = conn;
    ev->et_conn_free = dv_sk_conn_free;
    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    switch (ret) {
        case DV_OK:
            ret = dv_srv_handshake_done(sock, ev, suite);
            if (ret != DV_OK) {
                printf("Client cert verify failed!\n");
                goto free_ev;
            }
            dv_event_set_read(accept_fd, ev);
            break;
        case DV_EWANT_READ:
            ev->et_handler = dv_srv_read_handshake;
            dv_event_set_read(accept_fd, ev);
            break;
        case DV_EWANT_WRITE:
            ev->et_handler = dv_srv_write_handshake;
            dv_event_set_write(accept_fd, ev);
            break;
        default:
            goto free_ev;
    }

    if (dv_event_add(ev) != DV_OK) {
        close(accept_fd);
        dv_event_destroy(ev);
        return;
    }
    return;
out:
    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
    }

free_ev:
    if (ev != NULL) {
        dv_event_destroy(ev);
    }

    close(accept_fd);
}

static void
dv_srv_accept(int sock, short event, void *arg)
{
    struct sockaddr_in6     addr = {};
    socklen_t               addrlen = 0;

    _dv_srv_accept(sock, event, arg, (struct sockaddr *)&addr, &addrlen);
}

int
dv_srv_socket_init(char *ip, int port)
{
    dv_event_t  *ev = NULL; 
    int         ret = DV_ERROR;

    ret = dv_event_init();
    if (ret != DV_OK) {
        return ret;
    }

    ev = dv_srv_add_listenning(ip, dv_srv_accept, port);
    if (ev == NULL) {
        dv_event_exit();
        return DV_ERROR;
    }

    return DV_OK;
}
