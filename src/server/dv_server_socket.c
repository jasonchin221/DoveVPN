#include <unistd.h>

#include "dv_types.h"
#include "dv_socket.h"
#include "dv_event.h"
#include "dv_errno.h"
#include "dv_mem.h"
#include "dv_server_socket.h"
#include "dv_server_core.h"

#define DV_SERVER_LISTEN_NUM    100
#define DV_SERVER_BUF_SIZE      16384

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
    if (conn == NULL) {
        return;
    }

    dv_free(conn);
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
    dv_event_t              *ev = arg; 
    printf("Read!\n");
    close(sock);
    dv_event_del(ev);
    dv_event_destroy(ev);
}

static void
dv_srv_handshake(int sock, short event, void *arg)
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
        if (suite->ps_get_verify_result(ssl) != DV_OK) {
            printf("Client cert verify failed!\n");
            goto out;
        }
        //handler = dv_srv_read;
        conn->sc_flags |= DV_SK_CONN_FLAG_HANDSHAKED;
        return;
    }

    if (ret == DV_EWANT_READ) {
        return;
    }

    if (ret == DV_EWANT_WRITE) {
            //add write event
        return;
    }

out:
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
    dv_event_handler        handler = NULL;
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
    /* 建立 SSL 连接 */
    ret = suite->ps_accept(ssl);
    switch (ret) {
        case DV_OK:
            if (suite->ps_get_verify_result(ssl) != DV_OK) {
                printf("Client cert verify failed!\n");
                goto out;
            }
            handler = dv_srv_read;
            break;
        case DV_EWANT_READ:
            handler = dv_srv_handshake;
            break;
        case DV_EWANT_WRITE:
            //add write event
            handler = dv_srv_handshake;
            break;
        default:
            goto out;
    }

    ev = dv_event_create();
    if (ev == NULL) {
        goto out;
    }

    conn->sc_ssl = ssl;
    ev->et_conn = conn;
    ev->et_conn_free = dv_sk_conn_free;
    ev->et_handler = handler;
    dv_event_set_read(accept_fd, ev);
    if (dv_event_add(ev) != DV_OK) {
        close(accept_fd);
        dv_event_destroy(ev);
        return;
    }
    return;
out:
    if (conn != NULL) {
        dv_sk_conn_free(conn);
    }

    if (ssl != NULL) {
        suite->ps_ssl_free(ssl);
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
