#include <unistd.h>

#include "dv_types.h"
#include "dv_socket.h"
#include "dv_event.h"
#include "dv_errno.h"

#define DV_SERVER_LISTEN_NUM    100

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
_dv_srv_accept(int sock, short event, void *arg, struct sockaddr *addr,
        socklen_t *addrlen)
{
    dv_event_t              *ev = NULL; 
    int                     accept_fd = 0;

    printf("Accept!\n");
    accept_fd = accept(sock, addr, addrlen); 
    if (accept_fd < 0) {
        return;
    }

    ev->et_ssl = suite->ps_ssl_new(ctx);
    if (ev->et_ssl == NULL) {
        return;
    }
    /* 将连接用户的 socket 加入到 SSL */
    suite->ps_set_fd(ssl, accept_fd);
    /* 建立 SSL 连接 */
    if (suite->ps_accept(ssl) == -1) {
        perror("accept");
        close(accept_fd);
        goto out;
    }
    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        printf("Client cert verify failed!\n");
        exit(1);
    }

    ev = dv_event_create();
    if (ev == NULL) {
        close(accept_fd);
        return;
    }

    ev->et_handler = dv_srv_read;
    dv_event_set_read(accept_fd, ev);
    if (dv_event_add(ev) != DV_OK) {
        close(accept_fd);
        dv_event_destroy(ev);
        return;
    }
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
