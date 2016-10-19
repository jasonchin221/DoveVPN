#include <unistd.h>

#include "dv_types.h"
#include "dv_socket.h"
#include "dv_event.h"
#include "dv_errno.h"

#define DV_SERVER_LISTEN_NUM    100

static dv_event_t *
dv_srv_add_listenning(int (*bind)(const char *, dv_u16),
            dv_event_handler callback, int port)
{
    dv_event_t  *ev = NULL; 
    int         fd = 0;

    fd = bind(NULL, port);
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
}

static void
dv_srv_accept(int sock, short event, void *arg, struct sockaddr *addr,
        socklen_t *addrlen)
{
    dv_event_t              *ev = NULL; 
    int                     accept_fd = 0;

    accept_fd = accept(sock, addr, addrlen); 
    if (accept_fd < 0) {
        return;
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
dv_srv_accept4(int sock, short event, void *arg)
{
    struct sockaddr_in      addr = {};
    socklen_t               addrlen = 0;

    dv_srv_accept(sock, event, arg, (struct sockaddr *)&addr, &addrlen);
}

static void
dv_srv_accept6(int sock, short event, void *arg)
{
    struct sockaddr_in6     addr = {};
    socklen_t               addrlen = 0;

    dv_srv_accept(sock, event, arg, (struct sockaddr *)&addr, &addrlen);
}

int
dv_srv_socket_init(int port)
{
    dv_event_t  *ev4 = NULL; 
    dv_event_t  *ev6 = NULL; 
    int         ret = DV_ERROR;

    ret = dv_event_init();
    if (ret != DV_OK) {
        return ret;
    }

    ev4 = dv_srv_add_listenning(dv_sk_bind_v4, dv_srv_accept4, port);
    if (ev4 == NULL) {
        dv_event_exit();
        return DV_ERROR;
    }
    ev6 = dv_srv_add_listenning(dv_sk_bind_v6, dv_srv_accept6, port);
    if (ev6 == NULL) {
        dv_event_del(ev4);
        dv_event_destroy(ev4);
        dv_event_exit();
        return DV_ERROR;
    }

    return DV_OK;
}
