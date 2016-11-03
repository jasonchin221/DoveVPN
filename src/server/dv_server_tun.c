

#include "dv_types.h"
#include "dv_tun.h"
#include "dv_event.h"
#include "dv_assert.h"
#include "dv_errno.h"
#include "dv_server_tun.h"

dv_event_t *dv_srv_tun_rev;
dv_event_t *dv_srv_tun_wev;

static void
dv_srv_tun_read_handler(int sock, short event, void *arg)
{
}

static void
dv_srv_buf_to_tun(int sock, short event, void *arg)
{
}

int
dv_srv_tun_ev_create(int tun_fd)
{
    dv_event_t      *ev = NULL;

    dv_assert(dv_srv_tun_rev == NULL && dv_srv_tun_wev == NULL);

    ev = dv_srv_tun_rev = dv_event_create();
    if (ev == NULL) {
        return DV_ERROR;
    }

    ev->et_handler = dv_srv_tun_read_handler;
    dv_event_set_persist_read(tun_fd, ev);

    ev = dv_srv_tun_wev = dv_event_create();
    if (ev == NULL) {
        dv_srv_tun_ev_destroy();
        return DV_ERROR;
    }

    ev->et_handler = dv_srv_buf_to_tun;
    dv_event_set_write(tun_fd, ev);

    return DV_OK;
}

static void
_dv_srv_tun_ev_destroy(dv_event_t **ev)
{
    if (*ev == NULL) {
        return;
    }

    dv_event_destroy(*ev);
    *ev = NULL;
}

void
dv_srv_tun_ev_destroy(void)
{
    _dv_srv_tun_ev_destroy(&dv_srv_tun_rev);
    _dv_srv_tun_ev_destroy(&dv_srv_tun_wev);
}
