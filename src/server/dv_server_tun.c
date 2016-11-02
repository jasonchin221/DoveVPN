

#include "dv_types.h"
#include "dv_tun.h"
#include "dv_event.h"
#include "dv_assert.h"
#include "dv_errno.h"

static void
dv_srv_tun_read_handler(int sock, short event, void *arg)
{
}

int
dv_srv_tun_ev_create(int tun_fd)
{
    dv_event_t      *ev = NULL;

    dv_assert(dv_srv_tun_ev == NULL);

    ev = dv_srv_tun_ev = dv_event_create();
    if (ev == NULL) {
        return DV_ERROR;
    }

    ev->et_handler = dv_srv_tun_read_handler;
    dv_event_set_accept_read(tun_fd, ev);
    if (dv_event_add(ev) != DV_OK) {
        dv_event_destroy(ev);
        dv_srv_tun_ev = NULL;
        return DV_ERROR;
    }

    return DV_OK;
}

void
dv_srv_tun_ev_destroy(void)
{
    if (dv_srv_tun_ev == NULL) {
        return;
    }

    dv_event_destroy(dv_srv_tun_ev);
    dv_srv_tun_ev = NULL;
}
