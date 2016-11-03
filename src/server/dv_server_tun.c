

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
    dv_event_t              *ev = arg; 
    dv_sk_conn_t            *conn = ev->et_conn;
    dv_buffer_t             wbuf = conn->sc_buf;
    size_t                  ip_tlen = 0;
    int                     data_len = 0;
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

int
dv_srv_tun_ev_create(int tun_fd, size_t buf_size)
{
    dv_event_t      *rev = NULL;
    dv_event_t      *wev = NULL;
    dv_sk_conn_t    *conn = NULL;

    dv_assert(dv_srv_tun_rev == NULL && dv_srv_tun_wev == NULL);

    rev = dv_srv_tun_rev = dv_event_create();
    if (rev == NULL) {
        return DV_ERROR;
    }

    rev->et_handler = dv_srv_tun_read_handler;
    dv_event_set_persist_read(tun_fd, rev);

    wev = dv_srv_tun_wev = dv_event_create();
    if (wev == NULL) {
        dv_srv_tun_ev_destroy();
        return DV_ERROR;
    }

    wev->et_handler = dv_srv_buf_to_tun;
    dv_event_set_write(tun_fd, wev);

    conn = dv_sk_conn_alloc(buf_size);
    if (conn == NULL) {
        dv_srv_tun_ev_destroy();
        return DV_ERROR;
    }
    rev->et_conn_free = wev->et_conn_free = dv_sk_conn_free;
    wev->et_conn = dv_sk_conn_get(conn);
    rev->et_conn = wev->et_conn = conn;

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
