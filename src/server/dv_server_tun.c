#include <unistd.h>

#include "dv_types.h"
#include "dv_tun.h"
#include "dv_event.h"
#include "dv_assert.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_log.h"
#include "dv_ip_pool.h"
#include "dv_trans.h"
#include "dv_server_socket.h"
#include "dv_server_core.h"
#include "dv_server_tun.h"
#include "dv_server_cycle.h"
#include "dv_server_conn.h"

dv_u8 dv_route_net[DV_IP_ADDRESS_LEN];
size_t dv_route_mask;
dv_event_t *dv_srv_tun_rev;
dv_event_t *dv_srv_tun_wev;

static void
dv_srv_tun_to_ssl(int sock, short event, void *arg)
{
    dv_trans_buf_t          *tbuf = &dv_trans_buf;
    dv_event_t              *wev = NULL;
    dv_buffer_t             *wbuf = NULL;
    dv_srv_conn_t           *conn = NULL;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    struct iphdr            *ip4 = NULL;
    struct ip6_hdr          *ip6 = NULL;
    void                    *ssl = NULL;
    int                     tun_fd = dv_srv_tun.tn_fd;
    ssize_t                 rlen = 0;
    int                     ret = DV_ERROR;

    DV_LOG(DV_LOG_INFO, "Tun package arrived!\n");
    rlen = read(sock, tbuf->tb_buf, tbuf->tb_buf_size);
    if (rlen <= 0) {
        DV_LOG(DV_LOG_INFO, "Tun read error(%zd)!\n", rlen);
        return;
    }

    if (dv_ip_is_v4(tbuf->tb_buf)) {
        ip4 = (void *)tbuf->tb_buf;
        wev = dv_ip_wev_find(&ip4->daddr, sizeof(ip4->daddr));
    } else {
        ip6 = (void *)tbuf->tb_buf;
        wev = dv_ip_wev_find(&ip6->ip6_dst, sizeof(ip6->ip6_dst));
    }

    if (wev == NULL) {
        DV_LOG(DV_LOG_INFO, "Find wev failed!\n");
        return;
    }
    
    conn = wev->et_conn;
    if (conn->sc_flags & DV_SK_CONN_FLAG_HANDSHAKED) {
        DV_LOG(DV_LOG_INFO, "Handshaking!\n");
        return;
    }

    wbuf = &conn->sc_wbuf;
    ssl = conn->sc_ssl;
    ret = dv_trans_data_to_ssl(tun_fd, ssl, wbuf, suite, tbuf, rlen);
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(wev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add wev failed!\n");
            return;
        }
    }
}

static void
dv_srv_buf_to_tun(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_srv_conn_t           *conn = ev->et_conn;
    dv_buffer_t             *wbuf = &conn->sc_wbuf;
    size_t                  ip_tlen = 0;
    int                     data_len = 0;
    int                     tun_fd = dv_srv_tun.tn_fd;
    int                     ret = DV_ERROR;

    data_len = wbuf->bf_head - wbuf->bf_tail;
    ip_tlen = dv_ip_datalen(wbuf->bf_head, data_len);
    ret = dv_trans_buf_to_tun(tun_fd, wbuf, ip_tlen);
    if (ret != DV_OK) {
        if (dv_event_add(ev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add wev failed!\n");
            return;
        }
    }
}

int
dv_srv_tun_ev_create(int tun_fd, size_t bufsize)
{
    dv_srv_conn_t   *conn = NULL;
    dv_event_t      *rev = NULL;
    dv_event_t      *wev = NULL;

    dv_assert(dv_srv_tun_rev == NULL && dv_srv_tun_wev == NULL);

    conn = dv_srv_conn_mem_alloc(tun_fd, NULL, bufsize);
    if (conn == NULL) {
        DV_LOG(DV_LOG_INFO, "Create tun conn failed!\n");
        return DV_ERROR;
    }

    rev = dv_srv_tun_rev = &conn->sc_rev;
    rev->et_handler = dv_srv_tun_to_ssl;
    dv_event_set_persist_read(tun_fd, rev);
    if (dv_event_add(rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Tun add rev failed!\n");
        return DV_ERROR;
    }

    wev = dv_srv_tun_wev = &conn->sc_wev;
    wev->et_handler = dv_srv_buf_to_tun;
    dv_event_set_write(tun_fd, wev);

    return DV_OK;
}

static void
_dv_srv_tun_ev_destroy(dv_event_t **ev)
{
    if (*ev == NULL) {
        return;
    }

    dv_event_del(*ev);
    dv_event_destroy(*ev);
    *ev = NULL;
}

void
dv_srv_tun_ev_destroy(void)
{
    dv_ip_pool_exit();
    _dv_srv_tun_ev_destroy(&dv_srv_tun_rev);
    _dv_srv_tun_ev_destroy(&dv_srv_tun_wev);
}
