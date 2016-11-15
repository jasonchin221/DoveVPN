#ifndef __DV_SERVER_CONN_H__
#define __DV_SERVER_CONN_H__

#include "dv_buffer.h"
#include "dv_event.h"

typedef struct _dv_srv_conn_t {
    void            *sc_ssl;
    void            *sc_ip;
    int             sc_fd;
    dv_u32          sc_flags;
    dv_event_t      sc_wev;
    dv_event_t      sc_rev;
    dv_buffer_t     sc_rbuf;
    dv_buffer_t     sc_wbuf;
} dv_srv_conn_t;


