#ifndef __DV_CLIENT_PROCESS_H__
#define __DV_CLIENT_PROCESS_H__

#include "dv_buffer.h"
#include "dv_types.h"

enum {
    DV_CLI_CONN_STATE_NORMAL,
    DV_CLI_CONN_STATE_RECONNECTING,
};

typedef struct _dv_cli_conn_t {
    void            *cc_ssl;
    void            *cc_conf;
    void            *cc_ev_tun;
    void            *cc_ev_ssl;
    const void      *cc_suite;
    int             cc_tun_fd;
    dv_u32          cc_state;
    dv_buffer_t     *cc_rbuf;
    dv_buffer_t     *cc_wbuf;
} dv_cli_conn_t;

extern int dv_client_process(dv_client_conf_t *conf);

#endif
