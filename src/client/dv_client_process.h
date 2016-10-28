#ifndef __DV_CLIENT_PROCESS_H__
#define __DV_CLIENT_PROCESS_H__

#include "dv_buffer.h"

typedef struct _dv_cli_conn_t {
    void            *cc_ssl;
    const void      *cc_suite;
    int             cc_tun_fd;
    dv_buffer_t     *cc_rbuf;
    dv_buffer_t     *cc_wbuf;
} dv_cli_conn_t;

extern int dv_client_process(dv_client_conf_t *conf);

#endif
