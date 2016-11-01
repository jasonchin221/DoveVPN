#ifndef __DV_SERVER_SOCKET_H__
#define __DV_SERVER_SOCKET_H__

#define DV_SK_CONN_FLAG_HANDSHAKED      0x01

#include "dv_buffer.h"

typedef struct _dv_sk_conn_t {
    void        *sc_ssl;
    void        *sc_ip;
    dv_buffer_t *sc_rbuf;
    dv_buffer_t *sc_wbuf;
    dv_u32      sc_flags;
} dv_sk_conn_t;

extern void dv_sk_conn_free(void *conn);
extern int dv_srv_ssl_socket_init(char *ip, int port);


#endif
