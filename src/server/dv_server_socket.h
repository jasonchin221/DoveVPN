#ifndef __DV_SERVER_SOCKET_H__
#define __DV_SERVER_SOCKET_H__

#define DV_SK_CONN_FLAG_HANDSHAKED      0x01

typedef struct _dv_sk_conn_t {
    void        *sc_ssl;
    char        *sc_buf;
    dv_u32      sc_flags;
    dv_u16      sc_buf_len;
    dv_u16      sc_data_len;
} dv_sk_conn_t;

extern void dv_sk_conn_free(void *conn);

#endif
