#ifndef __DV_SERVER_SOCKET_H__
#define __DV_SERVER_SOCKET_H__

#define DV_SK_CONN_FLAG_HANDSHAKED      0x01

typedef struct _dv_sk_conn_t {
    void        *sc_ssl;
    void        *sc_ip;
    char        *sc_buf;
    dv_u32      sc_flags;
    size_t      sc_buf_len;
    size_t      sc_data_len;
} dv_sk_conn_t;

extern void dv_sk_conn_free(void *conn);

#endif
