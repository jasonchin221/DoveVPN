#ifndef __DV_TRANS_H__
#define __DV_TRANS_H__

#include "dv_buffer.h"
#include "dv_event.h"


typedef int (*dv_ssl_err_handler)(int sock, dv_event_t *ev,
            const dv_proto_suite_t *suite);

typedef struct _dv_trans_buf_t {
    void    *tb_buf;
    size_t  tb_buf_size;
} dv_trans_buf_t;

extern dv_trans_buf_t dv_trans_buf;

extern void
dv_ssl_write_handler(int sock, short event, void *arg, dv_buffer_t *rbuf,
        int tun_fd, dv_event_handler peer_handler);
extern void
dv_ssl_read_handler(int sock, short event, void *arg, void *ssl, int tun_fd,
        const dv_proto_suite_t *suite, dv_buffer_t *rbuf, dv_u32 mtu,
        dv_ssl_err_handler err_handler);
extern int dv_trans_buf_to_tun(int tun_fd, dv_buffer_t *rbuf, size_t data_len);
extern int dv_trans_init(size_t buf_size);
extern void dv_trans_exit(void);
extern int dv_trans_data_to_ssl(int tun_fd, void *ssl, dv_buffer_t *buf,
        const dv_proto_suite_t *suite, dv_trans_buf_t *tbuf,
        ssize_t rlen);

#endif
