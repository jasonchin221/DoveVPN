#ifndef __DV_TRANS_H__
#define __DV_TRANS_H__

#include "dv_buffer.h"
#include "dv_event.h"


typedef void (*dv_ssl_err_handler)(int sock, dv_event_t *ev,
            const dv_proto_suite_t *suite);

typedef struct _dv_trans_buf_t {
    void    *tb_buf;
    size_t  tb_buf_size;
} dv_trans_buf_t;

extern void
dv_ssl_write_handler(int sock, short event, void *arg, dv_buffer_t *rbuf,
        int tun_fd, dv_event_handler read_handler,
        dv_event_handler write_handler);
extern void
dv_ssl_read_handler(int sock, short event, void *arg, void *ssl, int tun_fd,
        const dv_proto_suite_t *suite, dv_buffer_t *rbuf,
        dv_event_handler write_handler, dv_ssl_err_handler err_handler);
extern int dv_trans_data_client(int tun_fd, void *ssl, dv_buffer_t *buf,
        const dv_proto_suite_t *suite);
extern int dv_trans_ssl_to_tun(int tun_fd, dv_buffer_t *rbuf, size_t data_len);
extern int dv_trans_init(size_t buf_size);
extern void dv_trans_exit(void);

#endif
