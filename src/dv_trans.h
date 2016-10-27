#ifndef __DV_TRANS_H__
#define __DV_TRANS_H__

typedef struct _dv_trans_buf_t {
    void    *tb_buf;
    size_t  tb_buf_size;
} dv_trans_buf_t;

extern int dv_trans_data_client(int tun_fd, void *ssl, void *buf,
        size_t buf_len, const dv_proto_suite_t *suite);
extern int dv_trans_init(size_t buf_size);
extern void dv_trans_exit(void);

#endif
