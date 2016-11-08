#include <string.h>
#include <unistd.h>


#include "dv_types.h"
#include "dv_mem.h"
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_trans.h"
#include "dv_assert.h"
#include "dv_lib.h"

#define DV_IP_HEADER_MIN_LEN    20

dv_trans_buf_t dv_trans_buf;

int
dv_trans_init(size_t buf_size)
{
    if (dv_trans_buf.tb_buf != NULL) {
        return DV_ERROR;
    }

    dv_trans_buf.tb_buf = dv_malloc(buf_size);
    if (dv_trans_buf.tb_buf == NULL) {
        return DV_ERROR;
    }

    dv_trans_buf.tb_buf_size = buf_size;

    return DV_OK;
}

void
dv_trans_exit(void)
{
    if (dv_trans_buf.tb_buf != NULL) {
        dv_free(dv_trans_buf.tb_buf);
        memset(&dv_trans_buf, 0, sizeof(dv_trans_buf));
    }
}

static void
dv_trans_buf_info_get(dv_buffer_t *buf, int *data_len, int *space,
        int *tail_len)
{
    if (buf->bf_flag & DV_BUF_FLAG_FULL) {
        dv_assert(buf->bf_head == buf->bf_tail);
        *tail_len = *space = 0;
        *data_len = buf->bf_bsize;
    } else if (buf->bf_tail >= buf->bf_head) {
        *data_len = buf->bf_tail - buf->bf_head;
        *space = buf->bf_bsize - *data_len;
        *tail_len = buf->bf_buf + buf->bf_bsize - buf->bf_tail;
    } else {
        *tail_len = *space = buf->bf_head - buf->bf_tail;
        *data_len = buf->bf_bsize - *space;
    }
}

int
dv_trans_data_to_ssl(int tun_fd, void *ssl, dv_buffer_t *buf,
        const dv_proto_suite_t *suite, ssize_t rlen)
{
    dv_trans_buf_t      *tbuf = &dv_trans_buf;
    int                 space = 0;
    int                 tail_len = 0;
    int                 wlen = 0;
    int                 data_len = 0;

    dv_assert(tbuf->tb_buf != NULL);

    dv_trans_buf_info_get(buf, &tail_len, &space, &tail_len);

    if (rlen == 0) {
        rlen = read(tun_fd, tbuf->tb_buf, tbuf->tb_buf_size);
        if (rlen == 0) {
            return -DV_EWANT_READ;
        }

        if (rlen < 0) {
            return -DV_ETUN;
        }

        if (rlen > space) {
            return -DV_EWANT_WRITE;
        }
    }

    if (data_len == 0) {
        wlen = suite->ps_write(ssl, tbuf->tb_buf, rlen);
        if (wlen == rlen) {
            return DV_OK;
        }

        if (wlen < 0) {
            if (wlen == -DV_EWANT_WRITE) {
                wlen = 0;
            } else {
                fprintf(stderr, "Send data failed! mlen = %d\n", (int)rlen);
                suite->ps_shutdown(ssl);
                return DV_ERROR;
            } 
        }
    }

    data_len = rlen - wlen;
    if (data_len <= tail_len) {
        memcpy(buf->bf_tail, (dv_u8 *)tbuf->tb_buf + wlen, data_len);
        buf->bf_tail += data_len;
        if (buf->bf_tail == (buf->bf_buf + buf->bf_bsize)) {
            buf->bf_tail = buf->bf_buf;
        }
    } else {
        memcpy(buf->bf_tail, (dv_u8 *)tbuf->tb_buf + wlen, tail_len);
        memcpy(buf->bf_buf, (dv_u8 *)tbuf->tb_buf + wlen + tail_len,
                data_len - tail_len);
        buf->bf_tail = buf->bf_buf + data_len - tail_len;
    }

    if (buf->bf_tail == buf->bf_head) {
        buf->bf_flag |= DV_BUF_FLAG_FULL;
    }

    return -DV_EWANT_WRITE;
}

int
dv_trans_buf_to_tun(int tun_fd, dv_buffer_t *rbuf, size_t data_len)
{
    ssize_t                 wlen = 0;
    int                     dlen = 0;

    wlen = write(tun_fd, rbuf->bf_head, data_len);
    if (wlen == data_len) {
        rbuf->bf_head += data_len;
        dlen = rbuf->bf_tail - rbuf->bf_head;
        if (dlen < DV_IP_HEADER_MIN_LEN || 
                dv_ip_datalen(rbuf->bf_head, dlen) >
                rbuf->bf_bsize - (rbuf->bf_head - rbuf->bf_buf)) {
            memmove(rbuf->bf_buf, rbuf->bf_head, dlen);
            rbuf->bf_tail -= (rbuf->bf_head - rbuf->bf_buf);
            rbuf->bf_head = rbuf->bf_buf;
        }

        return DV_OK;
    }

    return -DV_EWANT_WRITE;
}

void
dv_ssl_write_handler(int sock, short event, void *arg, dv_buffer_t *wbuf,
        int tun_fd, dv_event_handler peer_handler)
{
    dv_event_t              *ev = arg; 
    size_t                  ip_tlen = 0;
    int                     data_len = 0;
    int                     ret = DV_ERROR;

    data_len = wbuf->bf_head - wbuf->bf_tail;
    ip_tlen = dv_ip_datalen(wbuf->bf_head, data_len);
    ret = dv_trans_buf_to_tun(tun_fd, wbuf, ip_tlen);
    if (ret != DV_OK) {
        if (dv_event_add(ev) != DV_OK) {
            return;
        }
        return;
    }

    peer_handler(sock, event, ev->et_peer_ev);
}

void
dv_ssl_read_handler(int sock, short event, void *arg, void *ssl, int tun_fd,
        const dv_proto_suite_t *suite, dv_buffer_t *rbuf,
        dv_ssl_err_handler err_handler)
{
    dv_event_t              *ev = arg; 
    int                     rlen = 0;
    size_t                  ip_tlen = 0;
    int                     data_len = 0;
    int                     ret = DV_ERROR;

    while (1) {
        rlen = suite->ps_read(ssl, rbuf->bf_tail, rbuf->bf_bsize - 
                (rbuf->bf_tail - rbuf->bf_buf));
        if (rlen > 0) {
            rbuf->bf_tail += rlen;
            data_len = rbuf->bf_head - rbuf->bf_tail;
            ip_tlen = dv_ip_datalen(rbuf->bf_head, data_len);
            if (ip_tlen == 0 || ip_tlen > data_len) {
                /* Data not long enough */
                continue;
            }
            ret = dv_trans_buf_to_tun(tun_fd, rbuf, ip_tlen);
            if (ret != DV_OK) {
                if (dv_event_add(ev->et_peer_ev) != DV_OK) {
                    return;
                }
                break;
            }
        }

        if (rlen == -DV_EWANT_READ) {
            if (dv_event_add(ev) != DV_OK) {
                return;
            }
            break;
        }

        err_handler(sock, ev, suite);
        continue;
    }
}


