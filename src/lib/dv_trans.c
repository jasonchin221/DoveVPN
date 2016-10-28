#include <string.h>
#include <unistd.h>


#include "dv_types.h"
#include "dv_mem.h"
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_trans.h"
#include "dv_assert.h"

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

int
dv_trans_data_client(int tun_fd, void *ssl, dv_buf_t *buf,
        const dv_proto_suite_t *suite)
{
    dv_trans_buf_t      *tbuf = &dv_trans_buf;
    ssize_t             rlen = 0;
    int                 space = 0;
    int                 tail_len = 0;
    int                 wlen = 0;
    int                 data_len = 0;

    dv_assert(tbuf->tb_buf != NULL);

    if (buf->bf_flag & DV_BUF_FLAG_FULL) {
        dv_assert(buf->bf_head == buf->bf_tail);
        tail_len = space = 0;
        data_len = buf->bf_bsize;
    } else if (buf->bf_tail >= buf->bf_head) {
        data_len = buf->bf_tail - buf->bf_head;
        space = buf->bf_bsize - data_len;
        tail_len = buf->bf_buf + buf->bf_bsize - buf->bf_tail;
    } else {
        tail_len = space = buf->bf_head - buf->bf_tail;
        data_len = buf->bf_bsize - space;
    }

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

