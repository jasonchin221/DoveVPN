
#include "dv_buffer.h"
#include "dv_mem.h"
#include "dv_errno.h"

dv_buffer_t *
dv_buf_alloc(size_t size)
{
    dv_buffer_t        *buf = NULL;

    buf = dv_malloc(sizeof(*buf) + size);
    if (buf == NULL) {
        return NULL;
    }
    
    buf->bf_buf = buf->bf_head = buf->bf_tail = (dv_u8 *)(buf + 1);
    buf->bf_bsize = size;

    return buf;
}

void
dv_buf_free(dv_buffer_t *buf)
{
    if (buf == NULL) {
        return;
    }

    dv_free(buf);
}

int
dv_buf_data_to_ssl(void *ssl, dv_buffer_t *buf, const dv_proto_suite_t *suite)
{
    int                 wlen = 0;
    int                 data_len = 0;

    /* No data to send */
    if (buf->bf_head == buf->bf_tail && !(buf->bf_flag & DV_BUF_FLAG_FULL)) {
        return DV_OK;
    }

    if (buf->bf_head >= buf->bf_tail) {
        data_len = buf->bf_bsize - (buf->bf_buf - buf->bf_head);
        wlen = suite->ps_write(ssl, buf->bf_head, data_len);
        if (wlen < 0) {
            return wlen;
        }

        if (wlen == 0) {
            return DV_ERROR;
        }

        buf->bf_flag &= ~DV_BUF_FLAG_FULL;
        if (wlen < data_len) {
            buf->bf_head += wlen;
            return -DV_EWANT_WRITE;
        }

        buf->bf_head = buf->bf_buf;
    }

    /* No data to send */
    if (buf->bf_head == buf->bf_tail) {
        return DV_OK;
    }

    data_len = buf->bf_tail - buf->bf_head;
    wlen = suite->ps_write(ssl, buf->bf_head, data_len);
    if (wlen < 0) {
        return wlen;
    }

    if (wlen == 0) {
        return DV_ERROR;
    }

    buf->bf_flag &= ~DV_BUF_FLAG_FULL;
    if (wlen < data_len) {
        buf->bf_head += wlen;
        return -DV_EWANT_WRITE;
    }

    buf->bf_head = buf->bf_tail = buf->bf_buf;

    return DV_OK;
}

