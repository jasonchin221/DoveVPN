
#include "dv_buffer.h"
#include "dv_mem.h"
#include "dv_errno.h"
#include "dv_log.h"

void
dv_buf_reset(dv_buffer_t *buf)
{
    buf->bf_head = buf->bf_tail = buf->bf_buf;
}

void
dv_buf_init(dv_buffer_t *buf, void *head, size_t size)
{
    buf->bf_buf = buf->bf_head = buf->bf_tail = head;
    buf->bf_bsize = size;
}

dv_buffer_t *
dv_buf_alloc(size_t size)
{
    dv_buffer_t        *buf = NULL;

    buf = dv_malloc(sizeof(*buf) + size);
    if (buf == NULL) {
        return NULL;
    }
    
    dv_buf_init(buf, buf + 1, size);

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

dv_u8
dv_buf_empty(dv_buffer_t *buf) 
{
    return (buf->bf_head == buf->bf_tail &&
            !(buf->bf_flag & DV_BUF_FLAG_FULL));
}

int
dv_buf_data_to_ssl(void *ssl, dv_buffer_t *buf, const dv_proto_suite_t *suite)
{
    int                 wlen = 0;
    int                 data_len = 0;

    /* No data to send */
    if (dv_buf_empty(buf)) {
        return DV_OK;
    }

    if (buf->bf_head >= buf->bf_tail) {
        data_len = buf->bf_bsize - (buf->bf_buf - buf->bf_head);
        wlen = suite->ps_write(ssl, buf->bf_head, data_len);
        if (wlen < 0) {
            DV_LOG(DV_LOG_ERROR, "Write ssl error, data_len = %d\n", data_len);
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
    printf("data_len = %d\n", data_len);
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

