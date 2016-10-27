
#include "dv_buf.h"
#include "dv_mem.h"

dv_buf_t *
dv_buf_alloc(size_t size)
{
    dv_buf_t        *buf = NULL;

    buf = dv_malloc(sizeof(*buf) + size);
    if (buf == NULL) {
        return NULL;
    }
    
    buf->bf_buf = buf->bf_head = buf->bf_tail = (dv_u8 *)(buf + 1);
    buf->bf_bsize = size;

    return buf;
}

void
dv_buf_free(dv_buf_t *buf)
{
    if (buf == NULL) {
        return;
    }

    dv_free(buf);
}
