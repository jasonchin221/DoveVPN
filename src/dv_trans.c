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
dv_trans_data_client(int tun_fd, void *ssl, void *buf,
        size_t buf_len, const dv_proto_suite_t *suite)
{
    dv_trans_buf_t      *tbuf = &dv_trans_buf;
    ssize_t             rlen = 0;
    int                 wlen = 0;
    int                 data_len = 0;

    dv_assert(tbuf->tb_buf != NULL);

    rlen = read(tun_fd, tbuf->tb_buf, tbuf->tb_buf_size);
    if (rlen <= 0) {
        return 0;
    }
    
    if (rlen > buf_len) {
        return 0;
    }

    wlen = suite->ps_write(ssl, tbuf->tb_buf, rlen);
    if (wlen == rlen) {
        return 0;
    }

    if (wlen < 0) {
        if (wlen == -DV_EWANT_WRITE) {
            wlen = 0;
        } else {
            fprintf(stderr, "Send data failed! mlen = %d\n", (int)rlen);
            return 0;
        } 
    }

    data_len = rlen - wlen;
    memcpy(buf, (dv_u8 *)tbuf->tb_buf + wlen, data_len);

    return data_len;
}

