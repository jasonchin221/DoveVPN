#include <string.h>

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
    dv_trans_buf.tb_data_len = 0;

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
dv_trans_data(int tun_fd, void *ssl, void *buf,
        size_t buf_len, dv_proto_suite_t *suite)
{
    dv_assert(dv_trans_buf.tb_buf != NULL);

    return DV_OK;
}
