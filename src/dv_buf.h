#ifndef __DV_BUF_H__
#define __DV_BUF_H__

#include "dv_types.h"

typedef struct _dv_buf_t {
    dv_u8       *bf_buf;
    dv_u8       *bf_head;
    dv_u8       *bf_tail;
    size_t      bf_bsize;
} dv_buf_t;

extern dv_buf_t *dv_buf_alloc(size_t size);
extern void dv_buf_free(dv_buf_t *buf);

#endif
