#ifndef __DV_BUF_H__
#define __DV_BUF_H__

#include "dv_types.h"

#define DV_BUF_FLAG_FULL    0x01

typedef struct _dv_buf_t {
    dv_u8       *bf_buf;
    dv_u8       *bf_head;
    dv_u8       *bf_tail;
    dv_u32      bf_flag;
    size_t      bf_bsize;
} dv_buf_t;

extern dv_buf_t *dv_buf_alloc(size_t size);
extern void dv_buf_free(dv_buf_t *buf);

#endif
