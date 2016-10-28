#ifndef __DV_MEM_H__
#define __DV_MEM_H__

#include "dv_types.h"

#define DV_MEM_BLOCK_SIZE      123

typedef struct _dv_mem_block_t {
    dv_u8      mb_buf[DV_MEM_BLOCK_SIZE];
    dv_u8      mb_used;
} dv_mem_block_t;

extern void *dv_crypto_malloc(size_t num, const char *file, int line);
extern void *dv_crypto_calloc(size_t num, const char *file, int line);
extern void dv_crypto_free(void *ptr, const char *file, int line);

#define dv_malloc(size)     dv_crypto_malloc(size, __FUNCTION__, __LINE__)
#define dv_calloc(size)     dv_crypto_calloc(size, __FUNCTION__, __LINE__)
#define dv_free(ptr)        dv_crypto_free(ptr, __FUNCTION__, __LINE__)

#endif
