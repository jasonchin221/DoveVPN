#ifndef __DV_IP_POOL_H__
#define __DV_IP_POOL_H__

#include <pthread.h>

#include "list.h"

#include "dv_key.h"

typedef struct _dv_hash_table_t {
    struct list_head    nt_list_head;
    pthread_spinlock_t  nt_lock;
} dv_hash_table_t; 

typedef struct _dv_cache_pool_t {
    struct list_head    cp_list_head;
    pthread_spinlock_t  cp_lock;
    dv_u32             cp_qlen;
    dv_u32             cp_cache_used;
} dv_cache_pool_t; 


extern void dv_hash_add(dv_key_cache_t *k);
extern dv_key_cache_t *dv_hash_key_find(char *uid, dv_u32 kid);
extern dv_key_cache_t *dv_hash_key_alloc(void);
extern void dv_hash_key_free(dv_key_cache_t *k);
extern dv_key_cache_t *dv_hash_key_get(void);
extern void dv_hash_key_put(dv_key_cache_t *k);
extern int dv_hash_init(int max_conn);
extern void dv_hash_exit(void);

#endif
