#ifndef __DV_CONN_HASH_H__
#define __DV_CONN_HASH_H__

#include "list.h"

typedef struct _dv_conn_hash_t {
    dv_u32              ch_size;
    dv_u32              ch_num;
    size_t              ch_key_len;
    struct list_head    ch_table[0];
} dv_conn_hash_t;

extern int dv_conn_hash_init(size_t total_num, size_t key_len);
extern void dv_conn_hash_exit(void);
extern void dv_conn_hash_add(dv_srv_conn_t *conn);
extern void dv_conn_hash_del(dv_srv_conn_t *conn);
extern dv_srv_conn_t *dv_conn_hash_find(const struct sockaddr *addr,
        size_t len);

#endif
