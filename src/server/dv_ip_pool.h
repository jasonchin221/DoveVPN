#ifndef __DV_IP_POOL_H__
#define __DV_IP_POOL_H__

#include <pthread.h>

#include "list.h"

#include "dv_conf.h"

typedef struct _dv_subnet_ip_t {
    struct list_head    ht_list_head;
    char                ht_ip[DV_IP_ADDRESS_LEN];
} dv_subnet_ip_t; 

typedef struct _dv_ip_pool_t {
    struct list_head    ip_list_head;
    pthread_spinlock_t  ip_lock;
    dv_u32              ip_qlen;
    dv_u32              ip_used;
} dv_ip_pool_t; 


extern dv_subnet_ip_t *dv_subnet_ip_alloc(void);
extern void dv_subnet_ip_free(dv_subnet_ip_t *ip);
extern int dv_hash_init(int max_conn);
extern void dv_hash_exit(void);

#endif
