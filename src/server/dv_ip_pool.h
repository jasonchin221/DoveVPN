#ifndef __DV_IP_POOL_H__
#define __DV_IP_POOL_H__

#include <pthread.h>

#include "list.h"

#include "dv_conf.h"
#include "dv_types.h"

typedef struct _dv_subnet_ip_t {
    struct list_head    si_list_head;
    char                si_ip[DV_IP_ADDRESS_LEN];
} dv_subnet_ip_t; 

typedef struct _dv_ip_pool_t {
    struct list_head    ip_list_head;
    pthread_spinlock_t  ip_lock;
} dv_ip_pool_t; 

typedef struct _dv_pool_create_t {
    dv_u32      (*pc_get_ip_num)(int mask);
    int         (*pc_gen_ip)(char *ip, dv_u32 len, char *subnet,
                    int subnet_mask, dv_u32 seq);
} dv_pool_create_t; 


extern dv_subnet_ip_t *dv_subnet_ip_alloc(void);
extern void dv_subnet_ip_free(dv_subnet_ip_t *ip);
extern int dv_ip_pool_init(char *subnet_ip, dv_u32 len, int mask);
extern void dv_ip_pool_exit(void);

#endif
