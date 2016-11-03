#ifndef __DV_IP_POOL_H__
#define __DV_IP_POOL_H__

#include <pthread.h>

#include "list.h"

#include "dv_conf.h"
#include "dv_types.h"

typedef struct _dv_subnet_ip_t {
    struct list_head    si_list_head;
    struct list_head    si_list_hash;
    char                si_ip[DV_IP_ADDRESS_LEN];
    void                *si_wev;
} dv_subnet_ip_t; 

typedef struct _dv_ip_pool_t {
    struct list_head    ip_list_head;
    int                 ip_mask;
    int                 ip_mtu;
} dv_ip_pool_t; 

typedef struct _dv_pool_create_t {
    dv_u32      (*pc_get_ip_num)(int mask);
    int         (*pc_gen_ip)(char *ip, dv_u32 len, char *subnet,
                    int subnet_mask, dv_u32 seq);
} dv_pool_create_t; 


extern dv_u32 dv_get_subnet_mask(void);
extern dv_subnet_ip_t *dv_subnet_ip_alloc(void);
extern void dv_subnet_ip_free(dv_subnet_ip_t *ip);
extern int dv_ip_pool_init(char *subnet_ip, dv_u32 len, int mask, int mtu);
extern void dv_ip_pool_exit(void);
extern void dv_ip_hash_add(dv_subnet_ip_t *ip);
extern void dv_ip_hash_del(dv_subnet_ip_t *ip);

#endif
