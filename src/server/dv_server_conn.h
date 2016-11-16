#ifndef __DV_SERVER_CONN_H__
#define __DV_SERVER_CONN_H__

#include <pthread.h>

#include "list.h"

#include "dv_buffer.h"
#include "dv_event.h"
#include "dv_types.h"
#include "dv_ip_pool.h"

typedef struct _dv_srv_conn_t {
    struct list_head    sc_list_head;
    void                *sc_ssl;
    dv_subnet_ip_t      *sc_ip; 
    int                 sc_fd;
    dv_u32              sc_flags;
    dv_event_t          sc_wev;
    dv_event_t          sc_rev;
    dv_buffer_t         sc_rbuf;
    dv_buffer_t         sc_wbuf;
} dv_srv_conn_t;

typedef struct _dv_srv_conn_pool_t {
    struct list_head    cp_list_used;
    struct list_head    cp_list_free;
    pthread_spinlock_t  cp_lock;
    dv_u32              cp_used_num;
} dv_srv_conn_pool_t; 


extern int dv_srv_conn_pool_init(dv_u32 max_conn, size_t bufsize);
extern void dv_srv_conn_pool_destroy(void);
extern dv_srv_conn_t *dv_srv_conn_alloc(void);
extern void dv_srv_conn_free(dv_srv_conn_t *conn);

#endif
