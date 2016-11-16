#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_log.h"
#include "dv_server_conn.h"

#define DV_SRV_CONN_POOL_SHM_KEY    (IPC_PRIVATE)

static dv_srv_conn_pool_t *dv_srv_conn_pool;
static int dv_srv_conn_pool_shmid;

int
dv_srv_conn_pool_init(dv_u32 max_conn, size_t bufsize)
{
    size_t      size = 0;
    size_t      total_size = 0;

    size = (sizeof(dv_srv_conn_t) + bufsize)*2;
    total_size = size*max_conn + sizeof(*dv_srv_conn_pool);

    if ((dv_srv_conn_pool_shmid = shmget(DV_SRV_CONN_POOL_SHM_KEY, total_size,
                    IPC_CREAT | 0600)) < 0) {
        DV_LOG(DV_LOG_EMERG, "Alloc shm(%zu MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }


    return DV_OK;
}

void
dv_srv_conn_pool_destroy(void)
{
}

dv_srv_conn_t *
dv_srv_conn_alloc(void)
{
    dv_srv_conn_t   *conn = NULL;

    return conn;
}

void
dv_srv_conn_free(dv_srv_conn_t *conn)
{
}

