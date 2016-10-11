#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "dv_types.h"
#include "dv_log.h"
#include "dv_assert.h"
#include "dv_ip_pool.h"
#include "dv_errno.h"
#include "dv_lib.h"

#define DV_KEY_HASH_SHM_KEY    (IPC_PRIVATE)

static dv_ip_pool_t *dv_ip_pool;
static int dv_ip_pool_shmid;

int
dv_ip_pool_init(int total_num)
{
    dv_subnet_ip_t      *ip_array; 
    dv_u32              total_size = 0;
    dv_u32              i = 0;
    int                 ret = DV_ERROR;

    dv_assert(dv_ip_pool == NULL);

    total_size = (sizeof(dv_subnet_ip_t)) * total_num + sizeof(*dv_ip_pool);
    if ((dv_ip_pool_shmid = shmget(DV_KEY_HASH_SHM_KEY, total_size,
                    IPC_CREAT | 0600)) < 0) {
        DV_LOG(DV_LOG_EMERG, "Alloc shm(%d MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }

    if ((dv_ip_pool = shmat(dv_ip_pool_shmid, NULL, 0)) == (void *)-1) {
        goto out;
    }

    if (pthread_spin_init(&dv_ip_pool->ip_lock, PTHREAD_PROCESS_SHARED) != 0) {
        goto out;
    }

    INIT_LIST_HEAD(&dv_ip_pool->ip_list_head);
    ip_array = (void *)(dv_ip_pool + 1);
    for (i = 0; i < total_num; i++, ip_array++) {
        list_add_tail(&ip_array->si_list_head, &dv_ip_pool->ip_list_head);
    }

    DV_LOG(DV_LOG_NOTICE, "Alloc key cache(%d MB) OK!\n", 
            total_size/1000000);
    return DV_OK;

out:
    ret = shmctl(dv_ip_pool_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }

    DV_LOG(DV_LOG_NOTICE, "Init SHM failed!\n");
    return DV_ERROR;
}

dv_subnet_ip_t *
dv_subnet_ip_alloc(void)
{
    struct list_head    *head = NULL;
    dv_subnet_ip_t      *ip = NULL;

    dv_assert(dv_ip_pool != NULL);

    head = &dv_ip_pool->ip_list_head;
    pthread_spin_lock(&dv_ip_pool->ip_lock);
    if (!list_empty(head)) {
        ip = dv_container_of(head->next, dv_subnet_ip_t, si_list_head);
        list_del(head->next);
    } else {
        ip = NULL;
    }
    pthread_spin_unlock(&dv_ip_pool->ip_lock);

    return ip;
}

void
dv_subnet_ip_free(dv_subnet_ip_t *ip)
{
    dv_assert(dv_ip_pool != NULL);

    pthread_spin_lock(&dv_ip_pool->ip_lock);
    list_add_tail(&ip->si_list_head, &dv_ip_pool->ip_list_head);
    pthread_spin_unlock(&dv_ip_pool->ip_lock);
}

void
dv_ip_pool_exit(void)
{
    int                 ret = 0;

    if (dv_ip_pool == NULL) {
        return;
    }

    pthread_spin_destroy(&dv_ip_pool->ip_lock);
    
    shmdt(dv_ip_pool);
    ret = shmctl(dv_ip_pool_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }
}
