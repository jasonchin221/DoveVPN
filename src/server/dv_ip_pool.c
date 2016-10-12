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

static dv_u32 dv_get_ipv4_num(int mask);
static int dv_gen_ipv4(char *ip, dv_u32 len, char *subnet, dv_u32 seq);
static dv_u32 dv_get_ipv6_num(int mask);
static int dv_gen_ipv6(char *ip, dv_u32 len, char *subnet, dv_u32 seq);

static dv_pool_create_t dv_ipv4_pool = {
    .pc_get_ip_num = dv_get_ipv4_num,
    .pc_gen_ip = dv_gen_ipv4,
};

static dv_pool_create_t dv_ipv6_pool = {
    .pc_get_ip_num = dv_get_ipv6_num,
    .pc_gen_ip = dv_gen_ipv6,
};

static dv_u32
dv_get_ipv4_num(int mask)
{
    dv_u32          num = 0;

    return num;
}

static int
dv_gen_ipv4(char *ip, dv_u32 len, char *subnet, dv_u32 seq)
{
    return DV_OK;
}

static dv_u32
dv_get_ipv6_num(int mask)
{
    return 0;
}

static int
dv_gen_ipv6(char *ip, dv_u32 len, char *subnet, dv_u32 seq)
{
    return DV_ERROR;
}

int
dv_ip_pool_init(char *subnet_ip, dv_u32 len, int mask)
{
    dv_subnet_ip_t      *ip_array; 
    dv_pool_create_t    *create = NULL;
    dv_u32              total_size = 0;
    dv_u32              i = 0;
    dv_u32              total_num = 0;
    int                 ret = DV_ERROR;

    dv_assert(dv_ip_pool == NULL);

    if (dv_ip_version4(subnet_ip)) {
        create = &dv_ipv4_pool;
    } else {
        create = &dv_ipv6_pool;
    }

    total_num = create->pc_get_ip_num(mask);
    if (total_num == 0) {
        DV_LOG(DV_LOG_EMERG, "Total ip number of ip pool error!\n");
        return DV_ERROR;
    }

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
        ret = create->pc_gen_ip(ip_array->si_ip, sizeof(ip_array->si_ip),
                subnet_ip, i);
        if (ret != DV_OK) {
            goto out;
        }
        list_add_tail(&ip_array->si_list_head, &dv_ip_pool->ip_list_head);
    }

    DV_LOG(DV_LOG_NOTICE, "Alloc ip pool(%d MB) OK!\n", 
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
