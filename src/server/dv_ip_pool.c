#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "dv_types.h"
#include "dv_mem.h"
#include "dv_sys.h"
#include "dv_log.h"
#include "dv_debug.h"

#define DV_KEY_HASH_SHM_KEY    (IPC_PRIVATE)

static dv_hash_table_t *dv_hash_table;
static dv_cache_pool_t *dv_key_cache_pool;
static dv_key_cache_t *dv_key_cache_pool_head;
static dv_u32 dv_hash_table_size;
static int dv_key_hash_shmid;

int
dv_hash_init(int max_conn)
{
    dv_cache_pool_t    *pool = NULL;
    dv_u32             total_size = 0;
    dv_u32             i = 0;
    int                ret = DV_ERROR;

    DV_ASSERT(dv_hash_table == NULL);

    dv_hash_table_size = max_conn;
    total_size = (sizeof(dv_subnet_ip_t)) *
        dv_hash_table_size + sizeof(dv_ip_pool_t)*2;

    if ((dv_key_hash_shmid = shmget(DV_KEY_HASH_SHM_KEY, total_size,
                    IPC_CREAT | 0600)) < 0) {
        DV_LOG(DV_LOG_EMERG, "Alloc shm(%d MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }

    if ((dv_hash_table = shmat(dv_key_hash_shmid, NULL, 0)) == (void *)-1) {
        goto out;
    }

    pool = (void *)(dv_hash_table + dv_hash_table_size); 
    dv_key_cache_pool = pool;
    dv_key_cache_pool_head = (void *)(dv_key_cache_pool + 1); 

    if (pthread_spin_init(&pool->cp_lock, PTHREAD_PROCESS_SHARED) != 0) {
        goto out;
    }

    pool->cp_qlen = 0;
    pool->cp_cache_used = 0;
    INIT_LIST_HEAD(&pool->cp_list_head);

    DV_LOG(DV_LOG_NOTICE, "Alloc key cache(%d MB) OK!\n", 
            total_size/1000000);
    return DV_OK;

out:
    ret = shmctl(dv_key_hash_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }

    DV_LOG(DV_LOG_NOTICE, "Init SHM failed!\n");
    return DV_ERROR;
}

void
dv_hash_add(dv_key_cache_t *k)
{
    dv_hash_table_t    *ht = NULL;
    dv_u32             hid = 0;

    hid = dv_hash_value(k->kc_uid, k->kc_key.ks_kid);
    ht = &dv_hash_table[hid];
    pthread_spin_lock(&ht->nt_lock);
    list_add_tail(&k->kc_list_head, &ht->nt_list_head);
    pthread_spin_unlock(&ht->nt_lock);
}

dv_key_cache_t *
dv_hash_key_alloc(void)
{
    dv_key_cache_t     *key = NULL;

    DV_ASSERT(dv_key_cache_pool != NULL);

    pthread_spin_lock(&dv_key_cache_pool->cp_lock);
    if (dv_key_cache_pool->cp_cache_used < dv_hash_table_size) {
        key = &dv_key_cache_pool_head[dv_key_cache_pool->cp_cache_used];
        dv_key_cache_pool->cp_cache_used++;
    }
    pthread_spin_unlock(&dv_key_cache_pool->cp_lock);

    return key;
}

dv_key_cache_t *
dv_hash_key_get(void)
{
    dv_key_cache_t     *key = NULL;
    struct list_head    *head = NULL;

    DV_ASSERT(dv_key_cache_pool != NULL);

    head = &dv_key_cache_pool->cp_list_head;
    pthread_spin_lock(&dv_key_cache_pool->cp_lock);
    if (!list_empty(head)) {
        key = dv_container_of(head->next, dv_key_cache_t, kc_list_head);
        dv_key_cache_pool->cp_qlen--;
        list_del(head->next);
    } else if (dv_key_cache_pool->cp_cache_used < dv_hash_table_size) {
        key = &dv_key_cache_pool_head[dv_key_cache_pool->cp_cache_used];
        key->kc_key.ks_kid = dv_key_cache_pool->cp_cache_used;
        key->kc_key.ks_flag = 0;
        dv_key_cache_pool->cp_cache_used++;
    }
    pthread_spin_unlock(&dv_key_cache_pool->cp_lock);

    return key;
}

void
dv_hash_key_put(dv_key_cache_t *k)
{
    struct list_head    *head = NULL;

    DV_ASSERT(dv_key_cache_pool != NULL);

    head = &dv_key_cache_pool->cp_list_head;
    pthread_spin_lock(&dv_key_cache_pool->cp_lock);
    list_add_tail(&k->kc_list_head, head);
    dv_key_cache_pool->cp_qlen++;
    pthread_spin_unlock(&dv_key_cache_pool->cp_lock);
}

void
dv_hash_key_free(dv_key_cache_t *k)
{
}

dv_key_cache_t *
dv_hash_key_find(char *uid, dv_u32 kid)
{
    dv_hash_table_t    *ht = NULL;
    dv_key_cache_t     *k = NULL;
    struct list_head    *n = NULL;
    struct list_head    *pos = NULL;
    dv_u32             hid = 0;

    hid = dv_hash_value(uid, kid);
    ht = &dv_hash_table[hid];
    pthread_spin_lock(&ht->nt_lock);
    list_for_each_safe(pos, n, &ht->nt_list_head)  {
        k = dv_container_of(pos, dv_key_cache_t, kc_list_head);
        if (kid == k->kc_key.ks_kid &&
                strncmp(uid, k->kc_uid, sizeof(k->kc_uid)) == 0) {
            pthread_spin_unlock(&ht->nt_lock);
            return k;
        }
    }
    pthread_spin_unlock(&ht->nt_lock);

    return NULL;
}

void
dv_hash_exit(void)
{
    dv_hash_table_t    *ht = NULL;
    dv_u32             i = 0;
    int                 ret = 0;

    if (dv_hash_table == NULL) {
        return;
    }

    for (i = 0; i < dv_hash_table_size; i++) {
        ht = &dv_hash_table[i];
        pthread_spin_destroy(&ht->nt_lock);
    }

    pthread_spin_destroy(&dv_key_cache_pool->cp_lock);
    DV_LOG(DV_LOG_NOTICE, "Cache queue len = %u, used %u\n",
            dv_key_cache_pool->cp_qlen, 
            dv_key_cache_pool->cp_cache_used);
    
    shmdt(dv_hash_table);
    ret = shmctl(dv_key_hash_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }
}
