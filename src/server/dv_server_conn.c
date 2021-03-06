#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "dv_types.h"
#include "dv_errno.h"
#include "dv_log.h"
#include "dv_assert.h"
#include "dv_lib.h"
#include "dv_mem.h"
#include "dv_ip_pool.h"
#include "dv_server_conn.h"
#include "dv_server_core.h"
#include "dv_server_cycle.h"

#define DV_SRV_CONN_POOL_SHM_KEY    (IPC_PRIVATE)

static dv_srv_conn_pool_t *dv_srv_conn_pool;
static int dv_srv_conn_pool_shmid;

int
dv_srv_conn_pool_init(dv_u32 max_conn, size_t bufsize)
{
    dv_srv_conn_t       *conn = NULL;
    size_t              size = 0;
    size_t              total_size = 0;
    dv_u32              i = 0;
    int                 ret = 0;

    size = sizeof(dv_srv_conn_t) + 2*bufsize;
    total_size = size*max_conn + sizeof(*dv_srv_conn_pool);

    if ((dv_srv_conn_pool_shmid = shmget(DV_SRV_CONN_POOL_SHM_KEY, total_size,
                    IPC_CREAT | 0600)) < 0) {
        DV_LOG(DV_LOG_EMERG, "Alloc shm(%zu MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }

    if ((dv_srv_conn_pool = shmat(dv_srv_conn_pool_shmid, NULL, 0))
            == (void *)-1) {
        DV_LOG(DV_LOG_NOTICE, "Shmat failed!\n");
        goto out;
    }

    if (pthread_spin_init(&dv_srv_conn_pool->cp_lock,
                PTHREAD_PROCESS_SHARED) != 0) {
        DV_LOG(DV_LOG_NOTICE, "Spinlock init failed!\n");
        goto out;
    }

    INIT_LIST_HEAD(&dv_srv_conn_pool->cp_list_used);
    INIT_LIST_HEAD(&dv_srv_conn_pool->cp_list_free);
    dv_srv_conn_pool->cp_used_num = 0;
    dv_srv_conn_pool->cp_child_count = 0;

    conn = (void *)(dv_srv_conn_pool + 1);
    for (i = 0; i < max_conn; i++, conn = (void *)((dv_u8 *)conn + size)) {
        dv_buf_init(&conn->sc_rbuf, conn + 1, bufsize);
        dv_buf_init(&conn->sc_wbuf, (dv_u8 *)(conn + 1) + bufsize, bufsize);
        list_add_tail(&conn->sc_list_head, &dv_srv_conn_pool->cp_list_free);
    }

    DV_LOG(DV_LOG_NOTICE, "Alloc %u connection (%zu MB) OK!\n", max_conn, 
            total_size/1000000);

    return DV_OK;

out:
    ret = shmctl(dv_srv_conn_pool_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }

    DV_LOG(DV_LOG_NOTICE, "Init SHM failed!\n");
    return DV_ERROR;
}

static void
dv_srv_conn_pool_release(void *conn)
{
    dv_srv_conn_pool_free(conn);
}

static void
dv_srv_conn_init(dv_srv_conn_t *conn, int fd, void *ssl)
{
    dv_event_t          *rev = NULL;
    dv_event_t          *wev = NULL;

    conn->sc_fd = fd;
    conn->sc_flags = 0;
    conn->sc_ip = NULL;
    conn->sc_ssl = ssl;
    conn->sc_pid = getpid();

    rev = &conn->sc_rev;
    wev = &conn->sc_wev;
    memset(rev, 0, sizeof(*rev));
    memset(wev, 0, sizeof(*wev));
    rev->et_conn = wev->et_conn = conn;
    rev->et_conn_free = wev->et_conn_free = dv_srv_conn_pool_release;

    dv_buf_reset(&conn->sc_rbuf);
    dv_buf_reset(&conn->sc_wbuf);
}

dv_srv_conn_t *
dv_srv_conn_pool_alloc(int fd, void *ssl)
{
    dv_srv_conn_t       *conn = NULL;
    struct list_head    *list = NULL;
    struct list_head    *head = NULL;

    dv_assert(dv_srv_conn_pool != NULL);

    head = &dv_srv_conn_pool->cp_list_free;
    pthread_spin_lock(&dv_srv_conn_pool->cp_lock);
    list = head->next; 
    if (list == head) {
        pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);
        return NULL;
    }
    list_del_init(list);
    list_add_tail(list, &dv_srv_conn_pool->cp_list_used);
    dv_srv_conn_pool->cp_used_num++;
    pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);

    conn = dv_container_of(list, dv_srv_conn_t, sc_list_head);
    dv_srv_conn_init(conn, fd, ssl);

    return conn;
}

static void
dv_srv_conn_destroy(dv_srv_conn_t *conn)
{
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;

    dv_assert(suite != NULL);

    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    dv_event_destroy(&conn->sc_rev);
    dv_event_destroy(&conn->sc_wev);
    if (conn->sc_ip) {
        dv_subnet_ip_free(conn->sc_ip);
        conn->sc_ip = NULL;
    }
    if (conn->sc_ssl) {
        suite->ps_shutdown(conn->sc_ssl);
        suite->ps_ssl_free(conn->sc_ssl);
        conn->sc_ssl = NULL;
    }
    if (conn->sc_fd >= 0) {
        close(conn->sc_fd);
        conn->sc_fd = -1;
    }
    DV_LOG(DV_LOG_INFO, "SSL out!\n");
}

void
dv_srv_conn_pool_free(dv_srv_conn_t *conn)
{
    dv_assert(dv_srv_conn_pool != NULL);

    dv_srv_conn_destroy(conn);

    if (!list_empty(&conn->sc_list_head)) {
        pthread_spin_lock(&dv_srv_conn_pool->cp_lock);
        list_del_init(&conn->sc_list_head);
        list_add_tail(&conn->sc_list_head, &dv_srv_conn_pool->cp_list_free);
        dv_srv_conn_pool->cp_used_num--;
        pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);
    }
}

static void
_dv_srv_conn_pool_free(dv_srv_conn_t *conn)
{
    dv_assert(dv_srv_conn_pool != NULL);

    list_del_init(&conn->sc_list_head);
    dv_srv_conn_destroy(conn);
    list_add_tail(&conn->sc_list_head, &dv_srv_conn_pool->cp_list_free);

    dv_srv_conn_pool->cp_used_num--;
}

void
dv_srv_conn_pool_destroy(void)
{
    dv_srv_conn_t       *conn = NULL;
    struct list_head    *pos = NULL;
    struct list_head    *n = NULL;
    pid_t               pid = getpid();
    int                 destroy = 0;
    int                 count = 0;
    int                 ret = 0;

    if (dv_srv_conn_pool == NULL) {
        return;
    }

    pthread_spin_lock(&dv_srv_conn_pool->cp_lock);
    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    list_for_each_safe(pos, n, &dv_srv_conn_pool->cp_list_used) {
        conn = dv_container_of(pos, dv_srv_conn_t, sc_list_head);
        if (pid == conn->sc_pid) {
            _dv_srv_conn_pool_free(conn);
        }
    }
    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    if (dv_process == DV_PROCESS_WORKER) {
        dv_srv_conn_pool->cp_child_count++;
    }
    pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);

    if (dv_process == DV_PROCESS_MASTER) {
        while (count < 5) {
            pthread_spin_lock(&dv_srv_conn_pool->cp_lock);
            destroy = (dv_srv_conn_pool->cp_child_count == dv_ncpu);
            pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);
            if (destroy) {
                break;
            }
            DV_LOG(DV_LOG_INFO, "Waiting for child quit! child_count = %u\n",
                    dv_srv_conn_pool->cp_child_count);
            sleep(1);
            count++;
        }
        pthread_spin_destroy(&dv_srv_conn_pool->cp_lock);
    }
    shmdt(dv_srv_conn_pool);
    ret = shmctl(dv_srv_conn_pool_shmid, IPC_RMID, NULL);
    if (ret != 0) {
        DV_LOG(DV_LOG_NOTICE, "Remove SHM failed!\n");
    }
}

dv_u32
dv_srv_conn_num_get(void)
{
    dv_u32  num = 0;

    dv_assert(dv_srv_conn_pool != NULL);

    pthread_spin_lock(&dv_srv_conn_pool->cp_lock);
    num = dv_srv_conn_pool->cp_used_num;
    pthread_spin_unlock(&dv_srv_conn_pool->cp_lock);

    return num;
}

