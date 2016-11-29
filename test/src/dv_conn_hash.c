#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "jhash.h"

#include "dv_types.h"
#include "dv_log.h"
#include "dv_assert.h"
#include "dv_server_conn.h"
#include "dv_conn_hash.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_mem.h"
#include "dv_server_core.h"

#define DV_IPV4_ADDR_LEN        32

static dv_conn_hash_t *dv_conn_hash_table;

static dv_conn_hash_t *
_dv_conn_hash_init(dv_u32 size, size_t key_len)
{
    dv_conn_hash_t      *table = NULL;
    dv_u32              i = 0;

    table = dv_malloc(sizeof(*table) + size*sizeof(*(&table->ch_table[0])));
    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < size; i++) {
        INIT_LIST_HEAD(&table->ch_table[i]);
    }

    table->ch_size = size;
    table->ch_key_len = key_len;
    table->ch_num = 0;

    return table;
}

int
dv_conn_hash_init(size_t total_num, size_t key_len)
{
    dv_conn_hash_table = _dv_conn_hash_init(total_num, key_len);
    if (dv_conn_hash_table == NULL) {
        DV_LOG(DV_LOG_NOTICE, "Init ip hash failed!\n");
        return DV_ERROR;
    }

    return DV_OK;
}

void
dv_conn_hash_exit(void)
{
    if (dv_conn_hash_table == NULL) {
        return;
    }

    dv_free(dv_conn_hash_table);
    dv_conn_hash_table = NULL;
}

static dv_u32
dv_conn_hash_get(const void *key, dv_u32 length)
{
    return jhash(key, length, 0) % dv_conn_hash_table->ch_size;
}

void
dv_conn_hash_add(dv_srv_conn_t *conn)
{
    dv_conn_hash_t      *table = NULL;
    struct list_head    *head = NULL;
    dv_u32              hash = 0;

    table = dv_conn_hash_table;
    dv_assert(table != NULL);

    hash = dv_conn_hash_get(&conn->sc_addr, conn->sc_addr_len);
    head = &table->ch_table[hash];
    list_add(&conn->sc_list_hash, head);
    table->ch_num++;
}

void
dv_conn_hash_del(dv_srv_conn_t *conn)
{
    dv_assert(dv_conn_hash_table != NULL);

    list_del(&conn->sc_list_hash);
    dv_conn_hash_table->ch_num--;
}

dv_srv_conn_t *
dv_conn_hash_find(const struct sockaddr *addr, size_t len)
{
    dv_conn_hash_t      *table = NULL;
    struct list_head    *head = NULL;
    struct list_head    *pos = NULL;
    dv_srv_conn_t       *conn = NULL;
    dv_u32              hash = 0;

    table = dv_conn_hash_table;
    if (table == NULL) {
        DV_LOG(DV_LOG_INFO, "Table is NULL!\n");
        return NULL;
    }

    if (len != table->ch_key_len) {
        DV_LOG(DV_LOG_INFO, "Key len(%zu) not match(%zu)\n",
                len, table->ch_key_len);
        return NULL;
    }

    hash = dv_conn_hash_get(addr, len);
    head = &table->ch_table[hash];

    list_for_each_prev(pos, head) {
        conn = dv_container_of(pos, dv_srv_conn_t, sc_list_hash);
        if (memcmp(addr, &conn->sc_addr, len) == 0) {
            return conn;
        }
    }

    return NULL;
}

