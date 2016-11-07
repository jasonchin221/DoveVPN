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
#include "dv_ip_pool.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_mem.h"
#include "dv_server_core.h"

#define DV_IPV4_ADDR_LEN        32

static dv_ip_pool_t dv_ip_pool;

static dv_u32 dv_get_ipv4_num(int mask);
static int dv_gen_ipv4(char *ip, dv_u32 len, char *subnet,
        int subnet_mask, dv_u32 seq);
static dv_u32 dv_get_ipv6_num(int mask);
static int dv_gen_ipv6(char *ip, dv_u32 len, char *subnet,
        int subnet_mask, dv_u32 seq);

static dv_pool_create_t dv_ipv4_pool_create = {
    .pc_get_ip_num = dv_get_ipv4_num,
    .pc_gen_ip = dv_gen_ipv4,
};

static dv_pool_create_t dv_ipv6_pool_create = {
    .pc_get_ip_num = dv_get_ipv6_num,
    .pc_gen_ip = dv_gen_ipv6,
};

static dv_u32
dv_get_ipv4_num(int mask)
{
    if (mask >= DV_IPV4_ADDR_LEN) {
        return 0;
    }

    /* x.x.x.0, x.x.x.1, x.x.x.255 not used */
    return dv_pow(2, DV_IPV4_ADDR_LEN - mask) - 3;
}

static int
dv_gen_ipv4(char *ip, dv_u32 len, char *subnet, int subnet_mask, dv_u32 seq)
{
    struct in_addr  str_ip = {};
    dv_u32          addr = 0;
    dv_u32          mask = 0;
    int             i = 0;

    for (i = 0; i < subnet_mask; i++) {
        mask |= (1 << (DV_IPV4_ADDR_LEN - 1 - i));
    }
 
    addr = ntohl(inet_addr(subnet));
    addr &= mask;
    addr += seq;
    addr = htonl(addr);
    memcpy(&str_ip, &addr, sizeof(addr));
    snprintf(ip, len, "%s", inet_ntoa(str_ip));

    return DV_OK;
}

static dv_u32
dv_get_ipv6_num(int mask)
{
    return 0;
}

static int
dv_gen_ipv6(char *ip, dv_u32 len, char *subnet, int subnet_mask, dv_u32 seq)
{
    return DV_ERROR;
}

dv_u32
dv_get_subnet_mask(void)
{
    return dv_ip_pool.ip_mask;
}

int
dv_get_subnet_mtu(void)
{
    return dv_ip_pool.ip_mtu;
}

static dv_ip_hash_t *
dv_ip_hash_init(dv_u32 size)
{
    dv_ip_hash_t    *table = NULL;
    dv_u32          i = 0;

    table = dv_malloc(sizeof(*table) + size*sizeof(*(&table->ih_table[0])));
    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < size; i++) {
        INIT_LIST_HEAD(&table->ih_table[i]);
    }

    table->ih_size = size;
    table->ih_num = 0;

    return table;
}

static void
dv_ip_hash_exit(dv_ip_hash_t **table)
{
    if (*table == NULL) {
        return;
    }

    dv_free(*table);
    *table = NULL;
}

static int
_dv_ip_pool_init(dv_ip_pool_t *pool, char *subnet_ip, dv_u32 len, int mask, int mtu,
        dv_pool_create_t *create)
{
    dv_subnet_ip_t      *ip_array = NULL; 
    dv_u32              total_size = 0;
    dv_u32              i = 0;
    dv_u32              total_num = 0;
    int                 ret = DV_ERROR;

    total_num = create->pc_get_ip_num(mask);
    if (total_num == 0) {
        DV_LOG(DV_LOG_EMERG, "Total ip number of ip pool error!\n");
        return DV_ERROR;
    }

    total_size = (sizeof(dv_subnet_ip_t)) * total_num;
    ip_array = dv_calloc(total_size);
    if (ip_array == NULL) {
        DV_LOG(DV_LOG_EMERG, "Alloc mem(%d MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }

    INIT_LIST_HEAD(&pool->ip_list_head);
    for (i = 2; i < total_num + 3; i++, ip_array++) {
        /* skip x.x.x.255 */
        if ((i & 0xFF) == 0xFF) {
            continue;
        }
        ret = create->pc_gen_ip(ip_array->si_ip, sizeof(ip_array->si_ip),
                subnet_ip, mask, i);
        if (ret != DV_OK) {
            goto out;
        }
        list_add_tail(&ip_array->si_list_head, &pool->ip_list_head);
        //printf("ip=%s ", ip_array->si_ip);
    }

    pool->ip_mask = mask;
    pool->ip_mtu = mtu;
    DV_LOG(DV_LOG_NOTICE, "Alloc ip pool(%d MB) OK!\n", 
            total_size/1000000);

    pool->ip_hash_table = dv_ip_hash_init(dv_srv_conn_max);
    if (pool->ip_hash_table == NULL) {
        goto out;
    }

    pool->ip_array = ip_array;
    return DV_OK;

out:
    if (ip_array != NULL) {
        dv_free(p_array);
    }

    DV_LOG(DV_LOG_NOTICE, "Init ip pool failed!\n");
    return DV_ERROR;
}

int
dv_ip_pool_init(char *subnet_ip, dv_u32 len, int mask, int mtu)
{

    dv_subnet_ip_t      *ip_array; 
    dv_ip_pool_t        *pool = NULL;
    dv_pool_create_t    *create = NULL;
    dv_u32              total_size = 0;
    dv_u32              i = 0;
    dv_u32              total_num = 0;
    int                 ret = DV_ERROR;

    pool = &dv_ip_pool;
    dv_assert(pool->ip_array == NULL);

    if (dv_ip_version4(subnet_ip)) {
        create = &dv_ipv4_pool_create;
    } else {
        create = &dv_ipv6_pool_create;
    }

    return _dv_ip_pool_init(subnet_ip, len, mask, mtu, create);
}

dv_subnet_ip_t *
dv_subnet_ip_alloc(void)
{
    struct list_head    *head = NULL;
    dv_subnet_ip_t      *ip = NULL;

    head = &dv_ip_pool.ip_list_head;
    if (list_empty(head)) {
        return NULL;
    }

    ip = dv_container_of(head->next, dv_subnet_ip_t, si_list_head);
    list_del(head->next);
    INIT_LIST_HEAD(&ip->si_list_hash);

    return ip;
}

void
dv_subnet_ip_free(dv_subnet_ip_t *ip)
{
    dv_ip_hash_del(ip);
    list_add_tail(&ip->si_list_head, &dv_ip_pool.ip_list_head);
}

static void
_dv_ip_pool_exit(dv_ip_pool_t *pool)
{
    if (pool->ip_array == NULL) {
        return;
    }

    dv_ip_hash_exit(&pool->ip_hash_table);
    dv_free(pool->ip_array);
    INIT_LIST_HEAD(&ip_pool->ip_list_head);
}

void
dv_ip_pool_exit(void)
{
    _dv_ip_pool_exit(&dv_ip_pool);
}

static dv_u32
dv_ip_hash_get(const void *key, dv_u32 length)
{
    return jhash(key, 0) % dv_ip_hash_table->ih_size;
}

void
dv_ip_hash_add(dv_subnet_ip_t *ip)
{
}

void
dv_ip_hash_del(dv_subnet_ip_t *ip)
{
    list_del(&ip->si_list_hash);
}

static dv_subnet_ip_t *
dv_ip_hash_find(dv_ip_pool_t *pool, const void *key, size_t length)
{
    dv_ip_hash_t        *table = NULL;
    struct list_head    *head = NULL;
    struct list_head    *pos = NULL;
    dv_subnet_ip_t      ip = NULL;
    dv_u32              hash = 0;

    table = pool->ip_hash_table;
    if (table == NULL) {
        return NULL;
    }
    hash = dv_ip_hash_get(key, length);
    head = &table->ih_table[hash];

    list_for_each_prev(pos, head) {
        ip = dv_container_of(pos, dv_subnet_ip_t, si_list_hash);
        if (memcmp(key, &ip->si_addr, length) == 0) {
            return ip;
        }
    }

    return NULL;
}

dv_event_t *
dv_ip_wev_find(void *addr, size_t len)
{
    dv_subnet_ip_t      *ip = NULL;

    ip = dv_ip_hash_find(&dv_ip_pool, addr, len);
    if (ip == NULL) {
        return NULL;
    }

    return ip->si_wev;
}


