#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dv_types.h"
#include "dv_log.h"
#include "dv_assert.h"
#include "dv_ip_pool.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_mem.h"

#define DV_IPV4_ADDR_LEN        32

static dv_subnet_ip_t *dv_subnet_ip_array; 
static dv_ip_pool_t dv_ip_pool;

static dv_u32 dv_get_ipv4_num(int mask);
static int dv_gen_ipv4(char *ip, dv_u32 len, char *subnet,
        int subnet_mask, dv_u32 seq);
static dv_u32 dv_get_ipv6_num(int mask);
static int dv_gen_ipv6(char *ip, dv_u32 len, char *subnet,
        int subnet_mask, dv_u32 seq);

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

int
dv_ip_pool_init(char *subnet_ip, dv_u32 len, int mask)
{
    dv_subnet_ip_t      *ip_array; 
    dv_pool_create_t    *create = NULL;
    dv_ip_pool_t        *pool = &dv_ip_pool;
    dv_u32              total_size = 0;
    dv_u32              i = 0;
    dv_u32              total_num = 0;
    int                 ret = DV_ERROR;

    dv_assert(dv_subnet_ip_array == NULL);

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

    total_size = (sizeof(dv_subnet_ip_t)) * total_num;
    ip_array = dv_calloc(total_size);
    if (ip_array == NULL) {
        DV_LOG(DV_LOG_EMERG, "Alloc mem(%d MB) failed!\n", 
                total_size/1000000);
        return DV_ERROR;
    }

    dv_subnet_ip_array = ip_array;
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

    DV_LOG(DV_LOG_NOTICE, "Alloc ip pool(%d MB) OK!\n", 
            total_size/1000000);
    return DV_OK;

out:
    if (dv_subnet_ip_array != NULL) {
        dv_free(dv_subnet_ip_array);
        dv_subnet_ip_array = NULL;
    }

    DV_LOG(DV_LOG_NOTICE, "Init SHM failed!\n");
    return DV_ERROR;
}

dv_subnet_ip_t *
dv_subnet_ip_alloc(void)
{
    struct list_head    *head = NULL;
    dv_subnet_ip_t      *ip = NULL;

    head = &dv_ip_pool.ip_list_head;
    if (!list_empty(head)) {
        ip = dv_container_of(head->next, dv_subnet_ip_t, si_list_head);
        list_del(head->next);
    } else {
        ip = NULL;
    }

    return ip;
}

void
dv_subnet_ip_free(dv_subnet_ip_t *ip)
{
    list_add_tail(&ip->si_list_head, &dv_ip_pool.ip_list_head);
}

void
dv_ip_pool_exit(void)
{
    if (dv_subnet_ip_array == NULL) {
        return;
    }

    dv_free(dv_subnet_ip_array);
    INIT_LIST_HEAD(&dv_ip_pool.ip_list_head);
}
