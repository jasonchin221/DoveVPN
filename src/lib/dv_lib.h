#ifndef __DV_LIB_H__
#define __DV_LIB_H__

#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "dv_types.h"

#define dv_offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * dv_container_of - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define dv_container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define DV_ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

#define DV_HTONS(a)     htons(a)
#define DV_HTONL(a)     htonl(a)
#define DV_NTOHS(a)     ntohs(a)
#define DV_NTOHL(a)     ntohl(a)

static inline dv_u32
dv_pow(dv_u32 x, dv_u32 y)
{
    dv_u32      r = 1;

    for (; y > 0; y--) {
        r *= x;
    }

    return r;
}

static inline int 
dv_ip_version4(char *ip)
{
    return (strstr(ip, ":") == NULL);
}

static inline dv_u8
dv_ip_is_v4(void *h)
{
    struct iphdr    *ip4 = h;

    return ip4->version == 4;
}

static inline size_t
dv_ip_datalen(void *h, size_t len)
{
    struct iphdr    *ip4 = h;
    struct ip6_hdr  *ip6 = h;

    if (dv_ip_is_v4(ip4)) {
        if (len < sizeof(*ip4)) {
            return 0;
        }
        return DV_NTOHS(ip4->tot_len);
    }

    if (len < sizeof(*ip6)) {
        return 0;
    }

    return sizeof(*ip6) + DV_NTOHS(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
}

extern long dv_get_cpu_num(void);
extern dv_u32 dv_log2(dv_u32 x);

#endif
