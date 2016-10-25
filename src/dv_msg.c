#include <string.h>

#include "dv_msg.h"
#include "dv_assert.h"


void
dv_msg_ipalloc_build(void *buf, size_t buf_len, void *ip,
            size_t ip_len, dv_u32 mask)
{
    dv_msg_ipaddr_t     *addr = buf;

    dv_assert(ip_len < sizeof(addr->mi_ip));

    addr->mi_header.mh_type = DV_MSG_TYPE_IPADDR;
    addr->mi_header.mh_length = sizeof(*addr);
    addr->mi_mask = mask;
    memcpy(addr->mi_ip, ip, ip_len);
}
