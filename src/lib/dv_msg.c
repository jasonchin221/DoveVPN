#include <string.h>

#include "dv_msg.h"
#include "dv_assert.h"


size_t
dv_msg_ipalloc_build(void *buf, size_t buf_len, void *ip,
            size_t ip_len, size_t mask, size_t mtu)
{
    dv_msg_ipaddr_t     *addr = buf;

    dv_assert(ip_len < sizeof(addr->mi_ip));

    if (buf_len < sizeof(*addr)) {
        return 0;
    }

    addr->mi_header.mh_type = DV_MSG_TYPE_IPADDR;
    addr->mi_header.mh_length = sizeof(*addr);
    addr->mi_mask = mask;
    addr->mi_mtu = mtu;
    memcpy(addr->mi_ip, ip, ip_len);

    return sizeof(*addr);
}
