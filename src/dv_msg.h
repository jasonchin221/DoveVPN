#ifndef __DV_MSG_H__
#define __DV_MSG_H__

#include "dv_types.h"
#include "dv_conf.h"

enum {
    DV_MSG_TYPE_NONE,
    DV_MSG_TYPE_IPADDR,
    DV_MSG_TYPE_MAX,
};

typedef struct _dv_msg_header_t {
    dv_u16      mh_type;
    dv_u16      mh_length;
} dv_msg_header_t;

typedef struct _dv_msg_ipaddr_t {
    dv_msg_header_t     mi_header;
    char                mi_ip[DV_IP_ADDRESS_LEN];
    dv_u32              mi_mask;
} dv_msg_ipaddr_t;


extern size_t dv_msg_ipalloc_build(void *buf, size_t buf_len, 
            void *ip, size_t ip_len,  dv_u32 mask);

#endif
