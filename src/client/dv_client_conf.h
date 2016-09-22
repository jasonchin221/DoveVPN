#ifndef __DV_CLIENT_CONF_H__
#define __DV_CLIENT_CONF_H__

#include "dv_types.h"

typedef struct _dv_client_conf_t {
    union {
        struct sockaddr_in      cc_addr;
        struct sockaddr_in6     cc_addr6;
    };
    dv_u16                      cc_port;
} dv_client_conf_t;

#endif
