#ifndef __DV_CLIENT_CONF_H__
#define __DV_CLIENT_CONF_H__

#include "dv_types.h"

#define DV_IP_ADDRESS_LEN   32

typedef struct _dv_client_conf_t {
#if 0
    union {
        struct sockaddr_in      cc_addr;
        struct sockaddr_in6     cc_addr6;
    };
#endif
    char                        cc_ip[DV_IP_ADDRESS_LEN];
    dv_u16                      cc_port;
} dv_client_conf_t;

extern int dv_cli_conf_parse(dv_client_conf_t *conf, char *file);

#endif
