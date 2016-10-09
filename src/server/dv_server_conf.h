#ifndef __DV_SERVER_CONF_H__
#define __DV_SERVER_CONF_H__

#include "dv_types.h"
#include "dv_conf.h"

typedef struct _dv_srv_conf_t {
    int         sc_port;
    char        sc_subnet_ip[DV_IP_ADDRESS_LEN];
    int         sc_subnet_mask;
} dv_srv_conf_t;

extern int dv_srv_conf_parse(dv_srv_conf_t *conf, char *file);

#endif
