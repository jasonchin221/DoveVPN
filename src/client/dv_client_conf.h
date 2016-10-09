#ifndef __DV_CLIENT_CONF_H__
#define __DV_CLIENT_CONF_H__

#include "dv_types.h"
#include "dv_conf.h"

typedef struct _dv_client_conf_t {
    char                        cc_proto_type[DV_CONF_STR_LEN];
    char                        cc_cert[DV_CONF_STR_LEN];
    char                        cc_key[DV_CONF_STR_LEN];
    char                        cc_ca[DV_CONF_STR_LEN];
    char                        cc_ip[DV_IP_ADDRESS_LEN];
    int                         cc_port;
} dv_client_conf_t;

extern int dv_cli_conf_parse(dv_client_conf_t *conf, char *file);

#endif
