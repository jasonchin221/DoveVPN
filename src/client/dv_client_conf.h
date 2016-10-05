#ifndef __DV_CLIENT_CONF_H__
#define __DV_CLIENT_CONF_H__

#include "dv_types.h"

#define DV_IP_ADDRESS_LEN   32
#define DV_CONF_STR_LEN     256

typedef struct _dv_client_conf_t {
    char                        cc_proto_type[DV_CONF_STR_LEN];
    char                        cc_cert[DV_CONF_STR_LEN];
    char                        cc_key[DV_CONF_STR_LEN];
    char                        cc_server_cert[DV_CONF_STR_LEN];
    char                        cc_ip[DV_IP_ADDRESS_LEN];
    int                         cc_port;
} dv_client_conf_t;

extern int dv_cli_conf_parse(dv_client_conf_t *conf, char *file);

#endif
