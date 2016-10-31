#ifndef __DV_CLIENT_CONF_H__
#define __DV_CLIENT_CONF_H__

#include "dv_types.h"
#include "dv_conf.h"

typedef struct _dv_client_conf_t {
    char                        cc_ip[DV_IP_ADDRESS_LEN];
    int                         cc_port;
    int                         cc_daemon;
    int                         cc_buffer_size;
    int                         cc_reconn_interval;
    dv_cipher_conf_t            cc_proto;
} dv_client_conf_t;

extern int dv_cli_conf_parse(dv_client_conf_t *conf, char *file);

#endif
