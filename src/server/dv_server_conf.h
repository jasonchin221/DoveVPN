#ifndef __DV_SERVER_CONF_H__
#define __DV_SERVER_CONF_H__

#include "dv_types.h"
#include "dv_conf.h"

typedef struct _dv_srv_conf_t {
    int                 sc_daemon;
    int                 sc_mtu;
    int                 sc_port;
    int                 sc_single_process;
    int                 sc_ssl_bufsize;
    int                 sc_worker_connections;
    char                sc_pid_file[DV_CONF_STR_LEN];
    char                sc_listen_ip[DV_IP_ADDRESS_LEN];
    char                sc_subnet_ip[DV_IP_ADDRESS_LEN];
    char                sc_route_net[DV_IP_ADDRESS_LEN];
    int                 sc_subnet_mask;
    int                 sc_route_mask;
    dv_cipher_conf_t    sc_proto;
} dv_srv_conf_t;

extern int dv_srv_conf_parse(dv_srv_conf_t *conf, char *file);

#endif
