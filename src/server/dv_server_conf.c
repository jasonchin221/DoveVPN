
#include "dv_server_conf.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_log.h"

#define DV_SRV_CONF_NETWORK         "network"
#define DV_SRV_CONF_SUBNET_IP       "subnet-ip"
#define DV_SRV_CONF_SUBNET_MASK     "subnet-mask"
#define DV_SRV_CONF_ROUTE_NET_IP    "route-net-ip"
#define DV_SRV_CONF_ROUTE_MASK      "route-mask"
#define DV_SRV_CONF_LISTEN_IP       "listen-ip"
#define DV_SRV_CONF_PORT            "listen-port"
#define DV_SRV_CONF_MTU             "mtu"
#define DV_SRV_CONF_PROTO           "proto"
#define DV_SRV_CONF_PROTO_TYPE      "type"
#define DV_SRV_CONF_CERT            "cert"
#define DV_SRV_CONF_KEY             "key"
#define DV_SRV_CONF_CA              "ca"
#define DV_SRV_CONF_PROCESSES       "processes"
#define DV_SRV_CONF_DAEMON          "daemon"
#define DV_SRV_CONF_SINGLE_PROCESS  "single-process"
#define DV_SRV_CONF_PID             "pid-file"
#define DV_SRV_CONF_PROTO           "proto"
#define DV_SRV_CONF_CONNECTION      "connection"
#define DV_SRV_CONF_TUN_BUFFER_SIZE "tun-buffer-size"
#define DV_SRV_CONF_SSL_BUFFER_SIZE "ssl-buffer-size"

static dv_srv_conf_t dv_srv_conf;

static dv_conf_parse_t dv_srv_conf_network[] = {
    {
        .cp_name = DV_SRV_CONF_PORT,
        .cp_len = sizeof(dv_srv_conf.sc_port),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_port),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_LISTEN_IP,
        .cp_len = sizeof(dv_srv_conf.sc_listen_ip),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_listen_ip),
        .cp_type = json_type_string,
        .cp_necessary = DV_FALSE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_SRV_CONF_SUBNET_IP,
        .cp_len = sizeof(dv_srv_conf.sc_subnet_ip),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_subnet_ip),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_SRV_CONF_SUBNET_MASK,
        .cp_len = sizeof(dv_srv_conf.sc_subnet_mask),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_subnet_mask),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_ROUTE_NET_IP,
        .cp_len = sizeof(dv_srv_conf.sc_route_net),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_route_net),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_SRV_CONF_ROUTE_MASK,
        .cp_len = sizeof(dv_srv_conf.sc_route_mask),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_route_mask),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_MTU,
        .cp_len = sizeof(dv_srv_conf.sc_mtu),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_mtu),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
};

#define DV_SRV_CONF_NETWORK_ARRAY_SIZE DV_ARRAY_SIZE(dv_srv_conf_network)

static dv_conf_parse_t dv_srv_conf_processes[] = {
    {
        .cp_name = DV_SRV_CONF_DAEMON,
        .cp_len = sizeof(dv_srv_conf.sc_daemon),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_daemon),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_SINGLE_PROCESS,
        .cp_len = sizeof(dv_srv_conf.sc_single_process),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_single_process),
        .cp_type = json_type_int,
        .cp_necessary = DV_FALSE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_PID,
        .cp_len = sizeof(dv_srv_conf.sc_pid_file),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_pid_file),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
};

#define DV_SRV_CONF_PROCESSES_ARRAY_SIZE DV_ARRAY_SIZE(dv_srv_conf_processes)

static dv_conf_parse_t dv_srv_conf_connection[] = {
    {
        .cp_name = DV_SRV_CONF_TUN_BUFFER_SIZE,
        .cp_len = sizeof(dv_srv_conf.sc_tun_bufsize),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_tun_bufsize),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_SRV_CONF_SSL_BUFFER_SIZE,
        .cp_len = sizeof(dv_srv_conf.sc_ssl_bufsize),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_ssl_bufsize),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
};

#define DV_SRV_CONF_CONNECTION_ARRAY_SIZE DV_ARRAY_SIZE(dv_srv_conf_connection)


static int
dv_srv_conf_check(dv_srv_conf_t *conf)
{
    return DV_OK;
}

int 
dv_srv_conf_parse(dv_srv_conf_t *conf, char *file)
{
    int     ret = DV_OK;

    ret = dv_config_parse(file, conf, DV_SRV_CONF_NETWORK, 
        dv_srv_conf_network, DV_SRV_CONF_NETWORK_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_config_parse(file, conf, DV_SRV_CONF_PROCESSES, 
        dv_srv_conf_processes, DV_SRV_CONF_PROCESSES_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    DV_LOG(DV_LOG_NOTICE, "ip = %s, mask = %d\n", conf->sc_subnet_ip, 
            conf->sc_subnet_mask);
    ret = dv_cipher_conf_parse(&conf->sc_proto, DV_SRV_CONF_PROTO, file);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_config_parse(file, conf, DV_SRV_CONF_CONNECTION,
        dv_srv_conf_connection, DV_SRV_CONF_CONNECTION_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    return dv_srv_conf_check(conf);
}

