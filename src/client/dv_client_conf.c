
#include "dv_client_conf.h"
#include "dv_errno.h"
#include "dv_conf.h"
#include "dv_lib.h"

#define DV_CLI_CONF_ADDR            "address"
#define DV_CLI_CONF_IP              "ip"
#define DV_CLI_CONF_PORT            "port"
#define DV_CLI_CONF_PROCESSES       "processes"
#define DV_CLI_CONF_DAEMON          "daemon"
#define DV_CLI_CONF_PROTO           "proto"
#define DV_CLI_CONF_CONNECTION      "connection"
#define DV_CLI_CONF_BUFFER_SIZE     "buffer_size"
#define DV_CLI_CONF_RECONN_INTERVAL "reconn_interval"

static dv_client_conf_t dv_cli_conf;

static dv_conf_parse_t dv_cli_conf_addr[] = {
    {
        .cp_name = DV_CLI_CONF_IP,
        .cp_len = sizeof(dv_cli_conf.cc_ip),
        .cp_offset = dv_offsetof(dv_client_conf_t, cc_ip),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
    {
        .cp_name = DV_CLI_CONF_PORT,
        .cp_len = sizeof(dv_cli_conf.cc_port),
        .cp_offset = dv_offsetof(dv_client_conf_t, cc_port),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
};

#define DV_CLI_CONF_ADDR_ARRAY_SIZE DV_ARRAY_SIZE(dv_cli_conf_addr)

static dv_conf_parse_t dv_cli_conf_processes[] = {
    {
        .cp_name = DV_CLI_CONF_DAEMON,
        .cp_len = sizeof(dv_cli_conf.cc_daemon),
        .cp_offset = dv_offsetof(dv_client_conf_t, cc_daemon),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
};

#define DV_CLI_CONF_PROCESSES_ARRAY_SIZE DV_ARRAY_SIZE(dv_cli_conf_processes)

static dv_conf_parse_t dv_cli_conf_connection[] = {
    {
        .cp_name = DV_CLI_CONF_BUFFER_SIZE,
        .cp_len = sizeof(dv_cli_conf.cc_buffer_size),
        .cp_offset = dv_offsetof(dv_client_conf_t, cc_buffer_size),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
    {
        .cp_name = DV_CLI_CONF_RECONN_INTERVAL,
        .cp_len = sizeof(dv_cli_conf.reconn_interval),
        .cp_offset = dv_offsetof(dv_client_conf_t, reconn_interval),
        .cp_type = json_type_int,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_int,
    },
};

#define DV_CLI_CONF_CONNECTION_ARRAY_SIZE DV_ARRAY_SIZE(dv_cli_conf_connection)


static int
dv_cli_conf_check(dv_client_conf_t *conf)
{
    return DV_OK;
}

int
dv_cli_conf_parse(dv_client_conf_t *conf, char *file)
{
    int     ret = DV_OK;

    ret = dv_config_parse(file, conf, DV_CLI_CONF_ADDR, 
        dv_cli_conf_addr, DV_CLI_CONF_ADDR_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_config_parse(file, conf, DV_CLI_CONF_PROCESSES, 
        dv_cli_conf_processes, DV_CLI_CONF_PROCESSES_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_cipher_conf_parse(&conf->cc_proto, DV_CLI_CONF_PROTO, file);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_config_parse(file, conf, DV_CLI_CONF_CONNECTION,
        dv_cli_conf_connection, DV_CLI_CONF_CONNECTION_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    return dv_cli_conf_check(conf);
}
