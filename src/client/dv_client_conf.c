
#include "dv_client_conf.h"
#include "dv_errno.h"
#include "dv_conf.h"
#include "dv_lib.h"

#define DV_CLI_CONF_ADDR    "address"
#define DV_CLI_CONF_IP      "ip"
#define DV_CLI_CONF_PORT    "port"

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

int
dv_cli_conf_parse(dv_client_conf_t *conf, char *file)
{
    int     ret = DV_OK;

    ret = dv_config_parse(file, conf, DV_CLI_CONF_ADDR, 
        dv_cli_conf_addr, DV_CLI_CONF_ADDR_ARRAY_SIZE);

    printf("ip=%s, port=%d\n", conf->cc_ip, conf->cc_port);
    return ret;
}