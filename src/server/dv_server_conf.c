
#include "dv_server_conf.h"
#include "dv_errno.h"
#include "dv_lib.h"

#define DV_SRV_CONF_NETWORK         "network"
#define DV_SRV_CONF_SUBNET_IP       "subnet-ip"
#define DV_SRV_CONF_SUBNET_MASK     "subnet-mask"
#define DV_SRV_CONF_VNIC_IP         "vnic-ip"
#define DV_SRV_CONF_PORT            "listen-port"
#define DV_SRV_CONF_PROTO           "proto"
#define DV_SRV_CONF_PROTO_TYPE      "type"
#define DV_SRV_CONF_CERT            "cert"
#define DV_SRV_CONF_KEY             "key"
#define DV_SRV_CONF_CA              "ca"

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
        .cp_name = DV_SRV_CONF_VNIC_IP,
        .cp_len = sizeof(dv_srv_conf.sc_vnic_ip),
        .cp_offset = dv_offsetof(dv_srv_conf_t, sc_vnic_ip),
        .cp_type = json_type_string,
        .cp_necessary = DV_TRUE,
        .cp_parse = dv_conf_parse_str,
    },
};

#define DV_SRV_CONF_NETWORK_ARRAY_SIZE DV_ARRAY_SIZE(dv_srv_conf_network)


int 
dv_srv_conf_parse(dv_srv_conf_t *conf, char *file)
{
    int     ret = DV_OK;

    ret = dv_config_parse(file, conf, DV_SRV_CONF_NETWORK, 
        dv_srv_conf_network, DV_SRV_CONF_NETWORK_ARRAY_SIZE);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    return DV_OK;
}
