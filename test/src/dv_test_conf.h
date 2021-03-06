#ifndef __DV_TEST_CONF_H__
#define __DV_TEST_CONF_H__

#include <netinet/in.h>

#include "dv_server_conf.h"

#define DV_CONF_BACKEND_ADDR_MAX_NUM        128

typedef struct _dv_backend_addr_t {
    char    ba_addr[DV_IP_ADDRESS_LEN];
    dv_u16  ba_port;
} dv_backend_addr_t;

typedef struct _dv_test_conf_t {
    dv_backend_addr_t   cf_backend_addrs[DV_CONF_BACKEND_ADDR_MAX_NUM];
    dv_u16              cf_backend_addr_num;
    dv_u16              cf_curr;
} dv_test_conf_t;

typedef struct _dv_test_conf_parse_t {
    char        *cp_name;
    int         cp_type;
    int         (*cp_parser)(dv_backend_addr_t *addr, json_object *param);
} dv_test_conf_parse_t;

extern dv_test_conf_t dv_test_conf;

extern int dv_test_conf_parse(dv_srv_conf_t *conf, char *file);

#endif
