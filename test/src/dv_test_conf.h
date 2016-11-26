#ifndef __DV_TEST_CONF_H__
#define __DV_TEST_CONF_H__

#include <netinet/in.h>

#include "dv_server_conf.h"

#define DV_CONF_BACKEND_ADDR_MAX_NUM        128

typedef struct _dv_backend_addr_t {
    union {
        struct sockaddr_in  ba_addr4;
        struct sockaddr_in6 ba_addr6;
    } ba_addr;
} dv_backend_addr_t;

typedef struct _dv_test_conf_t {
    dv_srv_conf_t       cf_core;
    dv_backend_addr_t   cf_backend_addrs[DV_CONF_BACKEND_ADDR_MAX_NUM];
    dv_u32              cf_backend_addr_num;
} dv_test_conf_t;

extern int dv_test_conf_parse(dv_test_conf_t *conf, char *file);

#endif
