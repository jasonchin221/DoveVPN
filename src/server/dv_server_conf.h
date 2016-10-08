#ifndef __DV_SERVER_CONF_H__
#define __DV_SERVER_CONF_H__

#include "dv_types.h"

typedef struct _dv_srv_conf_t {
    int         sc_port;
    int         sc_subnet_mask;
} dv_srv_conf_t;

extern int dv_srv_conf_parse(dv_srv_conf_t *conf, char *file);

#endif
