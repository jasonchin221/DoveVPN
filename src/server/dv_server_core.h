#ifndef __DV_SERVER_CORE_H__
#define __DV_SERVER_CORE_H__

#include "dv_proto.h"
#include "dv_server_conf.h"

extern const dv_proto_suite_t *dv_srv_ssl_proto_suite;
extern void *dv_srv_ssl_ctx;
extern dv_u32 dv_ncpu;

extern int dv_srv_init(dv_srv_conf_t *conf);
extern void dv_srv_exit(void);


#endif
