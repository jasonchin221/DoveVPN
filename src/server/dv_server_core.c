
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_lib.h"

#define DV_SRV_LOG_NAME     "DoveVPN-Server"

dv_u32 dv_ncpu;
const dv_proto_suite_t *dv_srv_proto_suite;

int
dv_srv_init(dv_srv_conf_t *conf)
{
    int                         ret = DV_ERROR;

    dv_log_init(DV_SRV_LOG_NAME);
    dv_srv_proto_suite = dv_proto_suite_find(conf->sc_proto.cc_proto_type);
    if (dv_srv_proto_suite == NULL) {
        DV_LOG(DV_LOG_INFO, "Find suite failed!\n");
        return DV_ERROR;
    }

    dv_ncpu = dv_get_cpu_num();
    if (dv_ncpu == 0) {
        goto out;
    }

    ret = DV_OK;
out:
    return ret;
}

void
dv_srv_exit(void)
{
}
