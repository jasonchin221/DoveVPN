
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_lib.h"

dv_u32 dv_ncpu;

int
dv_srv_init(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

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
