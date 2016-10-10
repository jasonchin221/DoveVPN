

#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_errno.h"

int 
dv_server_cycle(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

    ret = dv_srv_init();
    if (ret != DV_OK) {
        goto out;
    }

    ret = DV_OK;
out:
    dv_srv_exit();
    return ret;
}
