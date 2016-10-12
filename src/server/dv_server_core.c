
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_ip_pool.h"

int
dv_srv_init(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

    ret = dv_ip_pool_init(conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip),
            conf->sc_subnet_mask);
    if (ret != DV_OK) {
    }

    return DV_OK;
}

void
dv_srv_exit(void)
{
    dv_ip_pool_exit();
}
