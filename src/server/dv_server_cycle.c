

#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_tun.h"

static dv_tun_t dv_srv_tun;

static int
dv_start_worker_processes(dv_srv_conf_t *conf, dv_u32 cpu_num)
{
    int     i = 0;
    int     ret = DV_ERROR;

    for (i = 0; i < 1/* cpu_num */; i++) {
        /* Fork process */

        ret = dv_tun_dev_create(&dv_srv_tun, i);
        if (ret != DV_OK) {
        }

        ret = dv_ip_pool_init(conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip),
                conf->sc_subnet_mask);
        /* Config ip for tun */
        /* Libevent */
    }

    return ret;
}

int 
dv_server_cycle(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

    ret = dv_srv_init(conf);
    if (ret != DV_OK) {
        goto out;
    }

    ret = dv_start_worker_processes(conf, dv_ncpu);
    if (ret != DV_OK) {
    }

    ret = DV_OK;
out:
    dv_srv_exit();
    return ret;
}
