

#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_tun.h"

static dv_tun_t dv_srv_tun = {
    .tn_fd = -1,
};

static int
dv_start_worker_processes(dv_srv_conf_t *conf, dv_u32 cpu_num)
{
    dv_subnet_ip_t  *ip = NULL;
    int             mask = conf->sc_subnet_mask;
    int             i = 0;
    int             ret = DV_ERROR;

    for (i = 0; i < 1/* cpu_num */; i++) {
        /* Fork process */

        ret = dv_tun_dev_create(&dv_srv_tun, i);
        if (ret != DV_OK) {
            break;
        }

        ret = dv_ip_pool_init(conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip),
                mask);
        if (ret != DV_OK) {
            break;
        }
        
        ip = dv_subnet_ip_alloc();
        if (ip == NULL) {
            ret = DV_ERROR;
            break;
        }
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
    if (dv_srv_tun.tn_fd >= 0) {
        dv_tun_dev_destroy(&dv_srv_tun);
    }
    dv_srv_exit();
    return ret;
}
