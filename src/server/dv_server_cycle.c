#include <unistd.h>

#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_if.h"
#include "dv_event.h"
#include "dv_log.h"
#include "dv_server_socket.h"
#include "dv_server_cycle.h"

dv_tun_t dv_srv_tun = {
    .tn_fd = -1,
};

static int
dv_srv_create_and_set_tun(dv_tun_t *tun, int seq, int mask, int mtu,
            char *subnet_ip, dv_u32 subnet_ip_size)
{
    dv_subnet_ip_t  *ip = NULL;
    int             ret = DV_ERROR;

    ret = dv_tun_dev_create(tun, seq);
    if (ret != DV_OK) {
        return DV_ERROR;
    }

    ret = dv_ip_pool_init(subnet_ip, subnet_ip_size, mask, mtu);
    if (ret != DV_OK) {
        goto err;
    }

    ip = dv_subnet_ip_alloc();
    if (ip == NULL) {
        goto err;
    }

    /* Config ip for tun */
    ret = dv_if_set(tun->tn_name, ip->si_ip, mask, mtu);
    if (ret != DV_OK) {
        goto err;
    }

    return DV_OK;
err:
    dv_tun_dev_destroy(tun);
    return ret;
}

static int
dv_start_worker_processes(dv_srv_conf_t *conf, dv_u32 cpu_num)
{
    dv_tun_t        *tun = &dv_srv_tun;
    int             mask = conf->sc_subnet_mask;
    int             i = 0;
    int             ret = DV_ERROR;

    for (i = 0; i < 1/* cpu_num */; i++) {
        /* Fork process */

        ret = dv_srv_create_and_set_tun(tun, i, mask, conf->sc_mtu,
            conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip));
        if (ret != DV_OK) {
            break;
        }

       /* Add event */
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

    /* Libevent */
    ret = dv_srv_ssl_socket_init(conf->sc_listen_ip, conf->sc_port);
    if (ret != DV_OK) {
        goto out;
    }

    ret = dv_start_worker_processes(conf, dv_ncpu);
    if (ret != DV_OK) {
        goto out;
    }

    /* Event loop */
    printf("Before loop\n");
    ret = dv_process_events();
    printf("After loop, ret = %d\n", ret);
    ret = DV_OK;
out:
    if (dv_srv_tun.tn_fd >= 0) {
        dv_tun_dev_destroy(&dv_srv_tun);
    }
    dv_srv_exit();
    return ret;
}
