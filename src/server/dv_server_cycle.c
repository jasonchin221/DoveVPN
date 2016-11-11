#include <unistd.h>
#include <string.h>

#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_if.h"
#include "dv_event.h"
#include "dv_log.h"
#include "dv_trans.h"
#include "dv_channel.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_server_socket.h"
#include "dv_server_cycle.h"
#include "dv_server_tun.h"

#include <signal.h>

sig_atomic_t dv_quit;
sig_atomic_t dv_reconfigure;
dv_u8 dv_exiting;

dv_tun_t dv_srv_tun = {
    .tn_fd = -1,
};

static int
dv_srv_create_and_set_tun(dv_tun_t *tun, int seq, int mask, int mtu,
            char *subnet_ip, dv_u32 subnet_ip_size, size_t tun_bsize)
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

    return dv_srv_tun_ev_create(tun->tn_fd, tun_bsize);
err:
    dv_tun_dev_destroy(tun);
    return ret;
}

static int
dv_start_worker_processes(dv_srv_conf_t *conf, dv_u32 child_num)
{
    dv_tun_t        *tun = &dv_srv_tun;
    //dv_channel_t    ch = {};
    int             mask = conf->sc_subnet_mask;
    int             i = 0;
    int             ret = DV_ERROR;

    //ch.ch_command = DV_CH_CMD_OPEN;
    for (i = 0; i < 1/* child_num */; i++) {
        /* Fork process */

        ret = dv_srv_create_and_set_tun(tun, i, mask, conf->sc_mtu,
            conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip),
            conf->sc_tun_bufsize);
        if (ret != DV_OK) {
            break;
        }

        //dv_pass_open_channel(cycle, &ch);
       /* Add event */
    }

    return ret;
}

void
dv_server_process_exit(void)
{
    dv_srv_tun_ev_destroy();
    dv_tun_dev_destroy(&dv_srv_tun);
    dv_trans_exit();
    dv_srv_exit();
}


static int
dv_master_process_cycle(dv_srv_conf_t *conf, dv_u32 cpu_num)
{
    sigset_t            set = {};
    int                 ret = DV_ERROR;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGUSR1);
   
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        DV_LOG(DV_LOG_ALERT, "sigprocmask() failed!\n");
        return DV_ERROR;
    }
   
    sigemptyset(&set);
    ret = dv_start_worker_processes(conf, cpu_num);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_ALERT, "Start worker process failed!\n");
        return DV_ERROR;
    }

    while (1) {
        sigsuspend(&set);
        if (dv_quit) {
            dv_server_process_exit();
            exit(0);
        }

        if (dv_reconfigure) {
        }
    }
}

int 
dv_server_cycle(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

    memcpy(dv_route_net, conf->sc_route_net, sizeof(conf->sc_route_net));
    dv_route_mask = conf->sc_route_mask;

    ret = dv_srv_init(conf);
    if (ret != DV_OK) {
        goto out;
    }

    ret = dv_trans_init(conf->sc_mtu);
    if (ret != DV_OK) {
        goto out;
    }

    /* Libevent */
    ret = dv_srv_ssl_socket_init(conf->sc_listen_ip, conf->sc_port);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Init ssl socket failed!\n");
        goto out;
    }

    ret = dv_master_process_cycle(conf, dv_ncpu);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Start worker processes failed!\n");
        goto out;
    }

    /* Event loop */
    DV_LOG(DV_LOG_INFO, "Before loop\n");
    ret = dv_process_events();
    DV_LOG(DV_LOG_INFO, "After loop, ret = %d\n", ret);
    ret = DV_OK;
out:
    dv_server_process_exit();
    return ret;
}
