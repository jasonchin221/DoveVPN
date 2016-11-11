#include <unistd.h>
#include <string.h>

#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_if.h"
#include "dv_event.h"
#include "dv_log.h"
#include "dv_trans.h"
#include "dv_channel.h"
#include "dv_process.h"
#include "dv_socket.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_server_socket.h"
#include "dv_server_cycle.h"
#include "dv_server_tun.h"

#include <signal.h>

sig_atomic_t dv_quit;
sig_atomic_t dv_reconfigure;
sig_atomic_t dv_terminate;
dv_u8 dv_process;
dv_u8 dv_worker;
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

static void
_dv_server_process_exit(void)
{
    dv_destroy_channel_events();
    dv_srv_tun_ev_destroy();
    dv_tun_dev_destroy(&dv_srv_tun);
    dv_trans_exit();
    dv_srv_exit();
}

void
dv_server_process_exit(void)
{
    _dv_server_process_exit();
    exit(0);
}

static void
dv_worker_channel_read_handler(int sock, short event, void *arg)
{
    dv_event_t      *ev = arg;
    dv_channel_t    ch = {};
    ssize_t         rlen = 0;

    while (1) {
        rlen = dv_sk_recv(sock, &ch, sizeof(ch));
        if (rlen == 0) {
            DV_LOG(DV_LOG_INFO, "Master closed!\n");
            close(sock);
            dv_server_process_exit();
        }

        if (rlen == -DV_EWANT_READ) {
            break;
        }

        if (rlen < 0) {
            DV_LOG(DV_LOG_INFO, "Channel error!\n");
            close(sock);
            dv_server_process_exit();
        }

        switch (ch.ch_command) {
            case DV_CH_CMD_CLOSE:
                dv_event_del(ev);
                close(sock);
                return;
            case DV_CH_CMD_QUIT:
            case DV_CH_CMD_TERMINATE:
                DV_LOG(DV_LOG_INFO, "Exit!\n");
                close(sock);
                dv_server_process_exit();
                return;
        }
    }
}

static void
dv_worker_process_init(int worker)
{
    sigset_t    set = {};
    int         n = 0;

    //ngx_setaffinity(cpu_affinity, cycle->log);
    sigemptyset(&set);
    
    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        DV_LOG(DV_LOG_ALERT, "Sigprocmask() failed");
        dv_server_process_exit();
    }

    for (n = 0; n < dv_last_process; n++) {
        if (dv_processes[n].pc_pid == -1) {
            continue;
        }

        if (n == dv_process_slot) {
            continue;
        }

        if (dv_processes[n].pc_channel[1] == -1) {
            continue;
        }

        if (close(dv_processes[n].pc_channel[1]) == -1) {
            DV_LOG(DV_LOG_ALERT, "Close() channel failed\n");
        }
    }

    if (close(dv_processes[dv_process_slot].pc_channel[0]) == -1) {
        DV_LOG(DV_LOG_ALERT, "Close() channel failed\n");
    }

    dv_add_channel_read_event(dv_channel, dv_worker_channel_read_handler);
}

static void
dv_worker_process_cycle(void *cycle, void *data)
{
    dv_srv_conf_t   *conf = cycle;
    dv_tun_t        *tun = &dv_srv_tun;
    int             mask = conf->sc_subnet_mask;
    int             worker = *((int *)data);
    int             ret = DV_ERROR;

    dv_process = DV_PROCESS_WORKER;
    dv_worker = worker;

    dv_worker_process_init(worker);

    //dv_setproctitle("worker process");

    ret = dv_srv_create_and_set_tun(tun, worker, mask, conf->sc_mtu,
            conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip),
            conf->sc_tun_bufsize);
    if (ret != DV_OK) {
        dv_server_process_exit();
    }
    /* Event loop */
    DV_LOG(DV_LOG_INFO, "Before loop\n");
    ret = dv_process_events();
    DV_LOG(DV_LOG_INFO, "After loop, ret = %d\n", ret);
}

static int
dv_start_worker_processes(void *cycle, dv_u32 child_num)
{
    int             i = 0;

    for (i = 0; i < 1/* child_num */; i++) {
        /* Fork process */
        dv_spawn_process(cycle, dv_worker_process_cycle,
                (void *)&i, "worker process");
    }

    return DV_OK;
}

static void
dv_reap_children(int cmd)
{
    dv_channel_t    ch = {};
    int             i = 0;

    ch.ch_command = cmd;
    for (i = 0; i < dv_last_process; i++) {
        if (dv_processes[i].pc_pid == -1) {
            continue;
        }
        dv_write_channel(dv_processes[i].pc_channel[0], &ch, sizeof(ch));
    }
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
    dv_process = DV_PROCESS_MASTER;

    ret = dv_start_worker_processes(conf, cpu_num);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_ALERT, "Start worker process failed!\n");
        return DV_ERROR;
    }

    while (1) {
        sigsuspend(&set);
        if (dv_quit) {
            dv_reap_children(DV_CH_CMD_QUIT);
            dv_server_process_exit();
        }

        if (dv_reconfigure) {
            dv_reap_children(DV_CH_CMD_QUIT);
        }

        if (dv_terminate) {
            dv_reap_children(DV_CH_CMD_TERMINATE);
        }
    }
}

int
dv_single_process_cycle(dv_srv_conf_t *conf)
{
    DV_LOG(DV_LOG_INFO, "Signale process!\n");
    return DV_OK;
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

    if (conf->sc_single_process) {
        ret = dv_single_process_cycle(conf);
    } else {
        ret = dv_master_process_cycle(conf, dv_ncpu);
    }
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Process cycle failed!\n");
        goto out;
    }

out:
    _dv_server_process_exit();
    return ret;
}
