#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "dv_errno.h"
#include "dv_ip_pool.h"
#include "dv_if.h"
#include "dv_event.h"
#include "dv_log.h"
#include "dv_trans.h"
#include "dv_channel.h"
#include "dv_mem.h"
#include "dv_process.h"
#include "dv_assert.h"
#include "dv_socket.h"
#include "dv_cpuaffinity.h"
#include "dv_setproctitle.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"
#include "dv_server_socket.h"
#include "dv_server_cycle.h"
#include "dv_server_tun.h"
#include "dv_server_signal.h"

#include <signal.h>

#define DV_MASTER_PROCESS_NAME  "master process"

sig_atomic_t dv_quit;
sig_atomic_t dv_reconfigure;
sig_atomic_t dv_terminate;
dv_u8 dv_process;
dv_u8 dv_worker;
dv_u8 dv_exiting;
int dv_argc;
char **dv_argv;
static char *dv_pid_file;

dv_tun_t dv_srv_tun = {
    .tn_fd = -1,
};

static int
dv_srv_create_and_set_tun(dv_tun_t *tun, int seq, int mask, int mtu,
            char *subnet_ip, dv_u32 subnet_ip_len)
{
    dv_subnet_ip_t  *ip = NULL;
    int             ret = DV_ERROR;

    ret = dv_tun_dev_create(tun, seq);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Tun create failed!\n");
        return DV_ERROR;
    }

    ret = dv_ip_pool_init(subnet_ip, subnet_ip_len, mask, mtu);
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

    return dv_srv_tun_ev_create(tun->tn_fd);
err:
    dv_tun_dev_destroy(tun);
    return ret;
}

static int
dv_server_create_pidfile(char *file)
{
    FILE    *fp = NULL;
    pid_t   pid;

    dv_assert(dv_pid_file == NULL);

    if (file[0] != '/') {
        DV_LOG(DV_LOG_INFO, "File %s is not absolute path!!\n", file);
        return DV_ERROR;
    }

    fp = fopen(file, "r");
    if (fp != NULL) {
        DV_LOG(DV_LOG_INFO, "Pid file %s already existed!!\n", file);
        fclose(fp);
        return DV_ERROR;
    }

    fp = fopen(file, "w");
    if (fp == NULL) {
        DV_LOG(DV_LOG_INFO, "Create pid file %s failed\n", file);
        return DV_ERROR;
    }

    pid = getpid();
    fprintf(fp, "%lu\n", (dv_ulong)pid);
    fclose(fp);

    dv_pid_file = dv_malloc(strlen(file) + 1);
    if (dv_pid_file == NULL) {
        unlink(file);
        DV_LOG(DV_LOG_INFO, "Malloc failed\n");
        return DV_ERROR;
    }

    strcpy(dv_pid_file, file);

    return DV_OK;
}

static void
dv_server_remove_pidfile(void)
{
    if (dv_pid_file == NULL) {
        return;
    }
    unlink(dv_pid_file);
    dv_free(dv_pid_file);
}

static pid_t
dv_server_get_master_pid(char *file)
{
    FILE    *fp = NULL;
    char    *pid = NULL;
    size_t  slen = 0;
    size_t  rlen = 0;

    if (file[0] != '/') {
        DV_LOG(DV_LOG_INFO, "File %s is not absolute path!\n", file);
        return DV_INVALID_PID;
    }

    fp = fopen(file, "r");
    if (fp == NULL) {
        DV_LOG(DV_LOG_INFO, "Open file %s failed!\n", file);
        return DV_INVALID_PID;
    }

    fseek(fp, 0, SEEK_END);
    slen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    pid = dv_calloc(slen);
    if (pid == NULL) {
        DV_LOG(DV_LOG_INFO, "Malloc failed!\n");
        fclose(fp);
        return DV_INVALID_PID;
    }

    rlen = fread(pid, slen, 1, fp);
    fclose(fp);
    if (rlen != 1) {
        DV_LOG(DV_LOG_INFO, "Read file %s failed(rlen = %zu)!\n", file, rlen);
        return DV_INVALID_PID;
    }

    pid[slen - 1] = 0;

    return atoi(pid);
}

int 
dv_server_send_signal(char *pid_file, char *cmd)
{
    pid_t   pid;

    pid = dv_server_get_master_pid(pid_file);
    if (pid == DV_INVALID_PID) {
        DV_LOG(DV_LOG_INFO, "Get pid from file %s failed!\n", pid_file);
        return DV_ERROR;
    }

    return dv_srv_signal_process(cmd, pid);
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

    DV_LOG(DV_LOG_INFO, "Channel!\n");
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

    //dv_setaffinity(cpu_affinity, cycle->log);
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

    DV_LOG(DV_LOG_INFO, "Add read channel!\n");
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

    dv_setproctitle("worker process");

    ret = dv_srv_create_and_set_tun(tun, worker, mask, conf->sc_mtu,
            conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip));
    if (ret != DV_OK) {
        dv_server_process_exit();
    }

    ret = dv_cpuaffinity_set(worker);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Set cpuaffinity failed!\n");
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

    for (i = 0; i < child_num; i++) {
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
    int             wlen = 0;

    ch.ch_command = cmd;
    for (i = 0; i < dv_last_process; i++) {
        if (dv_processes[i].pc_pid == -1) {
            continue;
        }
        wlen = dv_write_channel(dv_processes[i].pc_channel[0],
                &ch, sizeof(ch));
        DV_LOG(DV_LOG_ALERT, "Write channel %d!\n", wlen);
        if (wlen != sizeof(ch)) {
            DV_LOG(DV_LOG_ALERT, "Write channel failed!\n");
        }
    }
}

static int
dv_master_process_cycle(dv_srv_conf_t *conf, dv_u32 cpu_num)
{
    char                *title = NULL;
    char                *p = NULL;
    sigset_t            set = {};
    size_t              size = 0;
    int                 i = 0;
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

    size = sizeof(DV_MASTER_PROCESS_NAME);
    for (i = 0; i < dv_argc; i++) {
        size += strlen(dv_argv[i]) + 1;
    }

    title = dv_calloc(size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = title;
    p += snprintf(p, sizeof(DV_MASTER_PROCESS_NAME), 
            "%s", DV_MASTER_PROCESS_NAME);
    for (i = 0; i < dv_argc; i++) {
        *p++ = ' ';
        p += snprintf(p, size - (p - title), "%s", dv_argv[i]);
    }

    dv_setproctitle(title);
    dv_free(title);

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
            dv_server_remove_pidfile();
            dv_server_process_exit();
        }

        if (dv_reconfigure) {
            dv_reap_children(DV_CH_CMD_QUIT);
        }

        if (dv_terminate) {
            dv_reap_children(DV_CH_CMD_TERMINATE);
            dv_server_remove_pidfile();
            dv_server_process_exit();
        }
    }
}

int
dv_single_process_cycle(dv_srv_conf_t *conf)
{
    int     seq = 0;

    DV_LOG(DV_LOG_INFO, "Signale process!\n");
    dv_worker_process_cycle(conf, &seq);

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

    if (conf->sc_daemon) {
        if (dv_process_daemonize() != DV_OK) {
            DV_LOG(DV_LOG_ALERT, "Daemonize failed!\n");
            return -DV_ERROR;
        }
    }

    ret = dv_server_create_pidfile(conf->sc_pid_file);
    if (ret != DV_OK) {
        return ret;
    }

    ret = dv_init_setproctitle(dv_argv);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_ALERT, "Init set proc title failed!\n");
        return -DV_ERROR;
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
    dv_server_remove_pidfile();
    _dv_server_process_exit();
    return ret;
}
