
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_log.h"
#include "dv_lib.h"
#include "dv_trans.h"
#include "dv_process.h"
#include "dv_test_conf.h"
#include "dv_server_core.h"
#include "dv_server_cycle.h"
#include "dv_server_signal.h"
#include "dv_server_conn.h"
#include "dv_setproctitle.h"
#include "dv_client_ssl.h"
#include "dv_channel.h"
#include "dv_cpuaffinity.h"
#include "dv_if.h"
#include "dv_ip_pool.h"
#include "dv_server_socket.h"

#define DV_TEST_LOG_NAME     "DoveVPN-test-client"

static dv_event_t dv_test_tun_rev;
extern int _dv_master_process_cycle(dv_srv_conf_t *conf, dv_u32 cpu_num,
            int (*start_worker_processes)(void *, dv_u32));
extern void dv_worker_process_init(int worker);
extern void dv_worker_process_exit(void);

const dv_proto_suite_t *dv_test_ssl_proto_suite;

static dv_u8 dv_worker;

static dv_tun_t dv_test_tun = {
    .tn_fd = -1,
};

static int
dv_test_init(dv_srv_conf_t *conf)
{
    const dv_proto_suite_t  *suite = NULL;
    int                     ret = DV_ERROR;

    dv_log_init(DV_TEST_LOG_NAME);
    dv_process_init();
    ret = dv_srv_signal_init();
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Init signal failed!\n");
        return DV_ERROR;
    }

    dv_test_ssl_proto_suite = dv_proto_suite_find(conf->sc_proto.cc_proto_type);
    if (dv_test_ssl_proto_suite == NULL) {
        DV_LOG(DV_LOG_INFO, "Find suite failed!\n");
        return DV_ERROR;
    }

    dv_ncpu = dv_get_cpu_num();
    if (dv_ncpu == 0) {
        DV_LOG(DV_LOG_INFO, "Get cpu num failed!\n");
        goto out;
    }

    suite = dv_test_ssl_proto_suite;
    ret = dv_client_ssl_init(suite, &conf->sc_proto);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Init proto failed!\n");
        goto out;
    }

    ret = dv_srv_conn_pool_init(conf->sc_worker_connections,
            conf->sc_ssl_bufsize);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Connection init failed!\n");
    }

out:
    return ret;
}

static int
dv_test_socket_init(char *ip, int port)
{
    return dv_event_init();
}

static int
dv_test_single_process_cycle(dv_srv_conf_t *conf)
{
    return 0;
}

static void
dv_test_tun_to_ssl(int sock, short event, void *arg)
{
    dv_trans_buf_t          *tbuf = &dv_trans_buf;
    dv_event_t              *wev = NULL;
    dv_buffer_t             *wbuf = NULL;
    dv_srv_conn_t           *conn = NULL;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    struct iphdr            *ip4 = NULL;
    struct ip6_hdr          *ip6 = NULL;
    void                    *ssl = NULL;
    int                     tun_fd = dv_test_tun.tn_fd;
    ssize_t                 rlen = 0;
    int                     ret = DV_ERROR;

    rlen = read(sock, tbuf->tb_buf, tbuf->tb_buf_size);
    if (rlen <= 0) {
        DV_LOG(DV_LOG_INFO, "Tun read error(%zd)!\n", rlen);
        return;
    }

    if (dv_ip_is_v4(tbuf->tb_buf)) {
        ip4 = (void *)tbuf->tb_buf;
        wev = dv_ip_wev_find(&ip4->daddr, sizeof(ip4->daddr));
    } else {
        ip6 = (void *)tbuf->tb_buf;
        wev = dv_ip_wev_find(&ip6->ip6_dst, sizeof(ip6->ip6_dst));
    }

    if (wev == NULL) {
        DV_LOG(DV_LOG_INFO, "Find wev failed!\n");
        return;
    }
    
    conn = wev->et_conn;
    if (conn->sc_flags & DV_SK_CONN_FLAG_HANDSHAKED) {
        DV_LOG(DV_LOG_INFO, "Handshaking!\n");
        return;
    }

    wbuf = &conn->sc_wbuf;
    ssl = conn->sc_ssl;
    ret = dv_trans_data_to_ssl(tun_fd, ssl, wbuf, suite, tbuf, rlen);
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(wev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add wev failed!\n");
            return;
        }
    }
}

static int
dv_test_tun_ev_create(int tun_fd)
{
    dv_event_t      *rev = NULL;

    rev = &dv_test_tun_rev;
    rev->et_handler = dv_test_tun_to_ssl;
    dv_event_set_persist_read(tun_fd, rev);
    if (dv_event_add(rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Tun add rev failed!\n");
        return DV_ERROR;
    }

    return DV_OK;
}

void
dv_test_tun_ev_destroy(void)
{
    dv_event_destroy(&dv_test_tun_rev);
}

static int
dv_test_create_and_set_tun(dv_tun_t *tun, int seq, int mask, int mtu,
            char *subnet_ip, dv_u32 subnet_ip_len)
{
    dv_subnet_ip_t  *ip = NULL;
    int             ret = DV_ERROR;

    ret = dv_tun_dev_create(tun, (int)getpid());
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Tun create failed!\n");
        return DV_ERROR;
    }

    ret = dv_ip_pool_init(subnet_ip, subnet_ip_len, mask, mtu, seq, dv_ncpu);
    if (ret != DV_OK) {
        goto err;
    }

    ip = dv_subnet_ip_alloc();
    if (ip == NULL) {
        goto err;
    }

    DV_LOG(DV_LOG_INFO, "aaip = %s!\n", ip->si_ip);
    /* Config ip for tun */
    ret = dv_if_set(tun->tn_name, ip->si_ip, dv_get_subnet_mask(), mtu);
    dv_ip_pool_exit();
    if (ret != DV_OK) {
        goto err;
    }

    return dv_test_tun_ev_create(tun->tn_fd);
err:
    dv_tun_dev_destroy(tun);
    return ret;
}


static void 
dv_test_worker_process_cycle(void *cycle, void *data)
{
    dv_srv_conf_t   *conf = cycle;
    dv_tun_t        *tun = &dv_test_tun;
    int             mask = conf->sc_subnet_mask;
    int             worker = *((int *)data);
    int             ret = DV_ERROR;

    dv_process = DV_PROCESS_WORKER;
    dv_worker = worker;

    dv_worker_process_init(worker);

    dv_setproctitle("worker process");

    ret = dv_test_create_and_set_tun(tun, worker, mask, conf->sc_mtu,
            conf->sc_subnet_ip, sizeof(conf->sc_subnet_ip));
    if (ret != DV_OK) {
        dv_worker_process_exit();
    }

    ret = dv_cpuaffinity_set(worker);
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Set cpuaffinity failed!\n");
        dv_worker_process_exit();
    }

    /* Event loop */
    DV_LOG(DV_LOG_INFO, "Before loop\n");
    ret = dv_process_events();
    DV_LOG(DV_LOG_INFO, "After loop, ret = %d\n", ret);
}

static int
dv_test_start_worker_processes(void *cycle, dv_u32 child_num)
{
    int             i = 0;

    for (i = 0; i < child_num; i++) {
        /* Fork process */
        dv_spawn_process(cycle, dv_test_worker_process_cycle,
                (void *)&i, "test worker process");
    }

    return DV_OK;
}

static int
dv_test_master_process_cycle(dv_srv_conf_t *conf, dv_u32 ncpu)
{
    return _dv_master_process_cycle(conf, ncpu, dv_test_start_worker_processes);
}

int 
dv_test_cycle(dv_srv_conf_t *conf)
{
    int     ret = DV_ERROR;

    ret = dv_test_init(conf);
    if (ret != DV_OK) {
        goto out;
    }

    ret = dv_trans_init(conf->sc_mtu);
    if (ret != DV_OK) {
        goto out;
    }

    ret = dv_test_socket_init(conf->sc_listen_ip,
            conf->sc_port);
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
        ret = dv_test_single_process_cycle(conf);
    } else {
        ret = dv_test_master_process_cycle(conf, dv_ncpu);
    }

    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Process cycle failed!\n");
        goto out;
    }

out:

    return DV_OK;
}
