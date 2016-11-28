
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

#define DV_TEST_LOG_NAME     "DoveVPN-test-client"

const dv_proto_suite_t *dv_test_ssl_proto_suite;
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
    return 0;
}

static int
dv_test_single_process_cycle(dv_srv_conf_t *conf)
{
    return 0;
}

static int
dv_test_master_process_cycle(dv_srv_conf_t *conf, dv_u32 ncpu)
{
    return 0;
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
