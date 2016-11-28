#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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
#include "dv_socket.h"
#include "dv_assert.h"

#define DV_TEST_LOG_NAME     "DoveVPN-test-client"

extern void *dv_client_ctx;
extern int _dv_master_process_cycle(dv_srv_conf_t *conf, dv_u32 cpu_num,
            int (*start_worker_processes)(void *, dv_u32));
extern void dv_worker_process_init(int worker);
extern void dv_worker_process_exit(void);

const dv_proto_suite_t *dv_test_ssl_proto_suite;

static dv_event_t dv_test_tun_rev;
static dv_u8 dv_worker;

static dv_tun_t dv_test_tun = {
    .tn_fd = -1,
};

static int
dv_ip_addr4(void *h, struct sockaddr_in *addr)
{
    struct iphdr            *ip = h;
    struct tcphdr           *th = NULL;

    addr->sin_addr.s_addr = ip->saddr; 
    addr->sin_family = AF_INET;
    if (ip->protocol != IPPROTO_TCP) {
        return DV_ERROR;
    }

    th = (void *)((char *)ip + ip->ihl*4);
    addr->sin_port = th->source;

    return DV_OK;
}

static int
dv_ip_addr6(void *h, struct sockaddr_in6 *addr)
{
    struct ip6_hdr          *ip = h;
    struct tcphdr           *th = NULL;

    addr->sin6_addr = ip->ip6_src; 
    addr->sin6_family = AF_INET6;
    if (ip->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
        return DV_ERROR;
    }

    th = (void *)(ip + 1);
    addr->sin6_port = th->source;

    return DV_OK;
}


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

static int
dv_test_ssl_err_handler(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    DV_LOG(DV_LOG_INFO, "SSL data in!\n");
    dv_event_destroy(ev);

    return DV_ERROR;
}

static void
dv_test_ssl_to_tun(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_srv_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->sc_ssl;
    const dv_proto_suite_t  *suite = dv_test_ssl_proto_suite;
    dv_buffer_t             *rbuf = &conn->sc_rbuf;
    int                     tun_fd = dv_test_tun.tn_fd;

    dv_ssl_read_handler(sock, event, arg, ssl, tun_fd, suite, rbuf,
            dv_get_subnet_mtu(), dv_test_ssl_err_handler);
}

static int
dv_test_ssl_send_data(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_srv_conn_t           *conn = ev->et_conn;
    dv_buffer_t             *wbuf = &conn->sc_wbuf;
    dv_event_t              *wev = &conn->sc_wev;
    void                    *ssl = conn->sc_ssl;
    int                     ret = DV_OK;

    ev->et_handler = dv_test_ssl_to_tun;
    dv_event_set_read(sock, ev);
    ret = dv_buf_data_to_ssl(ssl, wbuf, suite);
    if (ret == DV_OK) {
        if (dv_event_add(ev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add read event failed!\n");
            return DV_ERROR;
        }
        return DV_OK;
    } 
    
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(ev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add read event failed!\n");
            return DV_ERROR;
        }
 
        if (dv_event_add(wev) != DV_OK) {
            DV_LOG(DV_LOG_INFO, "Add write event failed!\n");
            return DV_ERROR;
        }
        return DV_OK;
    }
 
    DV_LOG(DV_LOG_INFO, "Unknown return value %d!\n", ret);
    return DV_ERROR;
}

static int
dv_test_ssl_handshake_done(int sock, dv_event_t *ev, const dv_proto_suite_t *suite)
{
    dv_srv_conn_t           *conn = ev->et_conn;
    void                    *ssl = conn->sc_ssl;

    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Verify failed!\n");
        return DV_ERROR;
    }

    conn->sc_flags &= ~DV_SK_CONN_FLAG_HANDSHAKING;

    return dv_test_ssl_send_data(sock, ev, suite);
}

static void
dv_test_ssl_handshake(int sock, short event, void *arg)
{
    const dv_proto_suite_t  *suite = dv_test_ssl_proto_suite;
    dv_event_t              *ev = arg; 
    dv_srv_conn_t           *conn = ev->et_conn;
    void                    *ssl = NULL;
    int                     ret = DV_OK;

    ssl = conn->sc_ssl;
    conn = ev->et_conn;

    /* 建立 SSL 连接 */
    ret = suite->ps_connect(ssl);
    if (ret == DV_OK) {
        ret = dv_test_ssl_handshake_done(sock, ev, suite);
        if (ret == DV_ERROR) {
            DV_LOG(DV_LOG_INFO, "Handshake done proc failed!\n");
            goto out;
        }
        return;
    }

    if (ret == -DV_EWANT_READ) {
        dv_event_set_read(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

    if (ret == -DV_EWANT_WRITE) {
        dv_event_set_write(sock, ev);
        if (dv_event_add(ev) != DV_OK) {
            goto out;
        }
        return;
    }

out:
    dv_event_destroy(ev);
}

static void
dv_test_buf_to_ssl(int sock, short event, void *arg)
{
    dv_event_t              *ev = arg; 
    dv_srv_conn_t           *conn = ev->et_conn;
    dv_buffer_t             *wbuf = &conn->sc_wbuf;
    void                    *ssl = conn->sc_ssl;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    int                     ret = DV_OK;

    ret = dv_buf_data_to_ssl(ssl, wbuf, suite);
    if (ret == DV_OK) {
        conn->sc_flags &= ~DV_SK_CONN_FLAG_HANDSHAKING;
        return;
    } 
    
    if (ret == -DV_EWANT_WRITE) {
        if (dv_event_add(ev) == DV_OK) {
            return;
        }
    }

    dv_event_destroy(ev);
}

static int
dv_test_ssl_connect(void *key, size_t len, void *data, ssize_t dlen)
{
    const dv_proto_suite_t  *suite = dv_test_ssl_proto_suite;
    dv_backend_addr_t       *addr = NULL; 
    dv_event_t              *rev = NULL; 
    dv_event_t              *wev = NULL; 
    dv_srv_conn_t           *conn = NULL;
    dv_subnet_ip_t          *ip = NULL;
    dv_buffer_t             *wbuf = NULL;
    void                    *ssl = NULL;
    int                     sockfd = 0;
    int                     ret = DV_ERROR;

    addr = &dv_test_conf.cf_backend_addrs[dv_test_conf.cf_curr];
    dv_test_conf.cf_curr = (dv_test_conf.cf_curr + 1) %
        dv_test_conf.cf_backend_addr_num;
    if (dv_ip_version4(addr->ba_addr)) {
        sockfd = dv_sk_connect_v4(addr->ba_addr, addr->ba_port);
    } else {
        sockfd = dv_sk_connect_v6(addr->ba_addr, addr->ba_port);
    }

    if (sockfd < 0) {
        DV_LOG(DV_LOG_INFO, "Socket error!\n");
        return DV_ERROR;
    }

    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        DV_LOG(DV_LOG_INFO, "Set noblock failed(%s)!\n", strerror(errno));
        goto out;
    }

    ssl = suite->ps_ssl_new(dv_client_ctx);
    if (ssl == NULL) {
        DV_LOG(DV_LOG_INFO, "New ssl failed!\n");
        goto out;
    }

    suite->ps_set_fd(ssl, sockfd);

    conn = dv_srv_conn_pool_alloc(sockfd, ssl);
    if (conn == NULL) {
        DV_LOG(DV_LOG_INFO, "Create conn failed!\n");
        goto out;
    }

    rev = &conn->sc_rev;
    wev = &conn->sc_wev;
    wev->et_handler = dv_test_buf_to_ssl;
    dv_event_set_write(sockfd, wev);

    ip = dv_subnet_ip_alloc();
    if (ip == NULL) {
        DV_LOG(DV_LOG_INFO, "Alloc ip failed!\n");
        goto out;
    }

    ip->si_wev = &conn->sc_wev;
    /* Send message to alloc ip address */
    conn->sc_ip = ip;
    dv_ip_hash_add(ip);

    ret = suite->ps_connect(ssl);
    conn->sc_flags |= DV_SK_CONN_FLAG_HANDSHAKING;
    wbuf = &conn->sc_wbuf;

    dv_assert(wbuf->bf_bsize >= dlen);

    memcpy(wbuf->bf_head, data, dlen);
    wbuf->bf_tail = wbuf->bf_head + dlen;
    switch (ret) {
        case DV_OK:
            ret = dv_test_ssl_handshake_done(sockfd, rev, suite);
            if (ret == DV_ERROR) {
                DV_LOG(DV_LOG_INFO, "Handshake done proc failed!\n");
                goto out;
            }
            return DV_OK;
        case -DV_EWANT_READ:
            rev->et_handler = dv_test_ssl_handshake;
            dv_event_set_read(sockfd, rev);
            break;
        case -DV_EWANT_WRITE:
            rev->et_handler = dv_test_ssl_handshake;
            dv_event_set_write(sockfd, rev);
            break;
        default:
            goto out;
    }

    if (dv_event_add(rev) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Add rev failed!\n");
        goto out;
    }

    return ret;

out:
    if (conn != NULL) {
        dv_srv_conn_pool_free(conn);
    } else {
        close(sockfd);
    }

    return DV_ERROR;
}

static void
dv_test_tun_to_ssl(int sock, short event, void *arg)
{
    dv_trans_buf_t          *tbuf = &dv_trans_buf;
    dv_event_t              *wev = NULL;
    dv_buffer_t             *wbuf = NULL;
    dv_srv_conn_t           *conn = NULL;
    const dv_proto_suite_t  *suite = dv_srv_ssl_proto_suite;
    void                    *ssl = NULL;
    void                    *key = NULL;
    size_t                  ksize = 0;
    struct sockaddr_in      in4 = {
        .sin_family = AF_INET,
    };
    struct sockaddr_in6     in6 = {
        .sin6_family = AF_INET6,
    };
    int                     tun_fd = dv_test_tun.tn_fd;
    ssize_t                 rlen = 0;
    int                     ret = DV_ERROR;

    rlen = read(sock, tbuf->tb_buf, tbuf->tb_buf_size);
    if (rlen <= 0) {
        DV_LOG(DV_LOG_INFO, "Tun read error(%zd)!\n", rlen);
        return;
    }

    if (dv_ip_is_v4(tbuf->tb_buf)) {
        ret = dv_ip_addr4(tbuf->tb_buf, &in4);
        if (ret != DV_OK) {
            return;
        }
        wev = dv_ip_wev_find(&in4, sizeof(in4));
        key = &in4;
        ksize = sizeof(in4);
    } else {
        ret = dv_ip_addr6(tbuf->tb_buf, &in6);
        if (ret != DV_OK) {
            return;
        }
        wev = dv_ip_wev_find(&in6, sizeof(in6));
        key = &in6;
        ksize = sizeof(in6);
    }

    if (wev == NULL) {
        dv_test_ssl_connect(key, ksize, tbuf->tb_buf, rlen);
        return;
    }
    
    conn = wev->et_conn;
    if (conn->sc_flags & DV_SK_CONN_FLAG_HANDSHAKING) {
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
