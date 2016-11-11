
#include "dv_types.h"
#include "dv_errno.h"
#include "dv_lib.h"
#include "dv_proto.h"
#include "dv_log.h"
#include "dv_server_signal.h"
#include "dv_server_conf.h"
#include "dv_server_core.h"

#define DV_SRV_LOG_NAME     "DoveVPN-Server"

dv_u32 dv_ncpu;
dv_u32 dv_srv_conn_max = 200000;
const dv_proto_suite_t *dv_srv_ssl_proto_suite;
void *dv_srv_ssl_ctx;

int
dv_srv_init(dv_srv_conf_t *conf)
{
    const dv_proto_suite_t  *suite = NULL;
    dv_cipher_conf_t        *cipher = &conf->sc_proto;
    void                    *ctx = NULL;
    int                     ret = DV_ERROR;

    dv_log_init(DV_SRV_LOG_NAME);
    ret = dv_srv_signal_init();
    if (ret != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Init signal failed!\n");
        return DV_ERROR;
    }

    dv_srv_ssl_proto_suite = dv_proto_suite_find(conf->sc_proto.cc_proto_type);
    if (dv_srv_ssl_proto_suite == NULL) {
        DV_LOG(DV_LOG_INFO, "Find suite failed!\n");
        return DV_ERROR;
    }

    dv_ncpu = dv_get_cpu_num();
    if (dv_ncpu == 0) {
        DV_LOG(DV_LOG_INFO, "Get cpu num failed!\n");
        goto out;
    }

    suite = dv_srv_ssl_proto_suite;
    /* SSL 库初始化 */
    suite->ps_library_init();
    /* 载入所有 SSL 算法 */
    suite->ps_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    suite->ps_load_error_strings();
 
    /* 以 TLS1.2 标准兼容方式产生一个 SSL_CTX ,即 SSL Content Text */
    ctx = suite->ps_ctx_server_new();
    if (ctx == NULL) {
        DV_LOG(DV_LOG_INFO, "CTX new failed!\n");
        goto out;
    }

    dv_srv_ssl_ctx = ctx;
    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, cipher->cc_cert) < 0) {
        DV_LOG(DV_LOG_INFO, "Load certificate failed!\n");
        goto out;
    }

    /* 载入用户私钥 */
    if (suite->ps_ctx_use_private_key_file(ctx, cipher->cc_key) < 0) {
        DV_LOG(DV_LOG_INFO, "Load private key failed!\n");
        goto out;
    }

    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        DV_LOG(DV_LOG_INFO, "Check private key failed!\n");
        goto out;
    }

    suite->ps_set_verify(ctx, suite->ps_verify_mode, cipher->cc_ca);
    if (suite->ps_ctx_set_ciphers(ctx) != DV_OK) {
        DV_LOG(DV_LOG_INFO, "Set cipher failed!\n");
        goto out;
    }

    ret = DV_OK;
out:
    return ret;
}

void
dv_srv_exit(void)
{
    if (dv_srv_ssl_proto_suite == NULL) {
        return;
    }

    if (dv_srv_ssl_ctx != NULL) {
        dv_srv_ssl_proto_suite->ps_ctx_free(dv_srv_ssl_ctx);
    }
}
