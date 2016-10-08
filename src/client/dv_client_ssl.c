
#include "dv_proto.h"
#include "dv_errno.h"
#include "dv_log.h"
#include "dv_assert.h"
#include "dv_client_conf.h"

static void *dv_client_ctx;

int
dv_client_ssl_init(const dv_proto_suite_t *suite, dv_client_conf_t *conf)
{
    void    *ctx = NULL;

    suite->ps_library_init();
    suite->ps_add_all_algorithms();
    suite->ps_load_error_strings();
    ctx = suite->ps_ctx_client_new();
    if (ctx == NULL) {
        return DV_ERROR;
    }

    /* 载入用户的数字证书, 此证书用来发送给客户端。 证书里包含有公钥 */
    if (suite->ps_ctx_use_certificate_file(ctx, conf->cc_cert) < 0) {
        DV_LOG(DV_LOG_EMERG, "Load certificate %s failed!\n", conf->cc_cert);
        goto err;
    }
    /* 载入用户私钥 */
    if (suite->ps_ctx_use_privateKey_file(ctx, conf->cc_key) < 0) {
        DV_LOG(DV_LOG_EMERG, "Load private key %s failed!\n", conf->cc_key);
        goto err;
    }
    /* 检查用户私钥是否正确 */
    if (suite->ps_ctx_check_private_key(ctx) < 0) {
        DV_LOG(DV_LOG_EMERG, "Check private key failed!\n");
        goto err;
    }
 
    dv_client_ctx = ctx;
    suite->ps_set_verify(ctx, suite->ps_verify_mode, conf->cc_ca);
    return DV_OK;

err:
    suite->ps_ctx_free(ctx);
    return DV_ERROR;
}

void
dv_client_ssl_exit(const dv_proto_suite_t *suite)
{
    if (dv_client_ctx) {
        suite->ps_ctx_free(dv_client_ctx);
    }
}

void *
dv_client_ssl_conn_create(const dv_proto_suite_t *suite, int sockfd)
{
    void        *ssl = NULL;

    dv_assert(dv_client_ctx != NULL);

    ssl = suite->ps_ssl_new(dv_client_ctx);
    suite->ps_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (suite->ps_connect(ssl) == -1) {
        return NULL;
    }

    if (suite->ps_get_verify_result(ssl) != DV_OK) {
        return NULL;
    }

    return ssl;
}

