#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>

#include "dv_types.h"
#include "dv_lib.h"
#include "dv_errno.h"
#include "dv_proto.h"
#include "dv_log.h"

static void dv_openssl_add_all_algorighms(void);
static void *dv_openssl_ctx_client_new(void);
static void *dv_openssl_ctx_server_new(void);
static int dv_openssl_ctx_use_certificate_file(void *ctx, const char *file);
static int dv_openssl_ctx_use_private_key_file(void *ctx, const char *file);
static int dv_openssl_ctx_check_private_key(const void *ctx);
static int dv_openssl_ctx_set_ciphers(void *ctx);
static void *dv_openssl_new(void *ctx);
static int dv_openssl_set_fd(void *s, int fd);
static int dv_openssl_accept(void *s);
static int dv_openssl_connect(void *s);
static int dv_openssl_read(void *s, void *buf, int num);
static int dv_openssl_write(void *s, const void *buf, int num);
static int dv_openssl_shutdown(void *s);
static void dv_openssl_free(void *s);
static void dv_openssl_ctx_free(void *ctx);
static void dv_openssl_set_verify(void *s, int mode, char *peer_cf);
static int dv_openssl_get_verify_result(void *s);


const dv_proto_suite_t dv_suite_openssl = {
    .ps_proto_type = DV_PROTO_TYPE_OPENSSL,
    .ps_verify_mode = SSL_VERIFY_PEER,
    .ps_library_init = SSL_library_init,
    .ps_add_all_algorithms = dv_openssl_add_all_algorighms,
    .ps_load_error_strings = SSL_load_error_strings,
    .ps_ctx_client_new = dv_openssl_ctx_client_new,
    .ps_ctx_server_new = dv_openssl_ctx_server_new,
    .ps_ctx_use_certificate_file = dv_openssl_ctx_use_certificate_file,
    .ps_ctx_use_private_key_file = dv_openssl_ctx_use_private_key_file,
    .ps_ctx_check_private_key = dv_openssl_ctx_check_private_key,
    .ps_ctx_set_ciphers = dv_openssl_ctx_set_ciphers,
    .ps_ssl_new = dv_openssl_new,
    .ps_set_fd = dv_openssl_set_fd,
    .ps_accept = dv_openssl_accept,
    .ps_connect = dv_openssl_connect,
    .ps_read = dv_openssl_read,
    .ps_write = dv_openssl_write,
    .ps_shutdown = dv_openssl_shutdown,
    .ps_ssl_free = dv_openssl_free,
    .ps_ctx_free = dv_openssl_ctx_free,
    .ps_set_verify = dv_openssl_set_verify,
    .ps_get_verify_result = dv_openssl_get_verify_result,
};

static int
dv_openssl_callback(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/* OpenSSL */
static void
dv_openssl_add_all_algorighms(void)
{
    OpenSSL_add_all_algorithms();
}

static void *
dv_openssl_ctx_client_new(void)
{
    return SSL_CTX_new(TLSv1_2_client_method());
}

static void *
dv_openssl_ctx_server_new(void)
{
    return SSL_CTX_new(TLSv1_2_server_method());
}

static int 
dv_openssl_ctx_use_certificate_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static int
dv_openssl_ctx_use_private_key_file(void *ctx, const char *file)
{
    int     ret = 0;

    ret = SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static int 
dv_openssl_ctx_set_ciphers(void *ctx)
{    
    int      nid = 0;
    EC_KEY  *ecdh = NULL;
    char    *name = "prime256v1";

    if (SSL_CTX_set_cipher_list(ctx, DV_DEF_SERVER_CIPHERS) == 0) {
        printf("Set cipher %s\n", DV_DEF_SERVER_CIPHERS);
        return DV_ERROR;
    }

    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */

    nid = OBJ_sn2nid((const char *)name);
    if (nid == 0) {
        printf("Nid error!\n");
        return DV_ERROR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL) {
        printf("Unable to create curve \"%s\"", name);
        return DV_ERROR;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    EC_KEY_free(ecdh);

    return DV_OK;
}

static int
dv_openssl_ctx_check_private_key(const void *ctx)
{
    int     ret = 0;

    ret = SSL_CTX_check_private_key(ctx);
    if (ret == 0) {
        return DV_ERROR;
    }

    return DV_OK;
}

static void *dv_openssl_new(void *ctx)
{
    return SSL_new(ctx);
}

static int
dv_openssl_set_fd(void *s, int fd)
{
    return SSL_set_fd(s, fd);
}

static int
dv_openssl_error(void *s, int ret)
{
    int     sslerr = 0;

    sslerr = SSL_get_error(s, ret);
    if (sslerr == SSL_ERROR_WANT_READ) {
        return -DV_EWANT_READ;
    }

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        return -DV_EWANT_WRITE;
    }

    fprintf(stderr, "sslerr = %d, err = %ld\n", sslerr, ERR_get_error());
    return DV_ERROR;
}


static int
dv_openssl_accept(void *s)
{
    int     ret = 0;

    ret = SSL_accept(s);
    if (ret == 1) {
        return DV_OK;
    }

    return dv_openssl_error(s, ret);
}

static int
dv_openssl_connect(void *s)
{
    int     ret = 0;

    ret = SSL_connect(s);
    if (ret == 1) {
        return DV_OK;
    }

    return dv_openssl_error(s, ret);
}

static int
dv_openssl_read(void *s, void *buf, int num)
{
    int     ret = 0;

    ret = SSL_read(s, buf, num);
    if (ret >= 0) {
        return ret;
    }

    return dv_openssl_error(s, ret);
}

static int
dv_openssl_write(void *s, const void *buf, int num)
{
    int     ret = 0;

    ret = SSL_write(s, buf, num);
    if (ret > 0) {
        return DV_OK;
    }

    return dv_openssl_error(s, ret);
}

static int
dv_openssl_shutdown(void *s)
{
    return SSL_shutdown(s);
}

static void
dv_openssl_free(void *s)
{
    SSL_free(s);
}

static void
dv_openssl_ctx_free(void *ctx)
{
    SSL_CTX_free(ctx);
}

static void 
dv_openssl_set_verify(void *ctx, int mode, char *peer_cf)
{
    STACK_OF(X509_NAME)  *list = NULL;

    SSL_CTX_set_verify(ctx, mode, dv_openssl_callback);
    SSL_CTX_set_verify_depth(ctx, 1);

    if (SSL_CTX_load_verify_locations(ctx, peer_cf, NULL) == 0) {
        fprintf(stderr, "Load verify locations %s failed\n", peer_cf);
        exit(1);
    }
    
    list = SSL_load_client_CA_file(peer_cf);
    if (list == NULL) {
        fprintf(stderr, "Load client ca file %s failed\n", peer_cf);
        exit(1);
    }

    SSL_CTX_set_client_CA_list(ctx, list);
}

static int
dv_openssl_get_verify_result(void *s)
{
    long    ret = 0;

    ret = SSL_get_verify_result(s);
    if (ret != X509_V_OK) {
        fprintf(stderr, "Verify ret is %ld\n", ret);
        return DV_ERROR;
    }

    return DV_OK;
}



