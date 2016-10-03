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
//#include "dv_ssl.h"
//#include "dv_tls.h"
#include "dv_proto.h"

static void *dv_dovessl_ctx_client_new(void);
static void *dv_dovessl_ctx_server_new(void);
static int dv_dovessl_ctx_use_certificate_file(void *ctx, const char *file);
static int dv_dovessl_ctx_use_privateKey_file(void *ctx, const char *file);
static int dv_dovessl_ctx_check_private_key(const void *ctx);
static int dv_dovessl_ctx_set_ciphers(void *ctx);
static void *dv_dovessl_new(void *ctx);
static int dv_dovessl_set_fd(void *s, int fd);
static int dv_dovessl_accept(void *s);
static int dv_dovessl_connect(void *s);
static int dv_dovessl_read(void *s, void *buf, int num);
static int dv_dovessl_write(void *s, const void *buf, int num);
static int dv_dovessl_shutdown(void *s);
static void dv_dovessl_free(void *s);
static void dv_dovessl_ctx_free(void *ctx);
static void dv_dovessl_set_verify(void *s, int mode, char *peer_cf);
static int dv_dovessl_get_verify_result(void *s);

static const dv_proto_suite_t dv_dovessl_suite = {
    .ps_verify_mode = DV_SSL_VERIFY_PEER,
    .ps_library_init = dv_library_init,
    .ps_add_all_algorithms = dv_add_all_algorighms,
    .ps_load_error_strings = dv_load_error_strings,
    .ps_ctx_client_new = dv_dovessl_ctx_client_new,
    .ps_ctx_server_new = dv_dovessl_ctx_server_new,
    .ps_ctx_use_certificate_file = dv_dovessl_ctx_use_certificate_file,
    .ps_ctx_use_privateKey_file = dv_dovessl_ctx_use_privateKey_file,
    .ps_ctx_check_private_key = dv_dovessl_ctx_check_private_key,
    .ps_ctx_set_ciphers = dv_dovessl_ctx_set_ciphers,
    .ps_ssl_new = dv_dovessl_new,
    .ps_set_fd = dv_dovessl_set_fd,
    .ps_accept = dv_dovessl_accept,
    .ps_connect = dv_dovessl_connect,
    .ps_read = dv_dovessl_read,
    .ps_write = dv_dovessl_write,
    .ps_shutdown = dv_dovessl_shutdown,
    .ps_ssl_free = dv_dovessl_free,
    .ps_ctx_free = dv_dovessl_ctx_free,
    .ps_set_verify = dv_dovessl_set_verify,
    .ps_get_verify_result = dv_dovessl_get_verify_result,
};

/* DoveSSL */
static void *
dv_dovessl_ctx_client_new(void)
{
    return dv_ssl_ctx_new(dv_tls_v1_2_client_method());
}

static void *
dv_dovessl_ctx_server_new(void)
{
    return dv_ssl_ctx_new(dv_tls_v1_2_server_method());
}

static int 
dv_dovessl_ctx_use_certificate_file(void *ctx, const char *file)
{
    return dv_ssl_ctx_use_certificate_file(ctx, file, SSL_FILETYPE_PEM);
}

static int
dv_dovessl_ctx_use_privateKey_file(void *ctx, const char *file)
{
    return dv_ssl_ctx_use_private_key_file(ctx, file, SSL_FILETYPE_PEM);
}

static void *
dv_dovessl_new(void *ctx)
{
    return dv_ssl_new(ctx);
}

static int
dv_dovessl_set_fd(void *s, int fd)
{
    return dv_ssl_set_fd(s, fd);
}

static int
dv_dovessl_accept(void *s)
{
    return dv_ssl_accept(s);
}

static int
dv_dovessl_connect(void *s)
{
    return dv_ssl_connect(s);
}

static int
dv_dovessl_read(void *s, void *buf, int num)
{
    return dv_ssl_read(s, buf, num);
}

static int
dv_dovessl_write(void *s, const void *buf, int num)
{
    return dv_ssl_write(s, buf, num);
}

static int
dv_dovessl_shutdown(void *s)
{
    return dv_ssl_shutdown(s);
}

static int
dv_dovessl_ctx_set_ciphers(void *ctx)
{
    return DV_OK;
}

static int
dv_dovessl_ctx_check_private_key(const void *ctx)
{
    return dv_ssl_ctx_check_private_key(ctx);
}

static void
dv_dovessl_free(void *s)
{
    dv_ssl_free(s);
}

static void
dv_dovessl_ctx_free(void *ctx)
{
    dv_ssl_ctx_free(ctx);
}

static void 
dv_dovessl_set_verify(void *s, int mode, char *peer_cf)
{
}

static int
dv_dovessl_get_verify_result(void *s)
{
    return DV_OK;
}



