#ifndef __DV_PROTO_H__
#define __DV_PROTO_H__

#define DV_PROTO_CIPHER_MAX_NUM     16
#define DV_PROTO_CIPHER_NAME_LEN    128
#define DV_PROTO_OPENSSL            "openssl"
#define DV_PROTO_DOVESSL            "dovessl"
#define DV_PROTO_PLAINTEXT          "plaintext"

enum {
    DV_PROTO_TYPE_NONE,
    DV_PROTO_TYPE_OPENSSL,
    DV_PROTO_TYPE_DOVESSL,
    DV_PROTO_TYPE_MAX,
};

typedef struct _dv_proto_name_type_t {
    int         nt_type;
    const char  *nt_name;
} dv_proto_name_type_t;

typedef struct _dv_proto_suite_t {
    int     ps_proto_type;
    int     ps_verify_mode;
    int     (*ps_library_init)(void);
    void    (*ps_add_all_algorithms)(void);
    void    (*ps_load_error_strings)(void);
    void    *(*ps_ctx_client_new)(void);
    void    *(*ps_ctx_server_new)(void);
    int     (*ps_ctx_use_certificate_file)(void *ctx, const char *file);
    int     (*ps_ctx_use_private_key_file)(void *ctx, const char *file);
    int     (*ps_ctx_check_private_key)(const void *ctx);
    int     (*ps_ctx_set_ciphers)(void *ctx);
    void    *(*ps_ssl_new)(void *ctx);
    int     (*ps_set_fd)(void *s, int fd);
    int     (*ps_accept)(void *s);
    int     (*ps_connect)(void *s);
    int     (*ps_read)(void *s, void *buf, int num);
    int     (*ps_write)(void *s, const void *buf, int num);
    int     (*ps_shutdown)(void *s);
    void    (*ps_ssl_free)(void *s);
    void    (*ps_ctx_free)(void *ctx);
    void    (*ps_set_verify)(void *s, int mode, char *peer_cf);
    int     (*ps_get_verify_result)(void *s);
} dv_proto_suite_t;

extern char dv_proto_ciphers[DV_PROTO_CIPHER_MAX_NUM][DV_PROTO_CIPHER_NAME_LEN];
extern const dv_proto_suite_t dv_suite_openssl;
extern const dv_proto_suite_t *dv_proto_suite_find(const char *name);

#endif
