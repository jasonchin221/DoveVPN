#ifndef __DV_CLIENT_SSL_H__
#define __DV_CLIENT_SSL_H__

extern int dv_client_ssl_init(const dv_proto_suite_t *suite,
            dv_cipher_conf_t *conf);
extern void dv_client_ssl_exit(const dv_proto_suite_t *suite);
extern void *dv_client_ssl_conn_create(const dv_proto_suite_t *suite,
            int sockfd);

#endif
