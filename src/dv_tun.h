#ifndef __DV_TUN_H__
#define __DV_TUN_H__

#include "dv_types.h"

#define DV_DEV_TUN          "/dev/net/tun"
#define DV_DEV_NAME_LEN     32

typedef struct _dv_tun_t {
    int         tn_fd;
    int         tn_sock_fd;
    char        tn_name[DV_DEV_NAME_LEN + 1];
} dv_tun_t;

extern int dv_tun_dev_create(dv_tun_t *tun, int i);
extern void dv_tun_dev_destroy(dv_tun_t *tun);
extern int dv_tun_init(dv_tun_t *tun);
extern void dv_tun_exit(dv_tun_t *tun);

#endif
