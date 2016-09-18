#ifndef __DV_TUN_H__
#define __DV_TUN_H__

typedef struct _dv_tun_t {
    int         tn_fd;
} dv_tun_t;

extern int dv_tun_open(dv_tun_t *tun, char *dev);

#endif
