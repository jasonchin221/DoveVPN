#ifndef __DV_SRV_TUN_H__
#define __DV_SRV_TUN_H__


extern dv_event_t *dv_srv_tun_rev;
extern dv_event_t *dv_srv_tun_wev;

extern int dv_srv_tun_ev_create(int tun_fd, size_t buf_size);
extern void dv_srv_tun_ev_destroy(void);

#endif
