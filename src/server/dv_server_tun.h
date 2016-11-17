#ifndef __DV_SRV_TUN_H__
#define __DV_SRV_TUN_H__


extern dv_u8 dv_route_net[];
extern size_t dv_route_mask;
extern dv_event_t dv_srv_tun_rev;

extern int dv_srv_tun_ev_create(int tun_fd);
extern void dv_srv_tun_ev_destroy(void);

#endif
