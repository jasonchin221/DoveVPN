#ifndef __DV_SOCKET_H__
#define __DV_SOCKET_H__


extern int dv_sk_connect_v4(const char *dip, dv_u16 dport);
extern int dv_sk_connect_v6(const char *dip, dv_u16 dport);
extern int dv_sk_bind(const char *dip, dv_u16 dport);

#endif
