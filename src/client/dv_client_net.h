#ifndef __DV_CLIENT_NET_H__
#define __DV_CLIENT_NET_H__

int
dv_v4_client(struct sockaddr_in *addr, char *cf, char *key, char *ca,
        dv_u8 proto);
int
dv_v6_client(struct sockaddr_in6 *addr, char *cf, char *key, char *ca,
        dv_u8 proto);

#endif
