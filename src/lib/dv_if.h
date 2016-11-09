#ifndef __DV_IF_H__
#define __DV_IF_H__

#define DV_IP_MAX_MASK_STR_LEN      3  
#define DV_MTU_MAX_STR_LEN          5  

extern int dv_if_set(char *dev, char *ip, int mask, int mtu);
extern int dv_route_set(char *dev, char *net, int mask);

#endif
