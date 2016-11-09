#include <stdlib.h>
#include <string.h>

#include "dv_types.h"
#include "dv_mem.h"
#include "dv_errno.h"
#include "dv_if.h"
#include "dv_log.h"

#define DV_IF_SET_IP_STR_FORMAT     "ifconfig %s %s/%d up mtu %d"
#define DV_IF_SET_ROUTE_STR_FORMAT  "route add -net %s/%d dev %s"

int
dv_if_set(char *dev, char *ip, int mask, int mtu)
{
    char    *str = NULL;
    int     len = 0;
    int     ret = 0;

    len = sizeof(DV_IF_SET_IP_STR_FORMAT) + strlen(dev) + strlen(ip)
        + DV_IP_MAX_MASK_STR_LEN + DV_MTU_MAX_STR_LEN;

    str = dv_malloc(len);
    if (str == NULL) {
        return DV_ERROR;
    }

    snprintf(str, len, DV_IF_SET_IP_STR_FORMAT, dev, ip, mask, mtu);
    ret = system(str);
    if (ret != 0) {
        DV_LOG(DV_LOG_INFO, "Error cmd: %s\n", str);
        dv_free(str);
        return DV_ERROR;
    }
    dv_free(str);

    return DV_OK;
}

int
dv_route_set(char *dev, char *net, int mask)
{
    char    *str = NULL;
    int     len = 0;
    int     ret = 0;

    len = sizeof(DV_IF_SET_ROUTE_STR_FORMAT) + strlen(dev) + strlen(net)
        + DV_IP_MAX_MASK_STR_LEN;

    str = dv_malloc(len);
    if (str == NULL) {
        return DV_ERROR;
    }

    snprintf(str, len, DV_IF_SET_ROUTE_STR_FORMAT, net, mask, dev);
    ret = system(str);
    if (ret != 0) {
        DV_LOG(DV_LOG_INFO, "Error cmd: %s\n", str);
        dv_free(str);
        return DV_ERROR;
    }
    dv_free(str);

    return DV_OK;
}
