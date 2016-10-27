#include <stdlib.h>
#include <string.h>

#include "dv_types.h"
#include "dv_mem.h"
#include "dv_errno.h"
#include "dv_if.h"

#define DV_IF_SET_IP_STR_FORMAT     "ifconfig %s %s/%d up"

int
dv_if_set(char *dev, char *ip, int mask, int mtu)
{
    char    *str = NULL;
    int     len = 0;
    int     ret = 0;

    len = sizeof(DV_IF_SET_IP_STR_FORMAT) + strlen(dev) + 
        strlen(ip) + DV_IP_MAX_MASK_STR_LEN;

    str = dv_malloc(len);
    if (str == NULL) {
        return DV_ERROR;
    }

    snprintf(str, len, DV_IF_SET_IP_STR_FORMAT, dev, ip, mask);
    ret = system(str);
    if (ret != 0) {
        return DV_ERROR;
    }

    return DV_OK;
}
